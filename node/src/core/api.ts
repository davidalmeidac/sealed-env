/**
 * High-level public API: seal, unseal, loadSealed.
 *
 * - `seal()`: take plaintext + master key + mode → produce a SealedFile.
 * - `unseal()`: take a parsed SealedFile + key material → return plaintext.
 * - `loadSealed()`: convenience wrapper that reads from disk + env vars.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  constantTimeEqual,
  deriveMasterKey,
  hkdfExpand,
  hmacSha256,
  randomBytes,
  sha256,
  wipe,
} from './crypto.js';
import { SealedEnvError } from './errors.js';
import { parseSealedFile } from '../format/parser.js';
import { buildAad, serializeSealedFile } from '../format/serializer.js';
import {
  DEFAULT_KDF,
  DEFAULT_SCRYPT_PARAMS,
  HKDF_INFO_ENC,
  HKDF_INFO_MAC,
  KEY_LEN,
  NONCE_LEN,
  SALT_LEN,
  TOTP_VERIFY_TAG,
} from '../format/constants.js';
import type {
  KdfParams,
  LoadSealedOptions,
  ScryptParams,
  SealOptions,
  SealedFile,
  UnsealOptions,
} from './types.js';
import { verifyUnsealToken } from '../totp/unsealToken.js';

/* ──────────────────────────────────────────────────────────────────────── */
/*  SEAL                                                                     */
/* ──────────────────────────────────────────────────────────────────────── */

/**
 * Encrypt a plaintext into a SealedFile.
 *
 * Produces a deterministic-ish file: the salt and nonce are random, but every
 * other byte is determined by the inputs. Two calls with the same inputs will
 * differ ONLY in the salt/nonce/timestamp/ciphertext.
 */
export function seal(opts: SealOptions): { file: SealedFile; serialized: string } {
  validateMasterKey(opts.masterKey);

  if (opts.mode === 'enterprise') {
    if (!opts.totpSecret || opts.totpSecret.length < 16) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        'enterprise mode requires totpSecret (>=16 bytes)',
      );
    }
  }
  if (opts.mode === 'team' || opts.mode === 'enterprise') {
    if (!opts.signingKey || opts.signingKey.length < 16) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        `${opts.mode} mode requires signingKey (>=16 bytes)`,
      );
    }
  }

  const scryptParams: ScryptParams = {
    N: opts.scryptParams?.N ?? DEFAULT_SCRYPT_PARAMS.N,
    r: opts.scryptParams?.r ?? DEFAULT_SCRYPT_PARAMS.r,
    p: opts.scryptParams?.p ?? DEFAULT_SCRYPT_PARAMS.p,
  };
  const kdfParams: KdfParams = { kind: 'scrypt', params: scryptParams };

  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const created = new Date().toISOString();

  const derivedKey = deriveMasterKey(opts.masterKey, salt, kdfParams);
  try {
    const encKey = hkdfExpand(derivedKey, salt, HKDF_INFO_ENC, KEY_LEN);
    try {
      // Build a draft SealedFile (without ciphertext / aadDigest / hmac yet) so
      // we can compute AAD over canonical metadata
      const totpVerifier =
        opts.mode === 'enterprise'
          ? hmacSha256(
              derivedKey,
              Buffer.concat([opts.totpSecret!, Buffer.from(TOTP_VERIFY_TAG, 'utf8')]),
            )
          : undefined;

      const challengeBind: 'enabled' | 'disabled' | undefined =
        opts.mode === 'enterprise'
          ? opts.challengeBind === false
            ? 'disabled'
            : 'enabled'
          : undefined;

      const draft: SealedFile = {
        version: 1,
        mode: opts.mode,
        kdf: DEFAULT_KDF,
        kdfParams,
        salt,
        nonce,
        ...(totpVerifier && { totpVerifier }),
        ...(challengeBind && { challengeBind }),
        aadDigest: Buffer.alloc(32), // placeholder, recomputed below
        created,
        ciphertext: Buffer.alloc(0), // placeholder
      };

      const aad = buildAad(draft);
      const aadDigest = sha256(aad);
      draft.aadDigest = aadDigest;

      const plaintextBuf =
        typeof opts.plaintext === 'string'
          ? Buffer.from(opts.plaintext, 'utf8')
          : opts.plaintext;

      const ciphertext = aesGcmEncrypt(encKey, nonce, plaintextBuf, aad);

      // For team/enterprise: HMAC over magic+metadata(without HMAC)+ciphertext
      let hmac: Buffer | undefined;
      if (opts.mode === 'team' || opts.mode === 'enterprise') {
        const macKey = hkdfExpand(opts.signingKey!, salt, HKDF_INFO_MAC, KEY_LEN);
        try {
          hmac = hmacSha256(macKey, Buffer.concat([aad, ciphertext]));
        } finally {
          wipe(macKey);
        }
      }

      const file: SealedFile = {
        ...draft,
        ciphertext,
        ...(hmac && { hmac }),
      };

      return { file, serialized: serializeSealedFile(file) };
    } finally {
      wipe(encKey);
    }
  } finally {
    wipe(derivedKey);
  }
}

/* ──────────────────────────────────────────────────────────────────────── */
/*  UNSEAL                                                                   */
/* ──────────────────────────────────────────────────────────────────────── */

/**
 * Decrypt a SealedFile back to plaintext.
 *
 * All failure modes throw a generic `DECRYPT_FAILED` error to avoid leaking
 * which check failed (oracle defense). The exception is operational errors
 * like `MISSING_KEY` which occur before any cryptographic comparison.
 */
export function unseal(opts: UnsealOptions): Buffer {
  validateMasterKey(opts.masterKey);

  const { file } = opts;
  const derivedKey = deriveMasterKey(opts.masterKey, file.salt, file.kdfParams);
  try {
    // Mode-specific pre-checks BEFORE crypto, so missing config is reported
    // explicitly (these are operator errors, not adversarial probing)
    if (file.mode === 'team' || file.mode === 'enterprise') {
      if (!opts.signingKey) {
        throw new SealedEnvError(
          'MISSING_KEY',
          `${file.mode} mode requires signing key (set SEALED_ENV_SIGNING_KEY)`,
        );
      }
    }
    if (file.mode === 'enterprise') {
      if (!opts.unsealToken) {
        throw new SealedEnvError(
          'MISSING_TOKEN',
          'enterprise mode requires unseal token (set SEALED_ENV_UNSEAL_TOKEN)',
        );
      }
    }

    // Verify HMAC for team/enterprise — fail loud (intentional, integrity is
    // not an oracle, the attacker can already see ciphertext+metadata anyway)
    if (file.mode === 'team' || file.mode === 'enterprise') {
      const macKey = hkdfExpand(opts.signingKey!, file.salt, HKDF_INFO_MAC, KEY_LEN);
      try {
        const aad = buildAad(file);
        const expected = hmacSha256(macKey, Buffer.concat([aad, file.ciphertext]));
        if (!file.hmac || !constantTimeEqual(expected, file.hmac)) {
          throw SealedEnvError.decryptFailed();
        }
      } finally {
        wipe(macKey);
      }
    }

    // Verify unseal token for enterprise mode
    if (file.mode === 'enterprise') {
      const result = verifyUnsealToken({
        token: opts.unsealToken!,
        derivedKey,
        expectedDeployId: opts.deployId ?? null,
        challengeBindEnabled: file.challengeBind === 'enabled',
      });

      // The token carries the TOTP secret. Verify it matches the file's
      // verifier (the file commits to a specific TOTP secret at seal time).
      const expectedVerifier = hmacSha256(
        derivedKey,
        Buffer.concat([result.totpSecret, Buffer.from(TOTP_VERIFY_TAG, 'utf8')]),
      );
      if (
        !file.totpVerifier ||
        !constantTimeEqual(expectedVerifier, file.totpVerifier)
      ) {
        throw SealedEnvError.decryptFailed();
      }
      wipe(result.totpSecret);
    }

    // AAD digest verification (defense in depth: catches metadata tampering
    // even before GCM tag check, which subsumes this)
    const aad = buildAad(file);
    const computedDigest = sha256(aad);
    if (!constantTimeEqual(computedDigest, file.aadDigest)) {
      throw SealedEnvError.decryptFailed();
    }

    // Decrypt
    const encKey = hkdfExpand(derivedKey, file.salt, HKDF_INFO_ENC, KEY_LEN);
    try {
      return aesGcmDecrypt(encKey, file.nonce, file.ciphertext, aad);
    } finally {
      wipe(encKey);
    }
  } finally {
    wipe(derivedKey);
  }
}

/* ──────────────────────────────────────────────────────────────────────── */
/*  LOAD SEALED — convenience layer that reads from disk + env vars         */
/* ──────────────────────────────────────────────────────────────────────── */

/**
 * Read a `.env.sealed` file from disk, decrypt using env-var-supplied keys,
 * and (optionally) populate `process.env` with the resulting key/value pairs.
 *
 * Default behavior matches `dotenv`: parse KEY=value lines, ignore comments
 * starting with `#`, support double-quoted values, and skip lines that
 * already exist in `process.env` (so explicit env vars take precedence).
 */
export function loadSealed(opts: LoadSealedOptions = {}): Record<string, string> {
  const path = opts.path ?? '.env.sealed';
  const populate = opts.populate ?? true;
  const env = opts.envVars ?? {};
  const masterKeyVar = env.masterKey ?? 'SEALED_ENV_KEY';
  const signingKeyVar = env.signingKey ?? 'SEALED_ENV_SIGNING_KEY';
  const unsealTokenVar = env.unsealToken ?? 'SEALED_ENV_UNSEAL_TOKEN';
  const deployIdVar = env.deployId ?? 'SEALED_ENV_DEPLOY_ID';

  const masterKeyStr = process.env[masterKeyVar];
  if (!masterKeyStr) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `sealed-env: environment variable ${masterKeyVar} is required`,
    );
  }
  const masterKey = decodeKeyMaterial(masterKeyStr, masterKeyVar);

  const signingKeyStr = process.env[signingKeyVar];
  const signingKey = signingKeyStr
    ? decodeKeyMaterial(signingKeyStr, signingKeyVar)
    : undefined;

  const unsealToken = process.env[unsealTokenVar];
  const deployId = process.env[deployIdVar];

  const text = readFileSync(resolve(path), 'utf8');
  const file = parseSealedFile(text);
  const plaintextBuf = unseal({
    file,
    masterKey,
    ...(signingKey && { signingKey }),
    ...(unsealToken && { unsealToken }),
    ...(deployId && { deployId }),
  });

  try {
    const plaintext = plaintextBuf.toString('utf8');
    const parsed = parseDotenv(plaintext);
    if (populate) {
      for (const [k, v] of Object.entries(parsed)) {
        if (process.env[k] === undefined) {
          process.env[k] = v;
        }
      }
    }
    return parsed;
  } finally {
    wipe(plaintextBuf);
    wipe(masterKey);
    if (signingKey) wipe(signingKey);
  }
}

/* ──────────────────────────────────────────────────────────────────────── */
/*  Helpers                                                                  */
/* ──────────────────────────────────────────────────────────────────────── */

function validateMasterKey(masterKey: Buffer): void {
  if (!Buffer.isBuffer(masterKey)) {
    throw new SealedEnvError('CONFIG_ERROR', 'masterKey must be a Buffer');
  }
  if (masterKey.length < 16) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'masterKey too short (minimum 16 bytes, recommended 32)',
    );
  }
}

function decodeKeyMaterial(s: string, varName: string): Buffer {
  // Accept hex (64 chars) or base64 (44 chars for 32 raw bytes)
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
    return Buffer.from(s, 'hex');
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    return Buffer.from(s, 'base64');
  }
  throw new SealedEnvError(
    'CONFIG_ERROR',
    `${varName} must be hex or base64 encoded`,
  );
}

/**
 * Minimal dotenv parser. Handles:
 * - KEY=value
 * - KEY="quoted value with spaces and \\\"escapes\\\""
 * - KEY='single-quoted value (no interpolation)'
 * - blank lines
 * - # comments (start of line or after value)
 */
function parseDotenv(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = text.replace(/\r\n/g, '\n').split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;

    const eq = line.indexOf('=');
    if (eq <= 0) continue; // malformed, skip silently
    const key = line.substring(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    let value = line.substring(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value
        .substring(1, value.length - 1)
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    } else if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
      value = value.substring(1, value.length - 1);
    } else {
      // Strip inline trailing comment (basic; inside quotes already handled)
      const hashIdx = value.indexOf(' #');
      if (hashIdx >= 0) {
        value = value.substring(0, hashIdx).trim();
      }
    }
    result[key] = value;
  }
  return result;
}
