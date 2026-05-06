/**
 * Reader for the `.env.sealed` file format.
 *
 * Parsing is intentionally strict: any deviation from the spec is an error.
 * This is a security file — sloppy parsing is a vulnerability.
 *
 * Both `KDF=scrypt` and `KDF=argon2id` are accepted for cross-stack interop
 * with the Java implementation (which can write either). Node 22's stdlib
 * does not ship Argon2id, so reading argon2id-tagged files via Node will
 * surface a clear error directing the operator to the Java tool.
 *
 * @see /SPEC.md
 */

import { SealedEnvError } from '../core/errors.js';
import type {
  Mode,
  SealedFile,
  KdfParams,
  KdfAlgorithm,
  Argon2idParams,
  ScryptParams,
} from '../core/types.js';
import { MAGIC_LINE_PREFIX } from './constants.js';

const VALID_MODES: ReadonlySet<Mode> = new Set(['basic', 'team', 'enterprise']);
const VALID_KDFS: ReadonlySet<KdfAlgorithm> = new Set(['scrypt', 'argon2id']);

/**
 * Parse a `.env.sealed` file from its UTF-8 textual form.
 */
export function parseSealedFile(text: string): SealedFile {
  // Normalize line endings — be tolerant of CRLF on Windows but not for AAD
  const normalized = text.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');

  if (lines.length < 5) {
    throw new SealedEnvError('PARSE_ERROR', 'sealed-env: file too short to be valid');
  }

  // ── Magic line (line 0)
  const firstLine = lines[0]!;
  const magicMatch = firstLine.match(/^SEALED-ENV-V(\d+) MODE=([a-z]+)$/);
  if (!magicMatch) {
    throw new SealedEnvError(
      'PARSE_ERROR',
      `sealed-env: invalid magic line: "${truncate(firstLine, 60)}"`,
    );
  }
  const versionNum = Number(magicMatch[1]);
  const modeStr = magicMatch[2]!;
  if (versionNum !== 1) {
    throw new SealedEnvError(
      'UNSUPPORTED_VERSION',
      `sealed-env: file format V${versionNum} is too new, please upgrade your sealed-env library`,
    );
  }
  if (!VALID_MODES.has(modeStr as Mode)) {
    throw new SealedEnvError('UNKNOWN_MODE', `sealed-env: unknown mode "${modeStr}"`);
  }
  const mode = modeStr as Mode;

  // ── Metadata (lines 1..N until empty line)
  const metadata = new Map<string, string>();
  let i = 1;
  for (; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === '') {
      break;
    }
    const eq = line.indexOf('=');
    if (eq <= 0) {
      throw new SealedEnvError(
        'PARSE_ERROR',
        `sealed-env: malformed metadata at line ${i + 1}`,
      );
    }
    const key = line.substring(0, eq);
    const value = line.substring(eq + 1);
    if (!/^[A-Z][A-Z0-9-]*$/.test(key)) {
      throw new SealedEnvError(
        'PARSE_ERROR',
        `sealed-env: invalid metadata key at line ${i + 1}`,
      );
    }
    if (metadata.has(key)) {
      throw new SealedEnvError(
        'PARSE_ERROR',
        `sealed-env: duplicate metadata key "${key}"`,
      );
    }
    metadata.set(key, value);
  }

  if (i >= lines.length - 1) {
    throw new SealedEnvError(
      'PARSE_ERROR',
      'sealed-env: missing separator or body',
    );
  }

  // ── Body (line after empty)
  const bodyLine = lines[i + 1];
  if (!bodyLine) {
    throw new SealedEnvError('PARSE_ERROR', 'sealed-env: empty body');
  }
  const ciphertext = decodeBase64Strict(bodyLine, 'CIPHERTEXT');

  // ── Required fields
  const kdfStr = required(metadata, 'KDF');
  if (!VALID_KDFS.has(kdfStr as KdfAlgorithm)) {
    throw new SealedEnvError('INVALID_FIELD', `sealed-env: unsupported KDF "${kdfStr}"`);
  }
  const kdf = kdfStr as KdfAlgorithm;

  const kdfParams = parseKdfParams(kdf, required(metadata, 'KDF-PARAMS'));
  const salt = decodeBase64Strict(required(metadata, 'SALT'), 'SALT');
  const nonce = decodeBase64Strict(required(metadata, 'NONCE'), 'NONCE');
  const aadDigest = decodeBase64Strict(
    required(metadata, 'AAD-DIGEST'),
    'AAD-DIGEST',
  );
  const created = required(metadata, 'CREATED');

  // ── Optional/conditional fields
  let totpVerifier: Buffer | undefined;
  let challengeBind: 'enabled' | 'disabled' | undefined;
  if (mode === 'enterprise') {
    totpVerifier = decodeBase64Strict(
      required(metadata, 'TOTP-VERIFIER'),
      'TOTP-VERIFIER',
    );
    const cb = required(metadata, 'CHALLENGE-BIND');
    if (cb !== 'enabled' && cb !== 'disabled') {
      throw new SealedEnvError('INVALID_FIELD', 'sealed-env: invalid CHALLENGE-BIND');
    }
    challengeBind = cb;
  }

  let hmac: Buffer | undefined;
  if (mode === 'team' || mode === 'enterprise') {
    hmac = decodeBase64Strict(required(metadata, 'HMAC'), 'HMAC');
  }

  const rotated = metadata.get('ROTATED');

  return {
    version: 1,
    mode,
    kdf,
    kdfParams,
    salt,
    nonce,
    ...(totpVerifier && { totpVerifier }),
    ...(challengeBind && { challengeBind }),
    aadDigest,
    ...(hmac && { hmac }),
    created,
    ...(rotated && { rotated }),
    ciphertext,
  };
}

function required(metadata: Map<string, string>, key: string): string {
  const v = metadata.get(key);
  if (v === undefined) {
    throw new SealedEnvError(
      'MISSING_FIELD',
      `sealed-env: missing required metadata field "${key}"`,
    );
  }
  return v;
}

function parseKdfParams(kdf: KdfAlgorithm, s: string): KdfParams {
  if (kdf === 'argon2id') {
    const m = s.match(/^t=(\d+),m=(\d+),p=(\d+)$/);
    if (!m) {
      throw new SealedEnvError(
        'INVALID_FIELD',
        `sealed-env: invalid argon2id KDF-PARAMS "${s}"`,
      );
    }
    const params: Argon2idParams = {
      t: Number(m[1]),
      m: Number(m[2]),
      p: Number(m[3]),
    };
    if (
      !isFinite(params.t) ||
      !isFinite(params.m) ||
      !isFinite(params.p) ||
      params.t < 1 ||
      params.m < 1024 ||
      params.p < 1
    ) {
      throw new SealedEnvError(
        'INVALID_FIELD',
        'sealed-env: argon2id parameters out of range',
      );
    }
    return { kind: 'argon2id', params };
  }
  // scrypt
  const m = s.match(/^N=(\d+),r=(\d+),p=(\d+)$/);
  if (!m) {
    throw new SealedEnvError(
      'INVALID_FIELD',
      `sealed-env: invalid scrypt KDF-PARAMS "${s}"`,
    );
  }
  const params: ScryptParams = {
    N: Number(m[1]),
    r: Number(m[2]),
    p: Number(m[3]),
  };
  // N must be a power of two and ≥1024 for any sane cost
  if (
    !isFinite(params.N) ||
    !isFinite(params.r) ||
    !isFinite(params.p) ||
    params.N < 1024 ||
    (params.N & (params.N - 1)) !== 0 ||
    params.r < 1 ||
    params.p < 1
  ) {
    throw new SealedEnvError(
      'INVALID_FIELD',
      'sealed-env: scrypt parameters out of range',
    );
  }
  return { kind: 'scrypt', params };
}

function decodeBase64Strict(s: string, fieldName: string): Buffer {
  // Reject whitespace, padding errors, and non-base64 chars
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new SealedEnvError(
      'INVALID_FIELD',
      `sealed-env: invalid base64 in field "${fieldName}"`,
    );
  }
  try {
    return Buffer.from(s, 'base64');
  } catch {
    throw new SealedEnvError(
      'INVALID_FIELD',
      `sealed-env: corrupt base64 in field "${fieldName}"`,
    );
  }
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.substring(0, n)}…` : s;
}

/** Lookup magic-line prefix used elsewhere. */
export const _MAGIC_PREFIX = MAGIC_LINE_PREFIX;
