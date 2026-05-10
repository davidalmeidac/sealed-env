/**
 * Helpers for the "operator side" of enterprise mode: prompt for a
 * TOTP code, validate it, and mint an unseal token bound to a
 * specific file's salt.
 *
 * Used by:
 *   - `sealed-env unseal` (manual mint, prints the token)
 *   - `sealed-env exec`   (mints in-memory, never prints, sets in env)
 *   - `sealed-env deploy` (wraps exec for the production deploy flow)
 *
 * The TOTP secret is read from the SEALED_ENV_TOTP_SECRET env var
 * (which the auto-loader populates from .env.local or the keychain).
 * It is never printed and is wiped from memory after use.
 */

import { createInterface } from 'node:readline/promises';

import { deriveMasterKey, wipe } from '../../core/crypto.js';
import { SealedEnvError } from '../../core/errors.js';
import { verifyTotp } from '../../totp/totp.js';
import { buildUnsealToken } from '../../totp/unsealToken.js';
import type { SealedFile } from '../../core/types.js';
import { readKeyFromEnv, shellHintFor } from './io.js';
import { decodeBase32 } from './base32.js';

/** Decode a base32-encoded TOTP secret from an env var. */
function readTotpSecret(): Buffer {
  const v = process.env['SEALED_ENV_TOTP_SECRET'];
  if (!v) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `environment variable SEALED_ENV_TOTP_SECRET is required for enterprise mode.\n${shellHintFor('SEALED_ENV_TOTP_SECRET')}`,
    );
  }
  return decodeBase32(v, 'SEALED_ENV_TOTP_SECRET');
}

/**
 * Read a 6-digit TOTP code from the operator. Order of precedence:
 *
 *   1. Explicit `--totp <code>` flag (passed in as the `provided` arg)
 *   2. SEALED_ENV_TOTP_CODE env var (for non-interactive contexts)
 *   3. Interactive prompt on stdin
 *
 * Validates the format and returns the trimmed string.
 */
export async function readTotpCode(provided?: string): Promise<string> {
  let code = (provided ?? '').trim();
  if (!code) code = (process.env['SEALED_ENV_TOTP_CODE'] ?? '').trim();
  if (!code) {
    if (!process.stdin.isTTY) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        'TOTP code required but stdin is not a terminal. Pass --totp <code> or set SEALED_ENV_TOTP_CODE.',
      );
    }
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    code = (await rl.question('TOTP code (6 digits): ')).trim();
    rl.close();
  }
  if (!/^\d{6}$/.test(code)) {
    throw new SealedEnvError('CONFIG_ERROR', 'TOTP code must be exactly 6 digits');
  }
  return code;
}

export interface MintInMemoryInput {
  /** The parsed sealed file — used for salt + kdf params. */
  file: SealedFile;
  /** Optional explicit TOTP code; if omitted, prompts or reads env. */
  totpCode?: string;
  /** deploy_id binding; pass null to skip CHALLENGE-BIND verification. */
  deployId: string | null;
  /** TTL in seconds (clamped 5..600). */
  ttlSeconds?: number;
}

/**
 * Validate a TOTP code (interactively or from input), then mint an
 * unseal token bound to the file's salt + the operator's deploy_id.
 *
 * The token is returned as a string but should be treated as
 * sensitive — the caller is responsible for keeping it out of logs,
 * stdout, and persistent storage. For `exec`/`deploy` flows the
 * caller injects it into the child process env and never prints it.
 *
 * Wipes the TOTP secret and derived key from memory after use.
 */
export async function mintTokenInMemory(input: MintInMemoryInput): Promise<string> {
  const code = await readTotpCode(input.totpCode);

  const totpSecret = readTotpSecret();
  let derivedKey: Buffer | undefined;

  try {
    if (!verifyTotp(totpSecret, code)) {
      throw new SealedEnvError('TOKEN_INVALID', 'TOTP code invalid (or expired)');
    }

    const masterKey = readKeyFromEnv('SEALED_ENV_KEY');
    try {
      derivedKey = deriveMasterKey(masterKey, input.file.salt, input.file.kdfParams);
      const token = buildUnsealToken({
        derivedKey,
        totpSecret,
        salt: input.file.salt,
        deployId: input.deployId,
        ttlSeconds: input.ttlSeconds ?? 60,
      });
      return token;
    } finally {
      wipe(masterKey);
    }
  } finally {
    wipe(totpSecret);
    if (derivedKey) wipe(derivedKey);
  }
}
