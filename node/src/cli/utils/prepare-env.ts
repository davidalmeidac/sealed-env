/**
 * Shared helper for "decrypt a sealed file → return a Map of plaintext
 * env vars ready to inject into a child process".
 *
 * Used by:
 *   - `exec` (local child process)
 *   - `deploy --remote` (ship via SSH)
 *
 * Both paths need the same crypto + token-mint logic; only the
 * destination of the resulting env vars differs.
 *
 * The plaintext buffer returned by `decryptSealedFile` is wiped after
 * we copy values out, so callers do NOT need to handle it themselves.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { SealedEnvError } from '../../core/errors.js';
import { parseSealedFile } from '../../format/parser.js';
import { decryptSealedFile, parseDotenv } from './io.js';
import { mintTokenInMemory } from './token.js';

export interface PrepareOptions {
  filePath: string;
  /** TOTP code for enterprise mode. Empty/undefined → prompt or fail. */
  totp?: string;
  /** Deploy id (e.g. git commit sha). Empty → mintTokenInMemory may try other sources. */
  deployId?: string;
  /** Token TTL when minting in enterprise mode. Default: 60 seconds. */
  ttlSeconds?: number;
}

export interface PreparedEnv {
  /** Decrypted KEY → value pairs from the sealed file. */
  envVars: Map<string, string>;
  /** Resolved deploy-id (or empty string if not enterprise / not provided). */
  deployId: string;
  /** True if the file was enterprise mode (token was minted). */
  enterprise: boolean;
}

/**
 * Read, decrypt, and parse the sealed file. Mints a TOTP-bound unseal
 * token in memory if the file is enterprise mode.
 *
 * Throws SealedEnvError on missing keys, wrong totp, parse errors, etc.
 */
export async function prepareEnvFromSealed(opts: PrepareOptions): Promise<PreparedEnv> {
  const { filePath } = opts;
  if (!existsSync(filePath)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${filePath}`);
  }

  // Pre-flight: parse the file once to determine its mode. If it's
  // enterprise, mint a token and stuff it into process.env so the
  // existing unseal path picks it up uniformly.
  const fileText = readFileSync(resolve(filePath), 'utf8');
  const file = parseSealedFile(fileText);
  const isEnterprise = file.mode === 'enterprise';

  let resolvedDeployId = (opts.deployId ?? '').trim();

  if (isEnterprise && !process.env['SEALED_ENV_UNSEAL_TOKEN']) {
    process.stderr.write(
      `(enterprise mode detected — minting unseal token in memory)\n`,
    );
    const token = await mintTokenInMemory({
      file,
      totpCode: opts.totp ?? '',
      deployId: resolvedDeployId || null,
      ttlSeconds: opts.ttlSeconds ?? 60,
    });
    process.env['SEALED_ENV_UNSEAL_TOKEN'] = token;
    if (resolvedDeployId) process.env['SEALED_ENV_DEPLOY_ID'] = resolvedDeployId;
  }

  // Decrypt + parse. decryptSealedFile already throws shell-hint-aware
  // MISSING_KEY errors if env vars are missing.
  const { plaintext } = decryptSealedFile(filePath);
  const { pairs } = parseDotenv(plaintext.toString('utf8'));

  // Copy pairs into a Map and zero the plaintext buffer.
  const envVars = new Map<string, string>(pairs);
  plaintext.fill(0);

  return { envVars, deployId: resolvedDeployId, enterprise: isEnterprise };
}
