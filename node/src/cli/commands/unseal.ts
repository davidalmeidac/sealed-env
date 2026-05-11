/**
 * `sealed-env unseal` — generate an unseal token for a production deploy.
 *
 * Reads:
 *   SEALED_ENV_KEY           the master key
 *   SEALED_ENV_TOTP_SECRET   the operator's TOTP secret (base32)
 *
 * Asks for the current 6-digit code (interactively or via --totp).
 * If valid, prints an unseal token bound to the optional --deploy-id.
 *
 * The token is short-lived (default 60 seconds, max 10 minutes).
 *
 * Salt source for the derived signing key:
 *   - Preferred: --file <path>  → salt and KDF params are extracted from
 *                                 the .env.sealed file. The token will
 *                                 work with that exact file at decrypt time.
 *   - Fallback:  --salt <hex>   → manually provided salt (advanced).
 *   - Opt-in:   --unsafe-zero-salt  DANGEROUS: signs token with all-zero salt.
 *                                   Token will be unsafe for production use.
 *                                   Only correct when the verifying process
 *                                   derived its key from a zero salt in the
 *                                   same run. DO NOT USE in production.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';

import { deriveMasterKey } from '../../core/crypto.js';
import { SealedEnvError } from '../../core/errors.js';
import { verifyTotp } from '../../totp/totp.js';
import { buildUnsealToken } from '../../totp/unsealToken.js';
import { parseSealedFile } from '../../format/parser.js';
import { readKeyFromEnv, readEnvKeyBase32 } from '../utils/io.js';
import { parseFlags } from '../utils/flags.js';
import { DEFAULT_SCRYPT_PARAMS } from '../../format/constants.js';
import type { KdfParams } from '../../core/types.js';
import {
  getAttemptState,
  isLocked,
  recordFailedAttempt,
  resetAttempts,
} from '../utils/rate-limit.js';

export async function unsealCommand(argv: string[]): Promise<void> {
  const { values } = parseFlags(argv, {
    file: { type: 'string', default: '' },
    totp: { type: 'string', default: '' },
    'deploy-id': { type: 'string', default: '' },
    ttl: { type: 'string', default: '60' },
    salt: { type: 'string', default: '' },
    'token-only': { type: 'boolean', default: false },
    'unsafe-zero-salt': { type: 'boolean', default: false },
  });
  const tokenOnly = values['token-only'] as boolean;

  const masterKey = readKeyFromEnv('SEALED_ENV_KEY');
  const totpSecret = readEnvKeyBase32('SEALED_ENV_TOTP_SECRET');

  let code = (values.totp as string).trim();
  if (!code) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    code = (await rl.question('Enter 6-digit TOTP code: ')).trim();
    rl.close();
  }
  if (!/^\d{6}$/.test(code)) {
    throw new SealedEnvError('CONFIG_ERROR', 'TOTP code must be 6 digits');
  }

  // Rate-limit pre-check: reject immediately if master key is currently locked.
  // The TOTP code is NOT evaluated while locked — no verifyTotp call.
  const preLockState = getAttemptState(masterKey);
  if (isLocked(preLockState)) {
    const lockedUntilIso = new Date(preLockState.lockedUntil!).toISOString();
    throw new SealedEnvError(
      'CONFIG_ERROR',
      `Too many failed unseal attempts. Locked until ${lockedUntilIso}. ` +
      `If you suspect compromise, rotate via 'sealed-env init --mode enterprise'.`,
    );
  }

  if (!verifyTotp(totpSecret, code)) {
    // Record the failure (may set lockedUntil in the file for the next attempt).
    recordFailedAttempt(masterKey);
    // Always throw TOKEN_INVALID for the failed attempt itself.
    // The lockout CONFIG_ERROR is shown on the NEXT attempt via the pre-check above.
    throw new SealedEnvError('TOKEN_INVALID', 'TOTP code invalid (or expired)');
  }

  // Successful TOTP verification — reset the attempt counter.
  resetAttempts(masterKey);

  // Determine salt + KDF params. Priority:
  //   1. --file: parse the .env.sealed and use its real salt + params.
  //      Tokens generated this way are interoperable with the file at
  //      decrypt time (this is the path you want for enterprise mode).
  //   2. --salt: manually provided salt, scrypt with default params.
  //   3. neither: zero-salt sentinel (legacy; only OK if the same process
  //      both signs and verifies the token).
  const filePath = (values.file as string) || '';
  const saltOpt = (values.salt as string) || '';

  let salt: Buffer;
  let kdfParams: KdfParams;

  if (filePath) {
    if (!existsSync(filePath)) {
      throw new SealedEnvError('CONFIG_ERROR', `file not found: ${filePath}`);
    }
    const text = readFileSync(resolve(filePath), 'utf8');
    const parsed = parseSealedFile(text);
    salt = parsed.salt;
    kdfParams = parsed.kdfParams;
  } else if (saltOpt) {
    salt = Buffer.from(saltOpt, 'hex');
    if (salt.length !== 16) {
      throw new SealedEnvError('CONFIG_ERROR', '--salt must be 16 bytes (32 hex chars)');
    }
    kdfParams = { kind: 'scrypt', params: { ...DEFAULT_SCRYPT_PARAMS } };
  } else {
    if (!(values['unsafe-zero-salt'] as boolean)) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        '--file or --salt required; pass --unsafe-zero-salt to opt into the ' +
          'legacy zero-salt sentinel (DO NOT USE in production)',
      );
    }
    salt = Buffer.alloc(16, 0); // sentinel
    kdfParams = { kind: 'scrypt', params: { ...DEFAULT_SCRYPT_PARAMS } };
    process.stderr.write(
      'warning: --unsafe-zero-salt active. Signing with zero salt — token only ' +
        'valid against zero-salt files (none in normal use). NOT for production.\n',
    );
  }

  const derivedKey = deriveMasterKey(masterKey, salt, kdfParams);

  const ttl = Math.min(Math.max(Number(values.ttl) || 60, 5), 600);
  const deployId = (values['deploy-id'] as string) || null;

  const token = buildUnsealToken({
    derivedKey,
    totpSecret,
    salt,
    deployId,
    ttlSeconds: ttl,
  });

  if (tokenOnly) {
    // Machine-friendly mode: just the token, no decoration. Useful for
    // shell scripts that want `TOKEN=$(sealed-env unseal --token-only ...)`
    // without parsing through the human-friendly output.
    process.stdout.write(token + '\n');
    return;
  }

  process.stdout.write(
    [
      '',
      `✓ TOTP valid. Unseal token (expires in ${ttl}s):`,
      '',
      token,
      '',
      ...(deployId
        ? [`Deploy id binding: ${deployId}`, '']
        : ['No --deploy-id specified — token is NOT bound to a specific deploy.', '']),
      'Pass to your CI/CD as: SEALED_ENV_UNSEAL_TOKEN=' + token,
      '',
    ].join('\n'),
  );
}

