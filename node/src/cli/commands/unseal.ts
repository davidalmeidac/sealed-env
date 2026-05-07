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
 *   - Last:      no flag        → uses a zero-salt sentinel for legacy use.
 *                                 NOT recommended for enterprise mode.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';

import { deriveMasterKey } from '../../core/crypto.js';
import { SealedEnvError } from '../../core/errors.js';
import { verifyTotp } from '../../totp/totp.js';
import { buildUnsealToken } from '../../totp/unsealToken.js';
import { parseSealedFile } from '../../format/parser.js';
import { parseFlags } from '../utils/flags.js';
import { DEFAULT_SCRYPT_PARAMS } from '../../format/constants.js';
import type { KdfParams } from '../../core/types.js';

export async function unsealCommand(argv: string[]): Promise<void> {
  const { values } = parseFlags(argv, {
    file: { type: 'string', default: '' },
    totp: { type: 'string', default: '' },
    'deploy-id': { type: 'string', default: '' },
    ttl: { type: 'string', default: '60' },
    salt: { type: 'string', default: '' },
  });

  const masterKey = readEnvKey('SEALED_ENV_KEY');
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
  if (!verifyTotp(totpSecret, code)) {
    throw new SealedEnvError('TOKEN_INVALID', 'TOTP code invalid (or expired)');
  }

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
    salt = Buffer.alloc(16, 0); // sentinel
    kdfParams = { kind: 'scrypt', params: { ...DEFAULT_SCRYPT_PARAMS } };
    process.stderr.write(
      'warning: no --file or --salt; signing with zero-salt sentinel. ' +
        'Pass --file <.env.sealed> for tokens that interop with the actual file.\n',
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

function readEnvKey(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) throw new SealedEnvError('MISSING_KEY', `${varName} required`);
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}

function readEnvKeyBase32(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) throw new SealedEnvError('MISSING_KEY', `${varName} required`);
  return decodeBase32(v);
}

function decodeBase32(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const c of cleaned) {
    const idx = alphabet.indexOf(c);
    if (idx < 0) {
      throw new SealedEnvError('CONFIG_ERROR', 'invalid base32 in TOTP secret');
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
