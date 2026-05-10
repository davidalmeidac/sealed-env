/**
 * `sealed-env encrypt <input.env>` — produce a .env.sealed file.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { seal } from '../../core/api.js';
import { SealedEnvError } from '../../core/errors.js';
import type { Mode } from '../../core/types.js';
import { shellHintFor, writeSealedFile } from '../utils/io.js';
import { parseFlags } from '../utils/flags.js';

export function encryptCommand(argv: string[]): void {
  const { values, positional } = parseFlags(argv, {
    out: { type: 'string', default: '' },
    mode: { type: 'string', default: 'basic' },
  });

  const input = positional[0];
  if (!input) {
    throw new SealedEnvError('CONFIG_ERROR', 'usage: sealed-env encrypt <file.env>');
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }

  const mode = values.mode as Mode;
  if (mode !== 'basic' && mode !== 'team' && mode !== 'enterprise') {
    throw new SealedEnvError('CONFIG_ERROR', `unknown mode "${mode}"`);
  }

  const masterKey = readEnvKey('SEALED_ENV_KEY');
  const signingKey =
    mode === 'team' || mode === 'enterprise'
      ? readEnvKey('SEALED_ENV_SIGNING_KEY')
      : undefined;
  const totpSecret =
    mode === 'enterprise' ? readEnvKey('SEALED_ENV_TOTP_SECRET', true) : undefined;

  const plaintext = readFileSync(resolve(input), 'utf8');

  const { serialized } = seal({
    plaintext,
    masterKey,
    mode,
    ...(signingKey && { signingKey }),
    ...(totpSecret && { totpSecret }),
  });

  // If the user passed --out, respect it as-is (no surprise suffixing).
  // Otherwise default to "<input>.sealed" so the convention is obvious.
  const finalOut = values.out
    ? resolve(values.out as string)
    : resolve(`${input}.sealed`);
  writeSealedFile(finalOut, serialized);

  process.stdout.write(`✓ Encrypted ${input} → ${finalOut} (mode: ${mode})\n`);
  process.stdout.write(
    `  Remember to commit ${finalOut} but NOT ${input} — add ${input} to .gitignore.\n`,
  );
}

function readEnvKey(varName: string, base32 = false): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `environment variable ${varName} is required.\n${shellHintFor(varName)}`,
    );
  }
  if (base32) {
    return decodeBase32(v);
  }
  // Try hex first, then base64
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
    return Buffer.from(v, 'hex');
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) {
    return Buffer.from(v, 'base64');
  }
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
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
