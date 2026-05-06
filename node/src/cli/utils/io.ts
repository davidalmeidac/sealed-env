/**
 * Shared CLI helpers: read keys from env vars, decrypt a sealed file, and
 * re-seal plaintext. Used by get, set, edit, diff, and decrypt commands so
 * that the four crypto-handling code paths stay identical.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { seal, unseal } from '../../core/api.js';
import { SealedEnvError } from '../../core/errors.js';
import type { Mode, SealedFile } from '../../core/types.js';
import { parseSealedFile } from '../../format/parser.js';

/** Decode an env var that holds key material (hex or base64). */
export function readKeyFromEnv(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError('MISSING_KEY', `environment variable ${varName} is required`);
  }
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}

/**
 * Decrypt a sealed file from disk and return both the parsed metadata
 * (so callers know mode/kdf for re-sealing) and the plaintext.
 */
export function decryptSealedFile(filePath: string): { file: SealedFile; plaintext: Buffer } {
  const text = readFileSync(resolve(filePath), 'utf8');
  const file = parseSealedFile(text);

  const masterKey = readKeyFromEnv('SEALED_ENV_KEY');

  const opts: Parameters<typeof unseal>[0] = { file, masterKey };

  if (file.mode === 'team' || file.mode === 'enterprise') {
    opts.signingKey = readKeyFromEnv('SEALED_ENV_SIGNING_KEY');
  }
  if (file.mode === 'enterprise') {
    const t = process.env['SEALED_ENV_UNSEAL_TOKEN'];
    if (!t) {
      throw new SealedEnvError(
        'MISSING_TOKEN',
        'enterprise file requires SEALED_ENV_UNSEAL_TOKEN',
      );
    }
    opts.unsealToken = t;
    if (file.challengeBind === 'enabled') {
      const d = process.env['SEALED_ENV_DEPLOY_ID'];
      if (!d) {
        throw new SealedEnvError(
          'MISSING_TOKEN',
          'challenge-bound file requires SEALED_ENV_DEPLOY_ID',
        );
      }
      opts.deployId = d;
    }
  }

  const plaintext = unseal(opts);
  return { file, plaintext };
}

/**
 * Re-seal plaintext using the SAME mode + signing/totp inputs as the
 * original file. This keeps `set`, `edit`, etc. round-trippable without
 * forcing the user to re-supply mode-specific flags.
 */
export function resealLikeSource(
  source: SealedFile,
  newPlaintext: string | Buffer,
): string {
  const masterKey = readKeyFromEnv('SEALED_ENV_KEY');
  const opts: Parameters<typeof seal>[0] = {
    plaintext: newPlaintext,
    masterKey,
    mode: source.mode as Mode,
  };
  if (source.mode === 'team' || source.mode === 'enterprise') {
    opts.signingKey = readKeyFromEnv('SEALED_ENV_SIGNING_KEY');
  }
  if (source.mode === 'enterprise') {
    opts.totpSecret = readKeyFromEnv('SEALED_ENV_TOTP_SECRET');
    opts.challengeBind = source.challengeBind === 'enabled';
  }
  const { serialized } = seal(opts);
  return serialized;
}

/**
 * Parse plaintext .env style content into key/value pairs. Preserves
 * insertion order. Lines that don't match KEY=VALUE are kept as-is in a
 * separate "raw lines" array so that comments and blank lines survive
 * round-trips.
 */
export function parseDotenv(text: string): {
  pairs: Map<string, string>;
  rawLines: string[];
} {
  const pairs = new Map<string, string>();
  const rawLines: string[] = [];
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    rawLines.push(line);
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.substring(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    pairs.set(key, trimmed.substring(eq + 1));
  }
  return { pairs, rawLines };
}

/**
 * Render a key/value map back to .env-style text, preserving comments and
 * blank lines from the original raw lines if provided. New keys are
 * appended at the end.
 */
export function serializeDotenv(
  pairs: Map<string, string>,
  rawLines?: string[],
): string {
  if (!rawLines) {
    // Simple path: just emit key=value lines.
    return Array.from(pairs.entries()).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  }

  // Preserve comments + blank lines + order. Replace KEY=value lines in place
  // with the new value if the key changed, drop lines for removed keys, and
  // append new keys at the end.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of rawLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      out.push(line);
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      out.push(line);
      continue;
    }
    const key = trimmed.substring(0, eq).trim();
    if (!pairs.has(key)) continue; // key removed
    seen.add(key);
    out.push(`${key}=${pairs.get(key)}`);
  }
  // Append new keys not in the original.
  for (const [k, v] of pairs.entries()) {
    if (!seen.has(k)) out.push(`${k}=${v}`);
  }
  return out.join('\n');
}
