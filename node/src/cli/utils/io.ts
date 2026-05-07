/**
 * Shared CLI helpers: read keys from env vars, decrypt a sealed file, and
 * re-seal plaintext. Used by get, set, edit, diff, and decrypt commands so
 * that the four crypto-handling code paths stay identical.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

import { seal, unseal } from '../../core/api.js';
import { SealedEnvError } from '../../core/errors.js';
import type { Mode, SealedFile } from '../../core/types.js';
import { parseSealedFile } from '../../format/parser.js';

/** Decode an env var that holds key material (hex or base64). */
export function readKeyFromEnv(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `environment variable ${varName} is required.\n${shellHintFor(varName)}`,
    );
  }
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}

/**
 * Build a shell-appropriate "how to set this env var" hint. A frequent
 * footgun on Windows is using cmd.exe's `set X=Y` syntax inside a
 * PowerShell session — PowerShell parses that as `Set-Variable` and
 * creates a session-scoped PowerShell variable instead of an env var,
 * which child processes (like sealed-env) never see. We show both
 * syntaxes on Windows to cover the user no matter which shell they
 * are running in.
 */
export function shellHintFor(varName: string): string {
  const example = '<paste-the-hex-or-base64-key-here>';
  if (process.platform === 'win32') {
    return [
      'How to set it:',
      `  PowerShell:  $env:${varName} = "${example}"`,
      `  cmd.exe:     set ${varName}=${example}`,
      `  Git Bash:    export ${varName}="${example}"`,
      '',
      'Note: in PowerShell, `set X=Y` is NOT an env var — it creates a',
      'PowerShell variable that child processes cannot see. Use $env: instead.',
    ].join('\n');
  }
  return [
    'How to set it:',
    `  export ${varName}="${example}"`,
  ].join('\n');
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
 * Auto-load `SEALED_ENV_*` variables. Priority (highest first):
 *
 *   1. `process.env` — values already set by the parent shell or CI
 *      always win. We never override.
 *   2. **OS keychain** (Windows DPAPI / macOS Keychain / libsecret)
 *      — encrypted at rest, locked to the user login. If the operator
 *      has run `sealed-env keychain push` previously, the values live
 *      here and we read them on demand.
 *   3. `.env.local` in `cwd` — fallback for projects that haven't
 *      adopted the keychain yet, or for CI bootstrap.
 *
 * Returns the count of keys actually loaded, plus the source string
 * (`"keychain"` / `".env.local"` / `""` if nothing was loaded), so the
 * caller can log something useful to stderr without printing values.
 *
 * Only `SEALED_ENV_*` keys are touched. Other variables in `.env.local`
 * (if any) are ignored — that prevents this helper from acting as a
 * generic dotenv loader.
 */
export function autoloadSealedEnvLocal(
  cwd: string = process.cwd(),
): { loaded: number; source: string } {
  // Step 1: keychain first (more secure). We try lazily — only import
  // the backend when we actually need it, so non-enterprise / non-
  // keychain users don't pay the spawn cost.
  let loaded = 0;
  let sourceUsed = '';
  try {
    // Lazy require to avoid loading the keychain module on every
    // command invocation when no keychain is set up.
    const requireFn = createRequire(import.meta.url);
    const keychainMod = requireFn('./keychain.js') as {
      detectBackend: () => {
        isAvailable(): boolean;
        read(name: string): string | null;
      } | null;
      KEYCHAIN_NAMES: readonly string[];
    };
    const backend = keychainMod.detectBackend();
    if (backend && backend.isAvailable()) {
      for (const name of keychainMod.KEYCHAIN_NAMES) {
        if (process.env[name] !== undefined) continue; // host wins
        const v = backend.read(name);
        if (v !== null) {
          process.env[name] = v;
          loaded++;
          sourceUsed = 'OS keychain';
        }
      }
    }
  } catch {
    // Backend errored — silently fall through to file-based loading.
  }

  // Step 2: .env.local fills in anything still missing.
  const path = resolve(cwd, '.env.local');
  if (existsSync(path)) {
    let text: string;
    try {
      text = readFileSync(path, 'utf8');
    } catch {
      return { loaded, source: sourceUsed };
    }
    const { pairs } = parseDotenv(text);
    let fileLoaded = 0;
    for (const [key, value] of pairs) {
      if (!key.startsWith('SEALED_ENV_')) continue;
      if (process.env[key] !== undefined) continue;
      process.env[key] = value;
      fileLoaded++;
    }
    if (fileLoaded > 0) {
      loaded += fileLoaded;
      sourceUsed = sourceUsed ? `${sourceUsed} + .env.local` : '.env.local';
    }
  }

  return { loaded, source: sourceUsed };
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
