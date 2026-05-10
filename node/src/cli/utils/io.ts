/**
 * Shared CLI helpers: read keys from env vars, decrypt a sealed file, and
 * re-seal plaintext. Used by get, set, edit, diff, and decrypt commands so
 * that the four crypto-handling code paths stay identical.
 */

import fs, {
  existsSync,
  readFileSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

import { seal, unseal } from '../../core/api.js';
import { SealedEnvError } from '../../core/errors.js';
import type { Mode, SealedFile } from '../../core/types.js';
import { parseSealedFile } from '../../format/parser.js';
import { decodeBase32 } from './base32.js';

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
 * Decode an env var that holds a base32-encoded key (e.g. TOTP secret).
 *
 * Throws `MISSING_KEY` (with a shell hint) if the var is absent.
 * Throws `CONFIG_ERROR` if the value is not valid base32.
 */
export function readEnvKeyBase32(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `environment variable ${varName} is required.\n${shellHintFor(varName)}`,
    );
  }
  return decodeBase32(v, varName);
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
    opts.totpSecret = readEnvKeyBase32('SEALED_ENV_TOTP_SECRET');
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
 *   2. **OS keychain** — only if the project opted in by running
 *      `sealed-env keychain push` (which creates `.sealed-env.json` in
 *      cwd as a marker), or if `SEALED_ENV_USE_KEYCHAIN=1` is set
 *      explicitly. Without one of those signals we DON'T spawn the
 *      platform CLI on every command — that would add ~300ms of
 *      overhead for users who never enabled the keychain backend.
 *   3. `.env.local` in `cwd` — the default for projects that haven't
 *      adopted the keychain.
 *
 * Returns the count of keys actually loaded plus the source string
 * (`"OS keychain"` / `".env.local"` / `""` if nothing was loaded), so
 * the caller can log a stderr breadcrumb without printing values.
 *
 * Only `SEALED_ENV_*` keys are touched. Other variables in `.env.local`
 * (if any) are ignored — that prevents this helper from acting as a
 * generic dotenv loader.
 */
export function autoloadSealedEnvLocal(
  cwd: string = process.cwd(),
): { loaded: number; source: string } {
  let loaded = 0;
  let sourceUsed = '';

  // Step 1: keychain — but only if the project has opted in.
  if (isKeychainEnabled(cwd)) {
    try {
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
 * Check whether this project has opted into keychain-backed auto-load.
 * Two signals trigger it:
 *
 *   1. `.sealed-env.json` in cwd with `{ "storage": "keychain" }` —
 *      written by `sealed-env keychain push`. Persistent and committable
 *      so a team can standardize on keychain across machines.
 *   2. `SEALED_ENV_USE_KEYCHAIN=1` env var — for one-off / CI override.
 *
 * Without either, we skip the keychain path entirely. This means users
 * who never run `keychain push` pay ZERO overhead from this feature.
 */
export function isKeychainEnabled(cwd: string = process.cwd()): boolean {
  if (process.env['SEALED_ENV_USE_KEYCHAIN'] === '1') return true;
  const marker = resolve(cwd, '.sealed-env.json');
  if (!existsSync(marker)) return false;
  try {
    const cfg = JSON.parse(readFileSync(marker, 'utf8')) as { storage?: string };
    return cfg.storage === 'keychain';
  } catch {
    return false;
  }
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
 * Atomically write a sealed-file payload to `path` with mode 0o600 on POSIX.
 *
 * Strategy:
 *   1. Write to `<path>.tmp-<pid>` with mode 0o600.
 *   2. fsync the temp fd before close (crash-durability — survives power loss).
 *   3. If `options.preserveBackup` is supplied, copyFileSync(path → backupPath)
 *      then chmodSync(backupPath, 0o600). Done BEFORE rename so the backup is
 *      always the pre-write state.
 *   4. renameSync(<path>.tmp, path) — atomic on POSIX, atomic-enough on NTFS
 *      via Node's MoveFileEx semantics.
 *   5. Defense-in-depth: chmodSync(path, mode) on non-Windows (some filesystems
 *      drop mode bits across a rename).
 *   6. On error in any step: unlinkSync the temp file (best effort) and rethrow.
 *
 * Windows note: `mode` is silently ignored by Node on Windows (NTFS uses ACLs).
 * The temp+fsync+rename sequence still runs and still provides atomicity.
 * SEC-003 explicitly ships as POSIX-only; Windows ACL hardening is tracked as a
 * follow-up.
 *
 * SEC-003 + SEC-019: all sealed-file writes in the CLI MUST route through here.
 */
export function writeSealedFile(
  path: string,
  content: string | Buffer,
  options?: {
    /** Default 0o600. */
    mode?: number;
    /** If set, copy path → backupPath BEFORE rename so backup is pre-write state. */
    preserveBackup?: { backupPath: string };
  },
): void {
  const mode = options?.mode ?? 0o600;
  const tmpPath = `${path}.tmp-${process.pid}`;
  const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;

  let fd: number | undefined;
  try {
    fd = fs.openSync(tmpPath, 'w', mode);
    fs.writeSync(fd, buf, 0, buf.length, 0);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
  } catch (err) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
    throw err;
  }

  // Step 3: preserve backup BEFORE rename so backup is pre-write state.
  if (options?.preserveBackup) {
    try {
      fs.copyFileSync(path, options.preserveBackup.backupPath);
      if (process.platform !== 'win32') {
        fs.chmodSync(options.preserveBackup.backupPath, 0o600);
      }
    } catch (err) {
      try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
      throw err;
    }
  }

  // Step 4: atomic rename.
  try {
    fs.renameSync(tmpPath, path);
  } catch (err) {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
    throw err;
  }

  // Step 5: defense-in-depth chmod (some filesystems drop mode bits across rename).
  if (process.platform !== 'win32') {
    try { fs.chmodSync(path, mode); } catch { /* best effort */ }
  }
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
