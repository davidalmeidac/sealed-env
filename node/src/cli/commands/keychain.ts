/**
 * `sealed-env keychain <subcommand>` — manage SEALED_ENV_* secrets in
 * the OS-native keychain instead of `.env.local`.
 *
 *   push    — read .env.local, write each SEALED_ENV_* into the
 *             keychain, then optionally delete .env.local. The keys
 *             are now encrypted at rest by the OS.
 *   pull    — read each SEALED_ENV_* from the keychain and write to
 *             .env.local. Useful for migrating to a different machine
 *             or back to file-based storage.
 *   status  — list which entries exist (no values printed). Shows
 *             a 4+4 SHA-256 fingerprint per entry, same as `doctor`.
 *   clear   — remove all sealed-env entries from the keychain.
 *
 * Once `push` has run, the auto-loader in every other sealed-env
 * command prefers the keychain over `.env.local`.
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline/promises';

import { SealedEnvError } from '../../core/errors.js';
import { parseDotenv } from '../utils/io.js';

/**
 * Project-level marker that opts this directory into keychain-backed
 * auto-loading. Without this file (or `SEALED_ENV_USE_KEYCHAIN=1` in
 * the env), the auto-load helper skips the keychain entirely — so
 * users who never opt in pay zero overhead.
 *
 * Safe to commit: contains no secrets, just the choice of backend.
 * Different team members can then independently `keychain push` their
 * own credentials and the project's behavior stays consistent.
 */
const MARKER_FILE = '.sealed-env.json';

function writeMarker(backendLabel: string): void {
  const path = resolve(MARKER_FILE);
  const cfg = {
    $schema: 'https://github.com/davidalmeidac/sealed-env/blob/main/SPEC.md',
    storage: 'keychain' as const,
    backend: backendLabel,
    createdAt: new Date().toISOString(),
    note:
      'Created by `sealed-env keychain push`. Tells the auto-loader to ' +
      'check the OS keychain. Safe to commit. Remove with `sealed-env keychain clear`.',
  };
  writeFileSync(path, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o644 });
}

function removeMarker(): void {
  const path = resolve(MARKER_FILE);
  if (existsSync(path)) {
    try {
      unlinkSync(path);
    } catch {
      /* ignore */
    }
  }
}
import {
  KEYCHAIN_NAMES,
  detectBackend,
  type KeychainName,
} from '../utils/keychain.js';

export async function keychainCommand(argv: string[]): Promise<void> {
  const sub = argv[0];
  if (!sub || !['push', 'pull', 'status', 'clear'].includes(sub)) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env keychain <push|pull|status|clear>\n' +
        '\n  push    move .env.local secrets into the OS keychain\n' +
        '  pull    write keychain secrets back to .env.local\n' +
        '  status  list which entries exist (no values shown)\n' +
        '  clear   remove all sealed-env entries from the keychain',
    );
  }

  const backend = detectBackend();
  if (!backend) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      `OS keychain not supported on ${process.platform}. Stick to .env.local for now.`,
    );
  }
  if (!backend.isAvailable()) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      `${backend.label} CLI not found in PATH.\n` +
        installHintFor(backend.label),
    );
  }

  switch (sub) {
    case 'push':
      await pushCommand(backend);
      return;
    case 'pull':
      await pullCommand(backend);
      return;
    case 'status':
      statusCommand(backend);
      return;
    case 'clear':
      await clearCommand(backend);
      return;
  }
}

async function pushCommand(
  backend: ReturnType<typeof detectBackend> & {},
): Promise<void> {
  const path = resolve('.env.local');
  if (!existsSync(path)) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'no .env.local in this directory — nothing to push.',
    );
  }

  const text = readFileSync(path, 'utf8');
  const { pairs } = parseDotenv(text);

  const matched: KeychainName[] = [];
  for (const name of KEYCHAIN_NAMES) {
    if (pairs.has(name)) matched.push(name);
  }
  if (matched.length === 0) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      '.env.local has no SEALED_ENV_* entries to push.',
    );
  }

  process.stdout.write(`Pushing to ${backend.label}:\n`);
  for (const name of matched) {
    backend.write(name, pairs.get(name)!);
    process.stdout.write(`  [✓] ${name}\n`);
  }

  // Drop the opt-in marker so future commands check the keychain.
  // Without this, the auto-loader doesn't even spawn the keychain
  // backend (saves ~300ms / command for users who never opted in).
  writeMarker(backend.label);
  process.stdout.write(`✓ Wrote ${MARKER_FILE} (commit it to standardize the team)\n`);

  // Offer to delete .env.local. The whole point of pushing is to stop
  // having a plaintext copy on disk. We confirm explicitly because
  // accidentally deleting your only copy of the keys could lock the
  // operator out — even though the keychain has them now, "I changed
  // my mind, where's my .env.local?" is a real concern.
  if (process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const ans = (
      await rl.question(
        '\nDelete .env.local now that the keys are in the keychain? [y/N] ',
      )
    )
      .trim()
      .toLowerCase();
    rl.close();
    if (ans === 'y' || ans === 'yes') {
      unlinkSync(path);
      process.stdout.write('✓ Deleted .env.local\n');
    } else {
      process.stdout.write(
        '✓ Keys are in the keychain. .env.local kept (delete it manually when ready).\n',
      );
    }
  } else {
    process.stdout.write(
      '\n✓ Done. Run `rm .env.local` (or your platform equivalent) to remove the plaintext copy.\n',
    );
  }
}

async function pullCommand(
  backend: ReturnType<typeof detectBackend> & {},
): Promise<void> {
  const path = resolve('.env.local');
  if (existsSync(path)) {
    if (process.stdin.isTTY) {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      const ans = (
        await rl.question(
          '.env.local already exists. Overwrite? [y/N] ',
        )
      )
        .trim()
        .toLowerCase();
      rl.close();
      if (ans !== 'y' && ans !== 'yes') {
        process.stdout.write('Aborted.\n');
        return;
      }
    } else {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        '.env.local already exists. Refusing to overwrite without confirmation (TTY required).',
      );
    }
  }

  const lines: string[] = ['# sealed-env keys — DO NOT COMMIT THIS FILE.'];
  let count = 0;
  for (const name of KEYCHAIN_NAMES) {
    const v = backend.read(name);
    if (v !== null) {
      lines.push(`${name}=${v}`);
      count++;
    }
  }
  if (count === 0) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      `no sealed-env entries in ${backend.label} — push some first.`,
    );
  }
  writeFileSync(path, lines.join('\n') + '\n', { mode: 0o600 });
  // Pull means "I want the .env.local back" — drop the keychain marker
  // so auto-load uses the file copy from now on. Keychain entries
  // remain stored unless user runs `clear` separately.
  removeMarker();
  process.stdout.write(
    `✓ Pulled ${count} entr${count === 1 ? 'y' : 'ies'} from ${backend.label} → .env.local (mode 0600)\n`,
  );
  process.stdout.write(
    `✓ Removed ${MARKER_FILE} — auto-load will read from .env.local now\n`,
  );
  process.stdout.write(
    `(keychain entries kept; run "sealed-env keychain clear" if you want them gone too)\n`,
  );
}

function statusCommand(
  backend: ReturnType<typeof detectBackend> & {},
): void {
  process.stdout.write(`Backend: ${backend.label}\n`);
  const markerPath = resolve(MARKER_FILE);
  const markerExists = existsSync(markerPath);
  const envOptIn = process.env['SEALED_ENV_USE_KEYCHAIN'] === '1';
  process.stdout.write(`Opt-in:  ${MARKER_FILE} = ${markerExists ? 'present ✓' : 'missing'}`);
  if (envOptIn) process.stdout.write('  (SEALED_ENV_USE_KEYCHAIN=1)');
  process.stdout.write('\n\n');
  for (const name of KEYCHAIN_NAMES) {
    const v = backend.read(name);
    if (v === null) {
      process.stdout.write(`  [✗] ${name.padEnd(24)}  (not stored)\n`);
    } else {
      const fp = createHash('sha256').update(v).digest('hex');
      const short = `${fp.substring(0, 4)}..${fp.substring(60)}`;
      process.stdout.write(
        `  [✓] ${name.padEnd(24)}  ${v.length} chars (sha256: ${short})\n`,
      );
    }
  }
}

async function clearCommand(
  backend: ReturnType<typeof detectBackend> & {},
): Promise<void> {
  if (process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const ans = (
      await rl.question(
        `Remove ALL sealed-env entries from ${backend.label}? [y/N] `,
      )
    )
      .trim()
      .toLowerCase();
    rl.close();
    if (ans !== 'y' && ans !== 'yes') {
      process.stdout.write('Aborted.\n');
      return;
    }
  }
  for (const name of KEYCHAIN_NAMES) {
    backend.remove(name);
  }
  removeMarker();
  process.stdout.write(`✓ Cleared sealed-env entries from ${backend.label}\n`);
  process.stdout.write(`✓ Removed ${MARKER_FILE} — auto-load will fall back to .env.local\n`);
}

function installHintFor(label: string): string {
  if (label.startsWith('Windows')) {
    return 'cmdkey + PowerShell ship with Windows. If they\'re missing, repair the install.';
  }
  if (label.startsWith('macOS')) {
    return '`security` ships with macOS. If missing, repair Xcode CLI tools.';
  }
  if (label.startsWith('libsecret')) {
    return 'Install with: sudo apt install libsecret-tools  (or your distro equivalent)';
  }
  return '';
}
