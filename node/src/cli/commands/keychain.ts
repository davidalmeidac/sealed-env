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
  process.stdout.write(
    `✓ Pulled ${count} entr${count === 1 ? 'y' : 'ies'} from ${backend.label} → .env.local (mode 0600)\n`,
  );
}

function statusCommand(
  backend: ReturnType<typeof detectBackend> & {},
): void {
  process.stdout.write(`Backend: ${backend.label}\n\n`);
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
  process.stdout.write(`✓ Cleared sealed-env entries from ${backend.label}\n`);
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
