/**
 * `sealed-env edit <file.env.sealed>` — open the plaintext in $EDITOR,
 * re-seal and write back when the editor exits.
 *
 * The plaintext lives in a temp file ONLY for the duration of the editor
 * session. The temp file is created with mode 0600, placed in /dev/shm
 * on Linux when available (RAM-backed tmpfs, never hits disk), and is
 * unlinked + zeroed on exit (including SIGINT).
 *
 *   $ sealed-env edit .env.sealed     # uses $EDITOR (defaults to vi)
 *   $ EDITOR=nano sealed-env edit .env.sealed
 *
 * On save: re-seals using the same mode/keys as the original. A backup
 * of the previous sealed file is written to <file>.bak.
 */

import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

import { SealedEnvError } from '../../core/errors.js';
import { decryptSealedFile, resealLikeSource, writeSealedFile } from '../utils/io.js';

export function editCommand(argv: string[]): void {
  const input = argv[0];
  if (!input) {
    throw new SealedEnvError('CONFIG_ERROR', 'usage: sealed-env edit <file.env.sealed>');
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }

  // Decrypt before creating the temp file — fail fast on missing keys.
  const { file: source, plaintext } = decryptSealedFile(input);

  // Pick a tmp directory that is RAM-backed where possible.
  // Linux: /dev/shm is tmpfs by default (no disk write).
  // macOS / Windows: fall back to OS tmpdir.
  let tmpBase = tmpdir();
  try {
    if (existsSync('/dev/shm') && statSync('/dev/shm').isDirectory()) {
      tmpBase = '/dev/shm';
    }
  } catch {
    /* fall through */
  }
  const tmpDir = mkdtempSync(join(tmpBase, 'sealed-env-edit-'));
  const tmpFile = join(tmpDir, '.env.plaintext');

  // Open with mode 0600 explicitly, then write the plaintext.
  const fd = openSync(tmpFile, 'w', 0o600);
  let savedSealed: string | null = null;
  let editorExitCode = -1;

  // Cleanup runs on every exit path.
  const cleanup = () => {
    try {
      // Best-effort overwrite with zeros before unlink (defense in depth;
      // tmpfs may not actually persist this, but on disk-backed paths it
      // matters).
      const bytes = Buffer.alloc(plaintext.length, 0);
      try {
        writeSync(fd, bytes, 0, bytes.length, 0);
      } catch {
        /* ignore */
      }
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* nothing to do */
    }
  };

  // Catch Ctrl+C / kill so we still wipe the temp file.
  const sigHandler = () => {
    cleanup();
    process.exit(130);
  };
  process.on('SIGINT', sigHandler);
  process.on('SIGTERM', sigHandler);

  try {
    writeSync(fd, plaintext, 0, plaintext.length, 0);

    const editor = process.env['VISUAL'] || process.env['EDITOR'] || defaultEditor();
    const proc = spawnSync(editor, [tmpFile], { stdio: 'inherit' });
    editorExitCode = proc.status ?? -1;
    if (proc.error) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        `failed to launch editor "${editor}": ${proc.error.message}`,
      );
    }
    if (editorExitCode !== 0) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        `editor "${editor}" exited with code ${editorExitCode}; not saving changes`,
      );
    }

    // Read the (possibly modified) plaintext back.
    const newPlaintext = readFileSync(tmpFile, 'utf8');

    if (newPlaintext === plaintext.toString('utf8')) {
      process.stdout.write('No changes detected. File untouched.\n');
      return;
    }

    savedSealed = resealLikeSource(source, newPlaintext);
    const absolute = resolve(input);
    writeSealedFile(absolute, savedSealed, { preserveBackup: { backupPath: absolute + '.bak' } });

    process.stdout.write(
      [
        `✓ Re-sealed ${input}`,
        `  Backup of previous file: ${input}.bak`,
        '',
      ].join('\n'),
    );
  } finally {
    process.off('SIGINT', sigHandler);
    process.off('SIGTERM', sigHandler);
    cleanup();
  }
}

function defaultEditor(): string {
  return process.platform === 'win32' ? 'notepad' : 'vi';
}
