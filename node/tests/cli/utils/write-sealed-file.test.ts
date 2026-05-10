/**
 * Unit tests for writeSealedFile (SEC-003 + SEC-019).
 *
 * Tests:
 *  1. Success path: content written correctly, no backup
 *  2. Mode 0o600 on POSIX
 *  3. Backup file created with mode 0o600 on POSIX
 *  4. Crash simulation: renameSync throws → original untouched, temp cleaned up
 *  5. Windows degradation: mode ignored, no throw
 */

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs, {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  statSync,
  existsSync,
  rmSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir as osTmpdir } from 'node:os';

import { writeSealedFile } from '../../../src/cli/utils/io.js';

function makeTmpDir(): string {
  return mkdtempSync(join(osTmpdir(), 'wsf-test-'));
}

test('writes content to the target path', () => {
  const dir = makeTmpDir();
  const filePath = join(dir, 'out.sealed');
  const content = 'STRIPE_KEY=sk_test\nDB=postgres://localhost\n';

  writeSealedFile(filePath, content);

  assert.strictEqual(readFileSync(filePath, 'utf8'), content);

  // No temp file remains
  const tmpPath = `${filePath}.tmp-${process.pid}`;
  assert.ok(!existsSync(tmpPath), 'temp file must not remain after success');

  rmSync(dir, { recursive: true });
});

test('final file has mode 0o600 on POSIX', { skip: process.platform === 'win32' ? 'POSIX only' : false }, () => {
  const dir = makeTmpDir();
  const filePath = join(dir, 'mode-test.sealed');

  writeSealedFile(filePath, 'X=1\n');

  const mode = statSync(filePath).mode & 0o777;
  assert.strictEqual(mode, 0o600, `expected 0o600, got 0o${mode.toString(8)}`);

  rmSync(dir, { recursive: true });
});

test('backup file created with mode 0o600 on POSIX', { skip: process.platform === 'win32' ? 'POSIX only' : false }, () => {
  const dir = makeTmpDir();
  const filePath = join(dir, 'with-backup.sealed');
  const backupPath = filePath + '.bak';

  // Pre-existing file to back up
  writeFileSync(filePath, 'ORIGINAL=content\n', { mode: 0o644 });

  writeSealedFile(filePath, 'NEW=content\n', {
    preserveBackup: { backupPath },
  });

  // Backup exists and has the original content
  assert.ok(existsSync(backupPath), 'backup file must exist');
  assert.strictEqual(readFileSync(backupPath, 'utf8'), 'ORIGINAL=content\n');

  // Backup has mode 0o600
  const backupMode = statSync(backupPath).mode & 0o777;
  assert.strictEqual(backupMode, 0o600, `backup must be 0o600, got 0o${backupMode.toString(8)}`);

  // Final file updated
  assert.strictEqual(readFileSync(filePath, 'utf8'), 'NEW=content\n');

  rmSync(dir, { recursive: true });
});

test('crash simulation: renameSync throws → original untouched, temp cleaned up', () => {
  const dir = makeTmpDir();
  const filePath = join(dir, 'crash-test.sealed');
  const originalContent = 'ORIGINAL=safe\n';

  // Write original
  writeFileSync(filePath, originalContent);

  // Mock renameSync to throw
  mock.method(fs, 'renameSync', () => { throw new Error('simulated crash'); });

  assert.throws(
    () => writeSealedFile(filePath, 'NEW=content\n'),
    /simulated crash/,
  );

  mock.restoreAll();

  // Original file is untouched
  assert.strictEqual(readFileSync(filePath, 'utf8'), originalContent);

  // Temp file must be cleaned up
  const tmpPath = `${filePath}.tmp-${process.pid}`;
  assert.ok(!existsSync(tmpPath), 'temp file must be cleaned up on failure');

  rmSync(dir, { recursive: true });
});

test('Windows degradation: write succeeds without throwing on mode ignore', () => {
  // This test covers the documented behavior: on Windows, chmodSync on the
  // final file is skipped (wrapped in platform check), so no EPERM is thrown.
  // We run on Windows natively or mock process.platform.
  const dir = makeTmpDir();
  const filePath = join(dir, 'win-test.sealed');
  const content = 'WIN=ok\n';

  // Temporarily override platform
  const originalPlatform = process.platform;
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });

  try {
    // Must not throw
    assert.doesNotThrow(() => writeSealedFile(filePath, content));
    assert.strictEqual(readFileSync(filePath, 'utf8'), content);
  } finally {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
    rmSync(dir, { recursive: true });
  }
});
