/**
 * Unit tests for the TOTP rate-limit helper (SEC-009).
 *
 * TDD: tests written first (RED), then rate-limit.ts implemented (GREEN).
 *
 * Tests cover:
 *  1. Missing file → fresh state returned
 *  2. recordFailedAttempt increments and persists
 *  3. 5th failure sets lockedUntil = now + 300_000
 *  4. isLocked detects future lockedUntil
 *  5. isLocked returns false for past/null lockedUntil
 *  6. resetAttempts deletes the file
 *  7. resetAttempts on non-existent file does not throw
 *  8. Lockout expiry → next failure resets counter to 1 (new window)
 *  9. Corrupted JSON treated as fresh state
 * 10. mkdir -p created on first write
 * 11. Same master key bytes → same file name (deterministic fingerprint)
 * 12. Fingerprint is 32 lowercase hex chars
 * 13. Different keys → different files
 * 14. Increments correctly across multiple failures within window
 * 15. File mode is 0o600 on POSIX (skipped on Windows)
 *
 * Isolation: HOME (POSIX) / USERPROFILE (Windows) set to a temp dir so the
 * helper never writes to the real user's ~/.sealed-env-state/.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs, { mkdtempSync, rmSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir as osTmpdir } from 'node:os';

import {
  getAttemptState,
  recordFailedAttempt,
  resetAttempts,
  isLocked,
  type AttemptState,
} from '../../../src/cli/utils/rate-limit.js';

/** Build a 32-byte master key with a repeating byte pattern. */
function makeKey(byte: number = 0xab): Buffer {
  return Buffer.alloc(32, byte);
}

/** Create a temporary directory to use as the fake HOME. */
function makeTmpHome(): string {
  return mkdtempSync(join(osTmpdir(), 'rate-limit-home-'));
}

let tmpHome: string;
let savedHome: string | undefined;
let savedUserProfile: string | undefined;

describe('rate-limit helper', () => {
  beforeEach(() => {
    tmpHome = makeTmpHome();
    // Override HOME (POSIX) and USERPROFILE (Windows) so os.homedir() resolves
    // to our temp directory for the duration of each test.
    savedHome = process.env['HOME'];
    savedUserProfile = process.env['USERPROFILE'];
    process.env['HOME'] = tmpHome;
    process.env['USERPROFILE'] = tmpHome;
  });

  afterEach(() => {
    // Restore original HOME / USERPROFILE
    if (savedHome === undefined) {
      delete process.env['HOME'];
    } else {
      process.env['HOME'] = savedHome;
    }
    if (savedUserProfile === undefined) {
      delete process.env['USERPROFILE'];
    } else {
      process.env['USERPROFILE'] = savedUserProfile;
    }
    rmSync(tmpHome, { recursive: true, force: true });
  });

  test('getAttemptState on missing file returns fresh state', () => {
    const state = getAttemptState(makeKey());
    assert.strictEqual(state.attempts, 0);
    assert.strictEqual(state.firstFailureAt, 0);
    assert.strictEqual(state.lockedUntil, null);
  });

  test('recordFailedAttempt increments attempts and writes file', () => {
    const key = makeKey(0x01);
    const state = recordFailedAttempt(key);

    assert.strictEqual(state.attempts, 1);
    assert.ok(state.firstFailureAt > 0, 'firstFailureAt should be non-zero');
    assert.strictEqual(state.lockedUntil, null);

    // File should persist — getAttemptState reads it back
    const readBack = getAttemptState(key);
    assert.strictEqual(readBack.attempts, 1);
  });

  test('file mode is 0o600 on POSIX after first write', {
    skip: process.platform === 'win32' ? 'POSIX only' : false,
  }, () => {
    const key = makeKey(0x02);
    recordFailedAttempt(key);

    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');
    const files = fs.readdirSync(stateDir);
    assert.ok(files.length > 0, 'at least one state file should exist');

    for (const f of files) {
      const mode = statSync(join(stateDir, f)).mode & 0o777;
      assert.strictEqual(mode, 0o600, `state file must be 0o600, got 0o${mode.toString(8)}`);
    }
  });

  test('5th failure sets lockedUntil ≈ now + 300_000', () => {
    const key = makeKey(0x03);
    const before = Date.now();

    let state: AttemptState = { attempts: 0, firstFailureAt: 0, lockedUntil: null };
    for (let i = 0; i < 5; i++) {
      state = recordFailedAttempt(key);
    }

    const after = Date.now();
    assert.strictEqual(state.attempts, 5);
    assert.ok(state.lockedUntil !== null, 'lockedUntil must be set after 5 failures');
    assert.ok(state.lockedUntil! >= before + 300_000, 'lockedUntil must be at least now+300s');
    assert.ok(state.lockedUntil! <= after + 300_000 + 500, 'lockedUntil must not be far in future');
  });

  test('isLocked returns true for future lockedUntil', () => {
    const futureState: AttemptState = {
      attempts: 5,
      firstFailureAt: Date.now() - 1000,
      lockedUntil: Date.now() + 300_000,
    };
    assert.ok(isLocked(futureState));
  });

  test('isLocked returns false for past lockedUntil', () => {
    const expiredState: AttemptState = {
      attempts: 5,
      firstFailureAt: Date.now() - 400_000,
      lockedUntil: Date.now() - 1,
    };
    assert.ok(!isLocked(expiredState));
  });

  test('isLocked returns false when lockedUntil is null', () => {
    const state: AttemptState = { attempts: 2, firstFailureAt: Date.now(), lockedUntil: null };
    assert.ok(!isLocked(state));
  });

  test('resetAttempts deletes the counter file', () => {
    const key = makeKey(0x04);

    recordFailedAttempt(key);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');
    const filesBefore = fs.readdirSync(stateDir);
    assert.ok(filesBefore.length > 0, 'file must exist before reset');

    resetAttempts(key);

    const state = getAttemptState(key);
    assert.strictEqual(state.attempts, 0);
    assert.strictEqual(state.lockedUntil, null);
  });

  test('resetAttempts on non-existent file does not throw', () => {
    const key = makeKey(0x05);
    assert.doesNotThrow(() => resetAttempts(key));
  });

  test('lockout expiry: next failure resets counter to 1 (new window)', () => {
    const key = makeKey(0x06);

    // First attempt to create the file and discover its path
    recordFailedAttempt(key);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');
    const files = fs.readdirSync(stateDir);
    assert.ok(files.length === 1, 'exactly one file for this key');
    const filePath = join(stateDir, files[0]!);

    // Write an expired lockout state directly
    writeFileSync(filePath, JSON.stringify({
      attempts: 5,
      firstFailureAt: new Date(Date.now() - 400_000).toISOString(),
      lockedUntil: new Date(Date.now() - 1).toISOString(),
    }), { mode: 0o600 });

    // Next attempt: lockout expired → counter resets to 1
    const state = recordFailedAttempt(key);
    assert.strictEqual(state.attempts, 1, 'attempts must reset to 1 after lockout expiry');
    assert.strictEqual(state.lockedUntil, null, 'lockedUntil must be cleared after expiry');
  });

  test('corrupted JSON in state file treated as fresh state', () => {
    const key = makeKey(0x07);

    // Create one attempt to build directory and find path
    recordFailedAttempt(key);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');
    const files = fs.readdirSync(stateDir);
    const filePath = join(stateDir, files[0]!);
    writeFileSync(filePath, 'THIS IS NOT JSON {{{{', { mode: 0o600 });

    const state = getAttemptState(key);
    assert.strictEqual(state.attempts, 0);
    assert.strictEqual(state.lockedUntil, null);
  });

  test('mkdir -p is created on first write (no prior dir)', () => {
    const key = makeKey(0x08);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');

    assert.ok(!existsSync(stateDir), 'state dir must not exist before first write');

    recordFailedAttempt(key);

    assert.ok(existsSync(stateDir), 'state dir must be created after first write');
  });

  test('fingerprint is deterministic: same key → same file name', () => {
    const key = makeKey(0x09);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');

    recordFailedAttempt(key);
    const firstName = fs.readdirSync(stateDir)[0]!;

    resetAttempts(key);
    recordFailedAttempt(key);
    const secondName = fs.readdirSync(stateDir)[0]!;

    assert.strictEqual(firstName, secondName, 'same key must always produce same file name');
  });

  test('fingerprint is 32 lowercase hex chars', () => {
    const key = makeKey(0x0a);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');

    recordFailedAttempt(key);
    const name = fs.readdirSync(stateDir)[0]!;

    assert.ok(
      /^[0-9a-f]{32}$/.test(name),
      `fingerprint file name must be 32 lowercase hex chars, got: ${name}`,
    );
  });

  test('different master keys produce different file paths', () => {
    const key1 = makeKey(0x0b);
    const key2 = makeKey(0x0c);
    const stateDir = join(tmpHome, '.sealed-env-state', 'unseal-attempts');

    recordFailedAttempt(key1);
    recordFailedAttempt(key2);

    const files = fs.readdirSync(stateDir);
    assert.strictEqual(files.length, 2, 'two distinct files for two distinct keys');
    assert.notStrictEqual(files[0], files[1]);
  });

  test('increments correctly across multiple failures within window', () => {
    const key = makeKey(0x0d);

    for (let i = 1; i <= 4; i++) {
      const state = recordFailedAttempt(key);
      assert.strictEqual(state.attempts, i);
      assert.strictEqual(state.lockedUntil, null, `no lockout before 5th attempt (i=${i})`);
    }
  });
});
