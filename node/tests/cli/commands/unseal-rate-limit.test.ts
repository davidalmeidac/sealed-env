/**
 * Integration tests for TOTP rate limiting on `sealed-env unseal` (SEC-009, B-1..B-10).
 *
 * TDD: tests written first (RED), then unseal.ts wired (GREEN).
 *
 * Scenarios:
 *  1. 5 wrong codes → counter increments each time; 5th sets lockout
 *  2. 6th attempt → rejected without TOTP verify call (spy assert)
 *  3. Successful unseal resets counter (file deleted)
 *  4. Lockout expiry restores normal flow (pre-write expired lockout state)
 *  5. Master key fingerprint nonleakage (no 32-char hex in stderr/stdout)
 *  6. loadSealed() direct invocation (non-CLI) does NOT trigger rate limit
 *
 * Isolation: HOME / USERPROFILE → temp dir; env vars restored after each test.
 */

import { test, describe, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs, { mkdtempSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir as osTmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { unsealCommand } from '../../../src/cli/commands/unseal.js';
import { SealedEnvError } from '../../../src/core/errors.js';
import { generateTotp } from '../../../src/totp/totp.js';

/** RFC 4648 base32 (no padding) encode. */
function bufferToBase32(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 0x1f];
  return result;
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// A 32-byte master key used across tests.
const MASTER_KEY_HEX = 'b'.repeat(64);
const MASTER_KEY_BUF = Buffer.from(MASTER_KEY_HEX, 'hex');

// TOTP secret: 20 zero bytes.
const TOTP_SECRET = Buffer.alloc(20, 0);
const TOTP_SECRET_B32 = bufferToBase32(TOTP_SECRET);

/** Generate the current valid TOTP code for our fixture secret. */
function validCode(): string {
  return generateTotp(TOTP_SECRET);
}

/**
 * Generate a 6-digit code that is guaranteed wrong: we take the valid code and
 * add 500_000, wrapping modulo 1_000_000. This always differs from all 3 TOTP
 * windows (current ± 1 step) by at least 499_999.
 */
function wrongCode(): string {
  const valid = parseInt(generateTotp(TOTP_SECRET), 10);
  const wrong = (valid + 500_000) % 1_000_000;
  return wrong.toString().padStart(6, '0');
}

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

let tmpHome: string;
let savedHome: string | undefined;
let savedUserProfile: string | undefined;
let savedStderrWrite: typeof process.stderr.write;
let savedStdoutWrite: typeof process.stdout.write;
let capturedOutput: string;

function captureOutput(): void {
  capturedOutput = '';
  savedStderrWrite = process.stderr.write.bind(process.stderr);
  savedStdoutWrite = process.stdout.write.bind(process.stdout);
  process.stderr.write = ((chunk: string | Buffer, ...args: unknown[]) => {
    capturedOutput += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    return true;
  }) as typeof process.stderr.write;
  process.stdout.write = ((chunk: string | Buffer, ...args: unknown[]) => {
    capturedOutput += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    return true;
  }) as typeof process.stdout.write;
}

function restoreOutput(): void {
  process.stderr.write = savedStderrWrite;
  process.stdout.write = savedStdoutWrite;
}

async function withEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/** Base env vars required by unsealCommand. */
function baseEnv(): Record<string, string> {
  return {
    SEALED_ENV_KEY: MASTER_KEY_HEX,
    SEALED_ENV_TOTP_SECRET: TOTP_SECRET_B32,
  };
}

/** Run unsealCommand with the given TOTP code (and --unsafe-zero-salt to avoid --file). */
async function runUnseal(code: string): Promise<void> {
  await unsealCommand(['--totp', code, '--unsafe-zero-salt', '--token-only']);
}

// ---------------------------------------------------------------------------
// State dir helpers
// ---------------------------------------------------------------------------

function stateDir(): string {
  return join(tmpHome, '.sealed-env-state', 'unseal-attempts');
}

function listStateFiles(): string[] {
  if (!existsSync(stateDir())) return [];
  return fs.readdirSync(stateDir());
}

/** Write an expired lockout file for the current master key. */
function writeExpiredLockout(): void {
  const fp = createHash('sha256').update(MASTER_KEY_BUF).digest().subarray(0, 16).toString('hex');
  const dir = stateDir();
  fs.mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, fp), JSON.stringify({
    attempts: 5,
    firstFailureAt: new Date(Date.now() - 400_000).toISOString(),
    lockedUntil: new Date(Date.now() - 1).toISOString(),
  }), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('unseal rate limit integration', () => {
  beforeEach(() => {
    tmpHome = mkdtempSync(join(osTmpdir(), 'unseal-rl-home-'));
    savedHome = process.env['HOME'];
    savedUserProfile = process.env['USERPROFILE'];
    process.env['HOME'] = tmpHome;
    process.env['USERPROFILE'] = tmpHome;
  });

  afterEach(() => {
    mock.restoreAll();
    if (savedHome === undefined) delete process.env['HOME'];
    else process.env['HOME'] = savedHome;
    if (savedUserProfile === undefined) delete process.env['USERPROFILE'];
    else process.env['USERPROFILE'] = savedUserProfile;
    rmSync(tmpHome, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // Scenario 1: 5 wrong codes → counter increments; 5th sets lockout
  // -------------------------------------------------------------------------
  test('5 wrong codes: counter increments each time and 5th sets lockout', async () => {
    await withEnv(baseEnv(), async () => {
      for (let i = 1; i <= 4; i++) {
        const err = await runUnseal(wrongCode()).catch(e => e);
        assert.ok(err instanceof SealedEnvError, `attempt ${i} must throw SealedEnvError`);
        assert.strictEqual(err.code, 'TOKEN_INVALID', `attempt ${i} must be TOKEN_INVALID`);
        assert.ok(
          !err.message.includes('Locked until'),
          `attempt ${i} must not produce lockout message`,
        );
      }

      // 5th wrong code → TOKEN_INVALID but lockout is now set in the file
      const err5 = await runUnseal(wrongCode()).catch(e => e);
      assert.ok(err5 instanceof SealedEnvError);
      assert.strictEqual(err5.code, 'TOKEN_INVALID');

      // Verify lockout was persisted: next read will see it
      const files = listStateFiles();
      assert.ok(files.length > 0, 'state file must exist after 5 failures');
      const content = fs.readFileSync(join(stateDir(), files[0]!), 'utf8');
      const parsed = JSON.parse(content) as { attempts: number; lockedUntil: string | null };
      assert.strictEqual(parsed.attempts, 5);
      assert.ok(parsed.lockedUntil !== null, 'lockedUntil must be set in file');
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 2: 6th attempt during lockout → rejected before TOTP verify
  // -------------------------------------------------------------------------
  test('6th attempt: rejected with CONFIG_ERROR; correct code also rejected (no TOTP eval)', async () => {
    await withEnv(baseEnv(), async () => {
      // Trigger 5 failures to set lockout
      for (let i = 0; i < 5; i++) {
        await runUnseal(wrongCode()).catch(() => { /* expected */ });
      }

      // Verify lockout is set in the file before the 6th attempt
      const stateFiles = listStateFiles();
      assert.ok(stateFiles.length > 0, 'state file must exist after 5 failures');
      const stateContent = JSON.parse(
        fs.readFileSync(join(stateDir(), stateFiles[0]!), 'utf8'),
      ) as { lockedUntil: string | null };
      assert.ok(stateContent.lockedUntil !== null, 'lockedUntil must be set before 6th attempt');

      // 6th attempt with CORRECT TOTP code — should still be rejected (pre-check fires first)
      // This proves the code is NOT evaluated: if it were, a correct code would succeed.
      const err = await runUnseal(validCode()).catch(e => e);

      assert.ok(err instanceof SealedEnvError, 'must throw SealedEnvError when locked');
      assert.strictEqual(err.code, 'CONFIG_ERROR', 'locked state must produce CONFIG_ERROR');
      assert.ok(
        err.message.includes('Too many failed unseal attempts'),
        `message must contain "Too many failed unseal attempts", got: "${err.message}"`,
      );
      assert.ok(
        err.message.includes('Locked until'),
        `message must contain "Locked until", got: "${err.message}"`,
      );
      assert.ok(
        err.message.includes('sealed-env init --mode enterprise'),
        `message must contain rotation hint, got: "${err.message}"`,
      );

      // Assert the counter file is NOT updated by the 6th attempt
      // (if verifyTotp had been called, the wrong-code path would have incremented the counter).
      // Since we used a valid code and still got CONFIG_ERROR, TOTP was never evaluated.
      const stateAfter = JSON.parse(
        fs.readFileSync(join(stateDir(), stateFiles[0]!), 'utf8'),
      ) as { attempts: number };
      assert.strictEqual(stateAfter.attempts, 5, 'attempts must remain 5 (no additional increment)');
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 3: Successful unseal resets counter
  // -------------------------------------------------------------------------
  test('successful unseal resets counter (state file deleted)', async () => {
    await withEnv(baseEnv(), async () => {
      // Record 2 failures
      await runUnseal(wrongCode()).catch(() => { /* expected */ });
      await runUnseal(wrongCode()).catch(() => { /* expected */ });

      const filesAfterFailures = listStateFiles();
      assert.ok(filesAfterFailures.length > 0, 'state file must exist after failures');

      // Now succeed
      captureOutput();
      try {
        await runUnseal(validCode());
      } finally {
        restoreOutput();
      }

      // State file must be gone (or counter reset to 0)
      const state = listStateFiles();
      // Either the file is deleted OR it's empty/reset — both OK.
      // The design says "delete the file" (resetAttempts uses rmSync).
      assert.strictEqual(state.length, 0, 'state file must be deleted after successful unseal');
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 4: Lockout expiry restores normal flow
  // -------------------------------------------------------------------------
  test('lockout expiry: correct code succeeds after lockout expires', async () => {
    await withEnv(baseEnv(), async () => {
      // Write an already-expired lockout state
      writeExpiredLockout();

      // Command should succeed with a valid code
      captureOutput();
      let error: unknown = null;
      try {
        await runUnseal(validCode());
      } catch (e) {
        error = e;
      } finally {
        restoreOutput();
      }

      assert.strictEqual(error, null, `should succeed after lockout expiry, got: ${error}`);
    });
  });

  test('lockout expiry: wrong code after lockout → new window with attempts=1', async () => {
    await withEnv(baseEnv(), async () => {
      writeExpiredLockout();

      const err = await runUnseal(wrongCode()).catch(e => e);
      assert.ok(err instanceof SealedEnvError);
      // After expiry + wrong code: TOKEN_INVALID (not CONFIG_ERROR lockout)
      assert.strictEqual(err.code, 'TOKEN_INVALID');
      assert.ok(!err.message.includes('Locked until'), 'must not be locked on fresh window');

      // File should show attempts=1
      const files = listStateFiles();
      assert.ok(files.length > 0);
      const parsed = JSON.parse(
        fs.readFileSync(join(stateDir(), files[0]!), 'utf8'),
      ) as { attempts: number; lockedUntil: string | null };
      assert.strictEqual(parsed.attempts, 1);
      assert.strictEqual(parsed.lockedUntil, null);
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 5: Master key fingerprint nonleakage
  // -------------------------------------------------------------------------
  test('master key fingerprint never appears in stderr or stdout during lockout cycle', async () => {
    await withEnv(baseEnv(), async () => {
      // Compute expected fingerprint pattern
      const fp = createHash('sha256').update(MASTER_KEY_BUF).digest().subarray(0, 16).toString('hex');

      captureOutput();
      try {
        // Trigger 5 failures + 1 lockout attempt
        for (let i = 0; i < 5; i++) {
          await runUnseal(wrongCode()).catch(() => { /* expected */ });
        }
        // 6th attempt while locked
        await runUnseal(validCode()).catch(() => { /* expected */ });
      } finally {
        restoreOutput();
      }

      assert.ok(
        !capturedOutput.includes(fp),
        `fingerprint (${fp}) must not appear in any stdout/stderr output`,
      );

      // Also assert no 32-char lowercase hex substring appears (broader check)
      const hexPattern = /[0-9a-f]{32}/;
      // We ALLOW the fingerprint in the file system but NOT in logs.
      // The captured output should not contain any 32-char hex run.
      const match = hexPattern.exec(capturedOutput);
      assert.ok(
        match === null,
        `no 32-char hex substring should appear in output, found: "${match?.[0]}"`,
      );
    });
  });

  // -------------------------------------------------------------------------
  // Scenario 6: loadSealed() does NOT trigger rate limit (B-10)
  // -------------------------------------------------------------------------
  test('loadSealed() direct call does not create rate-limit state files', async () => {
    // loadSealed is the library API — it should never touch ~/.sealed-env-state/.
    // Assertion: after a failed loadSealed() call, no rate-limit state files exist.
    const { loadSealed } = await import('../../../src/core/api.js');

    await withEnv({
      HOME: tmpHome,
      USERPROFILE: tmpHome,
      SEALED_ENV_KEY: MASTER_KEY_HEX,
    }, async () => {
      // Call with a non-existent file path — will throw CONFIG_ERROR / PARSE_ERROR,
      // but must NOT create any rate-limit state files.
      try {
        loadSealed({ path: 'non-existent-file-that-does-not-exist.env.sealed', populate: false });
      } catch {
        // Expected — the file doesn't exist; we only care about state file side-effects.
      }

      const files = listStateFiles();
      assert.strictEqual(
        files.length,
        0,
        'loadSealed() must not create rate-limit state files',
      );
    });
  });
});
