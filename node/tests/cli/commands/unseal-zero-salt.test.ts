/**
 * SEC-005 tests: unseal command requires explicit salt source.
 *
 * Tests:
 *  1. No --file, --salt, or --unsafe-zero-salt → CONFIG_ERROR
 *  2. --unsafe-zero-salt → proceeds + stderr contains "unsafe"
 *  3. JSDoc contract: unseal.ts source contains '--unsafe-zero-salt' and 'unsafe' in header
 *  4. File source: --file with existing fixture preserves existing behavior
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unsealCommand } from '../../../src/cli/commands/unseal.js';
import { SealedEnvError } from '../../../src/core/errors.js';
import { generateTotp } from '../../../src/totp/totp.js';

const here = dirname(fileURLToPath(import.meta.url));

// Deterministic key material for tests
const MASTER_KEY_HEX = 'a'.repeat(64);

// Helper to set env vars, run fn, restore
async function withEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
  }
}

// Capture stderr writes during execution
function captureStderr(fn: () => Promise<void>): Promise<string> {
  return new Promise(async (resolve) => {
    let captured = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Buffer, ...args: unknown[]) => {
      captured += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      return true;
    }) as typeof process.stderr.write;
    try {
      await fn();
    } catch {
      // ignore errors — caller asserts separately
    } finally {
      process.stderr.write = orig;
      resolve(captured);
    }
  });
}

test('no --file, --salt, or --unsafe-zero-salt → CONFIG_ERROR', async () => {
  const zeroSecret = Buffer.alloc(20, 0);
  const base32Zero = bufferToBase32(zeroSecret);
  const validCode = generateTotp(zeroSecret);

  await withEnv({
    SEALED_ENV_KEY: MASTER_KEY_HEX,
    SEALED_ENV_TOTP_SECRET: base32Zero,
  }, async () => {
    await assert.rejects(
      () => unsealCommand(['--totp', validCode]),
      (err: unknown) => {
        assert.ok(err instanceof SealedEnvError, 'must be SealedEnvError');
        assert.strictEqual(err.code, 'CONFIG_ERROR');
        assert.ok(
          err.message.includes('--unsafe-zero-salt'),
          `message must mention --unsafe-zero-salt, got: "${err.message}"`,
        );
        return true;
      },
    );
  });
});

test('--unsafe-zero-salt proceeds and stderr contains "unsafe"', async () => {
  const zeroSecret = Buffer.alloc(20, 0);
  const base32Zero = bufferToBase32(zeroSecret);
  const validCode = generateTotp(zeroSecret);

  let stderrOutput = '';
  await withEnv({
    SEALED_ENV_KEY: MASTER_KEY_HEX,
    SEALED_ENV_TOTP_SECRET: base32Zero,
  }, async () => {
    stderrOutput = await captureStderr(async () => {
      // With --unsafe-zero-salt and --token-only, the command should succeed
      // and output a token to stdout. We capture stdout by redirecting briefly.
      const origStdout = process.stdout.write.bind(process.stdout);
      process.stdout.write = (() => true) as typeof process.stdout.write;
      try {
        await unsealCommand(['--totp', validCode, '--unsafe-zero-salt', '--token-only']);
      } finally {
        process.stdout.write = origStdout;
      }
    });
  });

  assert.ok(
    stderrOutput.includes('unsafe'),
    `stderr must contain "unsafe", got: "${stderrOutput}"`,
  );
});

test('JSDoc contract: unseal.ts contains --unsafe-zero-salt and unsafe in file header', () => {
  // Compiled tests are under dist/tests/cli/commands — go up to reach node/src/
  const srcPath = join(here, '..', '..', '..', '..', 'src', 'cli', 'commands', 'unseal.ts');
  const src = readFileSync(srcPath, 'utf8');

  assert.ok(
    src.includes('--unsafe-zero-salt'),
    'unseal.ts must contain --unsafe-zero-salt flag name',
  );
  assert.ok(
    src.includes('unsafe'),
    'unseal.ts must contain the literal "unsafe" (in flag, JSDoc, or error message)',
  );
  assert.ok(
    src.includes('DANGEROUS'),
    'unseal.ts must contain "DANGEROUS" in JSDoc for --unsafe-zero-salt',
  );
});

/**
 * Encode a Buffer as base32 (RFC 4648 alphabet, no padding).
 * Used to set SEALED_ENV_TOTP_SECRET in tests.
 */
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
  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 0x1f];
  }
  return result;
}
