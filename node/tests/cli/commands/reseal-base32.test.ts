/**
 * Regression tests for the base32 TOTP decoding bug in resealLikeSource.
 *
 * BUG (fixed): io.ts:resealLikeSource was reading SEALED_ENV_TOTP_SECRET via
 * readKeyFromEnv() (hex/base64 decoding) instead of readEnvKeyBase32()
 * (base32 decoding). Enterprise re-seal operations (rotate, set, edit, diff)
 * produced a file with wrong key material, causing unseal failures.
 *
 * These tests use the API layer directly (seal/unseal + resealLikeSource) to
 * verify the round-trip without spawning CLI subprocesses.
 *
 * TDD note: T1.4 (the fix) was applied before these tests were added;
 * the tests document the correct behaviour and serve as regression guards.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { seal, unseal } from '../../../src/index.js';
import { parseSealedFile } from '../../../src/format/parser.js';
import { buildUnsealToken } from '../../../src/totp/unsealToken.js';
import { deriveMasterKey, randomBytes } from '../../../src/core/crypto.js';
import { resealLikeSource, readEnvKeyBase32 } from '../../../src/cli/utils/io.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Encode a Buffer as a base32 string — mirrors the algorithm in init.ts.
 * Used to produce an `init`-style TOTP secret for tests.
 */
function toBase32(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | (buf[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

/** Mint an unseal token using the raw TOTP secret and file metadata. */
function mintToken(
  masterKey: Buffer,
  totpSecretRaw: Buffer,
  file: ReturnType<typeof parseSealedFile>,
): string {
  const derivedKey = deriveMasterKey(masterKey, file.salt, file.kdfParams);
  return buildUnsealToken({
    derivedKey,
    totpSecret: totpSecretRaw,
    salt: file.salt,
    deployId: 'test-deploy',
    ttlSeconds: 120,
  });
}

// ---------------------------------------------------------------------------
// Shared fixtures (generated once per test file, not per test)
// ---------------------------------------------------------------------------

interface Fixtures {
  masterKey: Buffer;
  signingKey: Buffer;
  totpSecretRaw: Buffer;
  totpSecretBase32: string;
  plaintext: string;
  serialized: string;
  file: ReturnType<typeof parseSealedFile>;
  token: string;
}

let fx: Fixtures;
const savedEnv: Record<string, string | undefined> = {};

before(() => {
  const masterKey = randomBytes(32);
  const signingKey = randomBytes(32);
  const totpSecretRaw = randomBytes(20);
  const totpSecretBase32 = toBase32(totpSecretRaw);

  const plaintext = 'API_KEY=test-secret\nDB_URL=postgres://localhost/test\n';

  const { serialized, file } = seal({
    plaintext,
    masterKey,
    signingKey,
    totpSecret: totpSecretRaw,
    mode: 'enterprise',
  });

  const token = mintToken(masterKey, totpSecretRaw, file);

  fx = {
    masterKey,
    signingKey,
    totpSecretRaw,
    totpSecretBase32,
    plaintext,
    serialized,
    file,
    token,
  };

  // Set env vars that resealLikeSource reads
  savedEnv['SEALED_ENV_KEY'] = process.env['SEALED_ENV_KEY'];
  savedEnv['SEALED_ENV_SIGNING_KEY'] = process.env['SEALED_ENV_SIGNING_KEY'];
  savedEnv['SEALED_ENV_TOTP_SECRET'] = process.env['SEALED_ENV_TOTP_SECRET'];

  process.env['SEALED_ENV_KEY'] = masterKey.toString('hex');
  process.env['SEALED_ENV_SIGNING_KEY'] = signingKey.toString('hex');
  process.env['SEALED_ENV_TOTP_SECRET'] = totpSecretBase32;
});

after(() => {
  // Restore env vars
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('resealLikeSource with base32 TOTP secret (regression — CVE-adjacent bug fix)', () => {
  test('rotate round-trip: resealLikeSource produces a file that unseals correctly', () => {
    // This is the primary regression test. The bug caused resealLikeSource to
    // decode the base32 TOTP secret as hex/base64, yielding wrong key material.
    const resealed = resealLikeSource(fx.file, fx.plaintext);
    const resealedFile = parseSealedFile(resealed);

    // Fresh token against the new salt
    const newToken = mintToken(fx.masterKey, fx.totpSecretRaw, resealedFile);

    const decrypted = unseal({
      file: resealedFile,
      masterKey: fx.masterKey,
      signingKey: fx.signingKey,
      unsealToken: newToken,
      deployId: 'test-deploy',
    });

    assert.equal(decrypted.toString('utf8'), fx.plaintext);
  });

  test('set round-trip: resealLikeSource after value mutation produces unseallable file', () => {
    // Simulate what setCommand does: change a key, reseal.
    const newPlaintext = 'API_KEY=updated-value\nDB_URL=postgres://localhost/test\n';
    const resealed = resealLikeSource(fx.file, newPlaintext);
    const resealedFile = parseSealedFile(resealed);

    const newToken = mintToken(fx.masterKey, fx.totpSecretRaw, resealedFile);

    const decrypted = unseal({
      file: resealedFile,
      masterKey: fx.masterKey,
      signingKey: fx.signingKey,
      unsealToken: newToken,
      deployId: 'test-deploy',
    });

    assert.equal(decrypted.toString('utf8'), newPlaintext);
  });

  test('edit smoke: resealLikeSource with editor-modified plaintext unseals correctly', () => {
    const editedPlaintext = fx.plaintext + 'NEW_VAR=added-by-edit\n';
    const resealed = resealLikeSource(fx.file, editedPlaintext);
    const resealedFile = parseSealedFile(resealed);

    const newToken = mintToken(fx.masterKey, fx.totpSecretRaw, resealedFile);
    const decrypted = unseal({
      file: resealedFile,
      masterKey: fx.masterKey,
      signingKey: fx.signingKey,
      unsealToken: newToken,
      deployId: 'test-deploy',
    });

    assert.equal(decrypted.toString('utf8'), editedPlaintext);
  });

  test('diff smoke: both files from resealLikeSource unseal to matching plaintexts', () => {
    // diff decrypts two files — both should be unseallable
    const newPlaintext = 'API_KEY=diffed-value\nDB_URL=postgres://localhost/test\n';
    const resealedNew = resealLikeSource(fx.file, newPlaintext);
    const resealedNewFile = parseSealedFile(resealedNew);

    const tokenForNew = mintToken(fx.masterKey, fx.totpSecretRaw, resealedNewFile);
    const decryptedOld = unseal({
      file: fx.file,
      masterKey: fx.masterKey,
      signingKey: fx.signingKey,
      unsealToken: fx.token,
      deployId: 'test-deploy',
    });
    const decryptedNew = unseal({
      file: resealedNewFile,
      masterKey: fx.masterKey,
      signingKey: fx.signingKey,
      unsealToken: tokenForNew,
      deployId: 'test-deploy',
    });

    assert.equal(decryptedOld.toString('utf8'), fx.plaintext);
    assert.equal(decryptedNew.toString('utf8'), newPlaintext);
  });

  test('readEnvKeyBase32 decodes the base32 TOTP secret to the correct raw bytes', () => {
    // Verify the env-var helper returns the same bytes as the raw secret.
    const decoded = readEnvKeyBase32('SEALED_ENV_TOTP_SECRET');
    assert.deepEqual(decoded, fx.totpSecretRaw);
  });

  test('invalid base32 SEALED_ENV_TOTP_SECRET throws CONFIG_ERROR (not DECRYPT_FAILED)', () => {
    const orig = process.env['SEALED_ENV_TOTP_SECRET'];
    process.env['SEALED_ENV_TOTP_SECRET'] = 'NOT!VALID!BASE32';
    try {
      assert.throws(
        () => resealLikeSource(fx.file, fx.plaintext),
        (err: unknown) => {
          // Must not be DECRYPT_FAILED — must be CONFIG_ERROR
          assert.ok(
            err instanceof Error && 'code' in err,
            'Expected SealedEnvError',
          );
          const code = (err as { code: string }).code;
          assert.notEqual(code, 'DECRYPT_FAILED', 'CONFIG errors must not be DECRYPT_FAILED');
          assert.equal(code, 'CONFIG_ERROR');
          return true;
        },
      );
    } finally {
      process.env['SEALED_ENV_TOTP_SECRET'] = orig;
    }
  });
});
