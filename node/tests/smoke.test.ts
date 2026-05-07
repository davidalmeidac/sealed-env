/**
 * Smoke tests — exercised by CI to catch obvious regressions.
 *
 * For v0.1.0-alpha we focus on roundtrip correctness in all modes plus
 * tamper-detection. Comprehensive cryptographic test vectors land in v0.1.0.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { seal, unseal } from '../src/index.js';
import { parseSealedFile } from '../src/format/parser.js';
import { buildUnsealToken } from '../src/totp/unsealToken.js';
import { deriveMasterKey } from '../src/core/crypto.js';
import { generateTotp, verifyTotp } from '../src/totp/totp.js';

describe('basic mode', () => {
  test('encrypt → decrypt roundtrip', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const plaintext = 'STRIPE_API_KEY=sk_test_12345\nDB_PASSWORD=hunter2\n';

    const { serialized } = seal({ plaintext, masterKey, mode: 'basic' });
    const file = parseSealedFile(serialized);
    const decrypted = unseal({ file, masterKey });

    assert.equal(decrypted.toString('utf8'), plaintext);
  });

  test('wrong master key fails to decrypt', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const wrongKey = Buffer.from('b'.repeat(64), 'hex');
    const { serialized } = seal({ plaintext: 'X=1\n', masterKey, mode: 'basic' });
    const file = parseSealedFile(serialized);

    assert.throws(() => unseal({ file, masterKey: wrongKey }), /corrupted, tampered, or wrong key/);
  });

  test('produces a valid V1 file', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const { serialized } = seal({ plaintext: 'A=1\n', masterKey, mode: 'basic' });
    assert.ok(serialized.startsWith('SEALED-ENV-V1 MODE=basic'), 'magic line correct');
    assert.ok(/\nKDF=scrypt\n/.test(serialized), 'KDF declared');
  });
});

describe('team mode', () => {
  test('encrypt → decrypt roundtrip', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const plaintext = 'API_KEY=team-secret\n';

    const { serialized } = seal({ plaintext, masterKey, signingKey, mode: 'team' });
    const file = parseSealedFile(serialized);

    assert.equal(file.mode, 'team');
    assert.ok(file.hmac, 'HMAC field present');

    const decrypted = unseal({ file, masterKey, signingKey });
    assert.equal(decrypted.toString('utf8'), plaintext);
  });

  test('tampered HMAC is rejected', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const { serialized } = seal({ plaintext: 'A=1\n', masterKey, signingKey, mode: 'team' });
    // Flip the first byte of the HMAC. Pick a replacement that is guaranteed
    // to differ from whatever was there (otherwise this test would be flaky
    // ~1/64 of the time when the original first char happened to match).
    const tampered = serialized.replace(/HMAC=([A-Za-z0-9+/=]+)/, (_, h) => {
      const first = h[0] === 'A' ? 'B' : 'A';
      return 'HMAC=' + first + h.substring(1);
    });
    const file = parseSealedFile(tampered);
    assert.throws(() => unseal({ file, masterKey, signingKey }), /corrupted, tampered/);
  });

  test('wrong signing key is rejected', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const wrongSigningKey = Buffer.from('c'.repeat(64), 'hex');
    const { serialized } = seal({ plaintext: 'A=1\n', masterKey, signingKey, mode: 'team' });
    const file = parseSealedFile(serialized);
    assert.throws(
      () => unseal({ file, masterKey, signingKey: wrongSigningKey }),
      /corrupted, tampered/,
    );
  });
});

describe('enterprise mode', () => {
  test('full flow: seal → build token → unseal', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const totpSecret = Buffer.from('c'.repeat(40), 'hex');

    const { serialized, file } = seal({
      plaintext: 'PROD=value\n',
      masterKey,
      signingKey,
      totpSecret,
      mode: 'enterprise',
    });
    assert.equal(file.mode, 'enterprise');
    assert.equal(file.challengeBind, 'enabled');
    assert.ok(file.epochCommit);

    const derivedKey = deriveMasterKey(masterKey, file.salt, file.kdfParams);
    const token = buildUnsealToken({
      derivedKey,
      totpSecret,
      salt: file.salt,
      deployId: 'sha-abc',
      ttlSeconds: 60,
    });

    const parsed = parseSealedFile(serialized);
    const decrypted = unseal({
      file: parsed,
      masterKey,
      signingKey,
      unsealToken: token,
      deployId: 'sha-abc',
    });
    assert.equal(decrypted.toString('utf8'), 'PROD=value\n');
  });

  test('wrong deploy_id is rejected with DEPLOY_MISMATCH', () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const totpSecret = Buffer.from('c'.repeat(40), 'hex');
    const { serialized, file } = seal({
      plaintext: 'P=v\n',
      masterKey,
      signingKey,
      totpSecret,
      mode: 'enterprise',
    });

    const derivedKey = deriveMasterKey(masterKey, file.salt, file.kdfParams);
    const token = buildUnsealToken({
      derivedKey,
      totpSecret,
      salt: file.salt,
      deployId: 'sha-abc',
      ttlSeconds: 60,
    });

    assert.throws(
      () =>
        unseal({
          file: parseSealedFile(serialized),
          masterKey,
          signingKey,
          unsealToken: token,
          deployId: 'WRONG',
        }),
      /different deploy/,
    );
  });

  test('expired token is rejected with TOKEN_EXPIRED', async () => {
    const masterKey = Buffer.from('a'.repeat(64), 'hex');
    const signingKey = Buffer.from('b'.repeat(64), 'hex');
    const totpSecret = Buffer.from('c'.repeat(40), 'hex');
    const { serialized, file } = seal({
      plaintext: 'X=1\n',
      masterKey,
      signingKey,
      totpSecret,
      mode: 'enterprise',
    });
    const derivedKey = deriveMasterKey(masterKey, file.salt, file.kdfParams);
    // 5-second token, sleep 6 seconds
    const token = buildUnsealToken({
      derivedKey,
      totpSecret,
      salt: file.salt,
      deployId: 'd',
      ttlSeconds: 5,
    });
    await new Promise((r) => setTimeout(r, 6000));
    assert.throws(
      () =>
        unseal({
          file: parseSealedFile(serialized),
          masterKey,
          signingKey,
          unsealToken: token,
          deployId: 'd',
        }),
      /expired/,
    );
  });
});

describe('TOTP', () => {
  test('verifyTotp accepts the current code', () => {
    const secret = Buffer.from('a'.repeat(20));
    const code = generateTotp(secret);
    assert.ok(verifyTotp(secret, code));
  });

  test('verifyTotp rejects a wrong code', () => {
    const secret = Buffer.from('a'.repeat(20));
    assert.equal(verifyTotp(secret, '000000'), false);
  });
});

describe('format parser', () => {
  test('rejects malformed magic line', () => {
    // Pad with extra lines so we hit the magic-line check, not the length check
    const bad = 'NOT-SEALED\nKDF=scrypt\nKDF-PARAMS=N=1024,r=8,p=1\nSALT=AA==\nNONCE=AA==\n';
    assert.throws(() => parseSealedFile(bad), /magic|invalid/i);
  });

  test('rejects unknown mode', () => {
    const bad =
      'SEALED-ENV-V1 MODE=hacker\nKDF=scrypt\nKDF-PARAMS=N=1024,r=8,p=1\nSALT=AA==\nNONCE=AA==\n';
    assert.throws(() => parseSealedFile(bad), /unknown mode|magic|invalid/i);
  });

  test('rejects too-short file', () => {
    assert.throws(() => parseSealedFile('SEALED-ENV-V1 MODE=basic\n'), /file too short/);
  });
});
