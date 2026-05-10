/**
 * SEC-007 tests: verifyUnsealToken must reject tokens whose payload.epoch
 * contains characters outside standard base64 ([A-Za-z0-9+/=]).
 *
 * Strategy: build a valid token, then re-sign it with a tampered epoch so
 * the signature check passes — only the epoch decode should fail.
 * This proves the validation gate runs AFTER signature check (correct) but
 * BEFORE Buffer.from decode.
 *
 * Tests:
 *  1. Token with tab injected into epoch → TOKEN_INVALID
 *  2. Token with newline in epoch → TOKEN_INVALID
 *  3. Token with non-base64 char (!) in epoch → TOKEN_INVALID
 *  4. Valid token still verifies (regression guard)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { buildUnsealToken, verifyUnsealToken } from '../../src/totp/unsealToken.js';
import { SealedEnvError } from '../../src/core/errors.js';
import { deriveMasterKey } from '../../src/core/crypto.js';
import { seal } from '../../src/core/api.js';
import { parseSealedFile } from '../../src/format/parser.js';

// Deterministic key material
const MASTER_KEY = Buffer.from('a'.repeat(64), 'hex');
const SIGNING_KEY = Buffer.from('b'.repeat(64), 'hex');
const TOTP_SECRET = Buffer.from('c'.repeat(40), 'hex');

function buildTestToken(): { token: string; derivedKey: Buffer } {
  const { serialized, file: sealedMeta } = seal({
    plaintext: 'X=1\n',
    masterKey: MASTER_KEY,
    signingKey: SIGNING_KEY,
    totpSecret: TOTP_SECRET,
    mode: 'enterprise',
  });
  void sealedMeta;
  const file = parseSealedFile(serialized);
  const derivedKey = deriveMasterKey(MASTER_KEY, file.salt, file.kdfParams);
  const token = buildUnsealToken({
    derivedKey,
    totpSecret: TOTP_SECRET,
    salt: file.salt,
    deployId: null,
    ttlSeconds: 60,
  });
  return { token, derivedKey };
}

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(s: string): Buffer {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Build a token identical to validToken except payload.epoch has injectedPrefix
 * prepended. Re-signs with derivedKey so the signature check passes.
 * Only the epoch validation gate should cause rejection.
 */
function buildTamperedToken(derivedKey: Buffer, validToken: string, injectedPrefix: string): string {
  const stripped = validToken.substring('usl_'.length);
  const [hB64, pB64] = stripped.split('.') as [string, string];

  const payload = JSON.parse(base64UrlDecode(pB64).toString('utf8')) as {
    epoch: string;
    [k: string]: unknown;
  };
  payload.epoch = injectedPrefix + payload.epoch;

  const newPayloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = Buffer.from(`${hB64}.${newPayloadB64}`, 'utf8');
  const sig = createHmac('sha256', derivedKey).update(signingInput).digest();

  return `usl_${hB64}.${newPayloadB64}.${base64UrlEncode(sig)}`;
}

test('token with tab in epoch → TOKEN_INVALID', () => {
  const { token, derivedKey } = buildTestToken();
  const tampered = buildTamperedToken(derivedKey, token, '\t');

  assert.throws(
    () => verifyUnsealToken({
      token: tampered,
      derivedKey,
      expectedDeployId: null,
      challengeBindEnabled: false,
    }),
    (err: unknown) => {
      assert.ok(err instanceof SealedEnvError, 'must be SealedEnvError');
      assert.strictEqual(err.code, 'TOKEN_INVALID');
      return true;
    },
  );
});

test('token with newline in epoch → TOKEN_INVALID', () => {
  const { token, derivedKey } = buildTestToken();
  const tampered = buildTamperedToken(derivedKey, token, '\n');

  assert.throws(
    () => verifyUnsealToken({
      token: tampered,
      derivedKey,
      expectedDeployId: null,
      challengeBindEnabled: false,
    }),
    (err: unknown) => {
      assert.ok(err instanceof SealedEnvError);
      assert.strictEqual(err.code, 'TOKEN_INVALID');
      return true;
    },
  );
});

test('token with non-base64 char (!) in epoch → TOKEN_INVALID', () => {
  const { token, derivedKey } = buildTestToken();
  const tampered = buildTamperedToken(derivedKey, token, '!');

  assert.throws(
    () => verifyUnsealToken({
      token: tampered,
      derivedKey,
      expectedDeployId: null,
      challengeBindEnabled: false,
    }),
    (err: unknown) => {
      assert.ok(err instanceof SealedEnvError);
      assert.strictEqual(err.code, 'TOKEN_INVALID');
      return true;
    },
  );
});

test('valid token still verifies (regression)', () => {
  const { token, derivedKey } = buildTestToken();

  const result = verifyUnsealToken({
    token,
    derivedKey,
    expectedDeployId: null,
    challengeBindEnabled: false,
  });

  assert.ok(result.enterpriseEpoch instanceof Buffer);
  assert.strictEqual(result.enterpriseEpoch.length, 32);
  assert.ok(typeof result.opsId === 'string' && result.opsId.length > 0);
});
