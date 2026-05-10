/**
 * Tests for SEC-002: DEFAULT_SCRYPT_PARAMS.N must be at the OWASP 2024 floor.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { DEFAULT_SCRYPT_PARAMS } from '../../src/format/constants.js';
import { seal } from '../../src/core/api.js';

test('DEFAULT_SCRYPT_PARAMS.N is 131072 (OWASP 2024 floor)', () => {
  assert.strictEqual(DEFAULT_SCRYPT_PARAMS.N, 131072);
});

test('DEFAULT_SCRYPT_PARAMS.r and .p unchanged', () => {
  assert.strictEqual(DEFAULT_SCRYPT_PARAMS.r, 8);
  assert.strictEqual(DEFAULT_SCRYPT_PARAMS.p, 1);
});

test('new seal() writes N=131072 in KDF-PARAMS header', () => {
  const masterKey = randomBytes(32);
  const { serialized } = seal({ plaintext: 'X=1\n', masterKey, mode: 'basic' });
  const kdfLine = serialized.split('\n').find(l => l.startsWith('KDF-PARAMS'));
  assert.ok(
    /^KDF-PARAMS=N=131072,r=8,p=1$/.test(kdfLine ?? ''),
    `expected KDF-PARAMS=N=131072,r=8,p=1, got: "${kdfLine}"`,
  );
});
