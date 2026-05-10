/**
 * SEC-002 backward-compat regression: a 0.1.0-era sealed file with N=32768
 * must still decrypt correctly after the N bump to 131072.
 *
 * Strategy: seal with an explicit scryptParams override of N=32768, then
 * unseal. The parser reads stored params from the header (no silent override),
 * so this mirrors what a real 0.1.0-written file would look like.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { seal, unseal } from '../../src/core/api.js';
import { parseSealedFile } from '../../src/format/parser.js';

test('0.1.0 file sealed with N=32768 still decrypts after N bump to 131072', () => {
  const masterKey = randomBytes(32);
  const plaintext = 'LEGACY_KEY=old-value\nOTHER=123\n';

  // Seal with old params (override N to 32768 to simulate a 0.1.0 file)
  const { serialized } = seal({
    plaintext,
    masterKey,
    mode: 'basic',
    scryptParams: { N: 32768 },
  });

  // Verify the file actually contains N=32768
  assert.ok(
    /KDF-PARAMS=N=32768,r=8,p=1/.test(serialized),
    'fixture must have N=32768',
  );

  // Unseal: the parser reads stored N=32768 and uses it — no silent override
  const file = parseSealedFile(serialized);
  assert.strictEqual(file.kdfParams.kind, 'scrypt', 'parser identifies scrypt KDF');
  assert.ok(file.kdfParams.kind === 'scrypt');
  assert.strictEqual(file.kdfParams.params.N, 32768, 'parser preserves stored N');

  const decrypted = unseal({ file, masterKey });
  assert.strictEqual(decrypted.toString('utf8'), plaintext);
});

test('new seal does NOT produce N=32768 anymore', () => {
  const masterKey = randomBytes(32);
  const { serialized } = seal({ plaintext: 'X=1\n', masterKey, mode: 'basic' });
  assert.ok(
    !/KDF-PARAMS=N=32768/.test(serialized),
    'new seal must not use old N=32768',
  );
});
