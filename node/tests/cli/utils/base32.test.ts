/**
 * Unit tests for the shared base32 decoder (cli/utils/base32.ts).
 *
 * TDD: these tests were written BEFORE the implementation file existed.
 * They drive the public contract:
 *   - valid base32 → correct Buffer
 *   - padding ('=') is accepted and stripped
 *   - invalid character → SealedEnvError with code CONFIG_ERROR
 *   - empty string → zero-length Buffer (no throw)
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { decodeBase32 } from '../../../src/cli/utils/base32.js';
import { SealedEnvError } from '../../../src/core/errors.js';

describe('decodeBase32', () => {
  test('(a) valid base32 "JBSWY3DP" decodes to correct 5 bytes', () => {
    // JBSWY3DP is the base32 encoding of "Hello"
    const result = decodeBase32('JBSWY3DP');
    assert.ok(result instanceof Buffer);
    assert.equal(result.length, 5);
    assert.equal(result.toString('utf8'), 'Hello');
  });

  test('(b) base32 with "=" padding is stripped and decoded correctly', () => {
    // 'ME======' decodes to a single byte 0x61 ('a')
    const result = decodeBase32('ME======');
    assert.ok(result instanceof Buffer);
    assert.equal(result.length, 1);
    assert.equal(result[0], 0x61);
  });

  test('(c) invalid char "!" throws SealedEnvError with code CONFIG_ERROR', () => {
    assert.throws(
      () => decodeBase32('JBSWY3DP!'),
      (err: unknown) => {
        assert.ok(err instanceof SealedEnvError);
        assert.equal(err.code, 'CONFIG_ERROR');
        return true;
      },
    );
  });

  test('(d) empty string returns zero-length Buffer without throwing', () => {
    const result = decodeBase32('');
    assert.ok(result instanceof Buffer);
    assert.equal(result.length, 0);
  });

  test('error message includes the bad char and var name when provided', () => {
    assert.throws(
      () => decodeBase32('JBSWY3DP!', 'MY_SECRET'),
      (err: unknown) => {
        assert.ok(err instanceof SealedEnvError);
        assert.ok(err.message.includes('!'), `expected "!" in: ${err.message}`);
        assert.ok(err.message.includes('MY_SECRET'), `expected "MY_SECRET" in: ${err.message}`);
        return true;
      },
    );
  });

  test('lowercase input is uppercased and decoded correctly', () => {
    // Same as 'JBSWY3DP' but lowercase
    const result = decodeBase32('jbswy3dp');
    assert.equal(result.toString('utf8'), 'Hello');
  });
});
