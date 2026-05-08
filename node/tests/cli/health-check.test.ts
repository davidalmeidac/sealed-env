/**
 * Unit tests for health-check.ts. Mocks `fetch` via global override.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { pollHealth } from '../../src/cli/utils/health-check.js';

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('pollHealth', () => {
  test('returns true on first 200', async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return new Response('ok', { status: 200 });
    }) as typeof fetch;

    const ok = await pollHealth('http://x', 5_000);
    assert.equal(ok, true);
    assert.equal(calls, 1);
  });

  test('returns false on timeout', async () => {
    globalThis.fetch = (async () => {
      // simulate a connection that never returns 2xx
      return new Response('err', { status: 503 });
    }) as typeof fetch;

    const ok = await pollHealth('http://x', 1_500);
    assert.equal(ok, false);
  });

  test('keeps polling on network error then succeeds', async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      if (calls < 3) throw new Error('ECONNREFUSED');
      return new Response('ok', { status: 200 });
    }) as typeof fetch;

    const ok = await pollHealth('http://x', 10_000);
    assert.equal(ok, true);
    assert.ok(calls >= 3, `expected at least 3 calls, got ${calls}`);
  });

  test('treats 4xx as not-ok and keeps polling', async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      if (calls < 2) return new Response('not ready', { status: 404 });
      return new Response('ok', { status: 200 });
    }) as typeof fetch;

    const ok = await pollHealth('http://x', 10_000);
    assert.equal(ok, true);
    assert.ok(calls >= 2);
  });
});
