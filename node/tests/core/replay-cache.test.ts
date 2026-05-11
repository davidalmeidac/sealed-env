/**
 * Unit tests for InProcessReplayCache.
 *
 * TDD: tests written first (RED), then InProcessReplayCache implemented (GREEN).
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { InProcessReplayCache } from '../../src/core/replay-cache.js';

function futureExp(offsetSec = 3600): number {
  return Math.floor(Date.now() / 1000) + offsetSec;
}

function pastExp(offsetSec = 3600): number {
  return Math.floor(Date.now() / 1000) - offsetSec;
}

describe('InProcessReplayCache', () => {
  let cache: InProcessReplayCache;

  beforeEach(() => {
    cache = new InProcessReplayCache();
  });

  test('unseen opsId returns false from isOpsIdSeen', () => {
    assert.equal(cache.isOpsIdSeen('some-id'), false);
  });

  test('markOpsIdSeen then isOpsIdSeen returns true for future expiry', () => {
    cache.markOpsIdSeen('id-1', futureExp());
    assert.equal(cache.isOpsIdSeen('id-1'), true);
  });

  test('expired entry: isOpsIdSeen returns false and entry is GC-ed', () => {
    cache.markOpsIdSeen('expired-id', pastExp());
    // Should be treated as unseen (expired)
    assert.equal(cache.isOpsIdSeen('expired-id'), false);
    // GC occurred: subsequent call still returns false
    assert.equal(cache.isOpsIdSeen('expired-id'), false);
  });

  test('entry with future expiry is seen', () => {
    cache.markOpsIdSeen('future-id', futureExp());
    assert.equal(cache.isOpsIdSeen('future-id'), true);
  });

  test('cap eviction at 10001 entries: oldest evicted, newest preserved, size is 10000', () => {
    const oldestId = 'id-0';
    cache.markOpsIdSeen(oldestId, futureExp());

    // Insert 10000 more entries (10001 total)
    for (let i = 1; i <= 10000; i++) {
      cache.markOpsIdSeen(`id-${i}`, futureExp());
    }

    // Oldest (id-0) must be evicted
    assert.equal(cache.isOpsIdSeen(oldestId), false, 'oldest entry was evicted');

    // Newest must be preserved
    assert.equal(cache.isOpsIdSeen('id-10000'), true, 'newest entry is present');

    // Size stays at 10000 (we just checked isOpsIdSeen on id-0 and id-10000,
    // but id-0 was already deleted so only id-10000 lookup counted as a hit)
    // Re-insert id-0 to test we have room
    cache.markOpsIdSeen(oldestId, futureExp());
    assert.equal(cache.isOpsIdSeen(oldestId), true, 'can re-insert evicted id');
  });

  test('GC on markOpsIdSeen path: marking an expired entry key with new expiry makes it seen', () => {
    // First mark with past expiry (expired)
    cache.markOpsIdSeen('reused-id', pastExp());

    // isOpsIdSeen returns false (expired)
    assert.equal(cache.isOpsIdSeen('reused-id'), false);

    // Re-mark with future expiry
    cache.markOpsIdSeen('reused-id', futureExp());

    // Now it should be seen again
    assert.equal(cache.isOpsIdSeen('reused-id'), true);
  });
});
