/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Default bounded in-process replay cache.
 *
 * <p>Thread-safe: reads and writes are lock-free via {@link ConcurrentHashMap};
 * only the rare soft-cap eviction path acquires the instance monitor.
 *
 * <p>Eviction races are tolerated: two threads may both observe
 * {@code size > SOFT_CAP} and both call {@code evictOldest()}. Because
 * {@code evictOldest} is {@code synchronized} and {@link ConcurrentLinkedDeque#pollFirst()}
 * returns {@code null} when the deque is empty, over-cap by a small margin is
 * acceptable but the cache will never under-evict on the happy path.
 *
 * <p>GC policy: expired entries are removed lazily on each call to
 * {@link #markOpsIdSeen}. No background timer is used to avoid untracked
 * thread handles.
 *
 * <p><b>Not exported from the public package surface.</b> Only the
 * {@link ReplayCache} interface is part of the public API.
 */
public final class InProcessReplayCache implements ReplayCache {

    static final int SOFT_CAP = 10_000;

    /** opsId → expiresAtEpochMillis */
    private final ConcurrentHashMap<String, Long> entries = new ConcurrentHashMap<>();

    /**
     * Tracks insertion order for FIFO eviction. May contain stale keys whose
     * entries were removed by GC; {@code evictOldest} tolerates this.
     */
    private final ConcurrentLinkedDeque<String> insertionOrder = new ConcurrentLinkedDeque<>();

    @Override
    public boolean isOpsIdSeen(String opsId) {
        Long exp = entries.get(opsId);
        if (exp == null) return false;
        if (exp <= System.currentTimeMillis()) {
            // Expired — treat as unseen; remove inline.
            entries.remove(opsId);
            return false;
        }
        return true;
    }

    @Override
    public void markOpsIdSeen(String opsId, long expiresAtEpochMillis) {
        // GC expired entries on every write to prevent unbounded growth when
        // callers submit many short-lived tokens.
        gcExpired();

        if (entries.put(opsId, expiresAtEpochMillis) == null) {
            // Only track insertion order for genuinely new entries.
            insertionOrder.add(opsId);
        }
        if (entries.size() > SOFT_CAP) {
            evictOldest();
        }
    }

    /** Remove all entries whose TTL has already elapsed. Best-effort. */
    private void gcExpired() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> it = entries.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> e = it.next();
            if (e.getValue() <= now) {
                it.remove();
            }
        }
    }

    /**
     * Evict oldest entries until the cache is within the soft cap.
     * Synchronized to bound concurrent eviction races.
     */
    private synchronized void evictOldest() {
        while (entries.size() > SOFT_CAP) {
            String oldest = insertionOrder.pollFirst();
            if (oldest == null) break; // insertionOrder exhausted (stale keys already removed)
            entries.remove(oldest);
        }
    }
}
