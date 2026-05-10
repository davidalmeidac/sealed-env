/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link InProcessReplayCache}.
 *
 * <p>Covers the spec A-9 DoS guard (cap at 10k entries),
 * expired-entry GC, and basic mark/see semantics.
 */
@DisplayName("InProcessReplayCache")
class InProcessReplayCacheTest {

    private static long futureExp() {
        // 1 hour from now, in epoch milliseconds (the interface contract)
        return System.currentTimeMillis() + 3_600_000L;
    }

    private static long pastExp() {
        // 1 second in the past, in epoch milliseconds
        return System.currentTimeMillis() - 1_000L;
    }

    @Nested
    @DisplayName("basic mark / see")
    class BasicMarkSee {

        @Test
        @DisplayName("first mark → isSeen returns true")
        void firstMarkThenSee() {
            InProcessReplayCache cache = new InProcessReplayCache();
            String opsId = "ops-001";

            cache.markOpsIdSeen(opsId, futureExp());

            assertThat(cache.isOpsIdSeen(opsId)).isTrue();
        }

        @Test
        @DisplayName("unseen opsId → isSeen returns false")
        void unseenReturnsFalse() {
            InProcessReplayCache cache = new InProcessReplayCache();
            assertThat(cache.isOpsIdSeen("ops-never-seen")).isFalse();
        }

        @Test
        @DisplayName("different opsId is not conflated")
        void differentOpsIdIsIndependent() {
            InProcessReplayCache cache = new InProcessReplayCache();
            cache.markOpsIdSeen("ops-A", futureExp());

            assertThat(cache.isOpsIdSeen("ops-A")).isTrue();
            assertThat(cache.isOpsIdSeen("ops-B")).isFalse();
        }
    }

    @Nested
    @DisplayName("expiry / GC")
    class ExpiryAndGc {

        @Test
        @DisplayName("expired entry treated as missing (returns false)")
        void expiredEntryTreatedAsMissing() {
            InProcessReplayCache cache = new InProcessReplayCache();
            cache.markOpsIdSeen("ops-expired", pastExp());

            assertThat(cache.isOpsIdSeen("ops-expired")).isFalse();
        }

        @Test
        @DisplayName("future entry is visible (returns true)")
        void futureEntryIsVisible() {
            InProcessReplayCache cache = new InProcessReplayCache();
            cache.markOpsIdSeen("ops-future", futureExp());

            assertThat(cache.isOpsIdSeen("ops-future")).isTrue();
        }

        @Test
        @DisplayName("GC of expired entries runs on markOpsIdSeen")
        void gcRunsOnMark() {
            InProcessReplayCache cache = new InProcessReplayCache();
            // Mark two expired entries
            cache.markOpsIdSeen("expired-1", pastExp());
            cache.markOpsIdSeen("expired-2", pastExp());

            // Trigger GC by marking a fresh entry
            cache.markOpsIdSeen("fresh-1", futureExp());

            // After GC, expired entries must be treated as unseen
            assertThat(cache.isOpsIdSeen("expired-1")).isFalse();
            assertThat(cache.isOpsIdSeen("expired-2")).isFalse();
            // The fresh one must still be visible
            assertThat(cache.isOpsIdSeen("fresh-1")).isTrue();
        }
    }

    @Nested
    @DisplayName("soft cap eviction at 10 001 entries")
    class CapEviction {

        @Test
        @DisplayName("inserting 10_001 distinct entries keeps cache bounded at or below 10_000")
        void capEvictionAt10001() {
            InProcessReplayCache cache = new InProcessReplayCache();
            long exp = futureExp();

            // Insert exactly 10_001 entries. The first (index 0) is the oldest.
            for (int i = 0; i <= 10_000; i++) {
                cache.markOpsIdSeen("opsid-" + i, exp);
            }

            // The newest entry (10_000) must be present
            assertThat(cache.isOpsIdSeen("opsid-10000")).isTrue();

            // The oldest entry (0) must have been evicted
            assertThat(cache.isOpsIdSeen("opsid-0")).isFalse();
        }
    }

    @Nested
    @DisplayName("thread-safety smoke test")
    class ThreadSafety {

        @Test
        @DisplayName("concurrent marks from multiple threads do not throw or corrupt state")
        void concurrentMarksDoNotCrash() throws InterruptedException {
            InProcessReplayCache cache = new InProcessReplayCache();
            int threads = 8;
            int perThread = 500;
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Throwable> errors = new ArrayList<>();

            ExecutorService pool = Executors.newFixedThreadPool(threads);
            for (int t = 0; t < threads; t++) {
                final int threadId = t;
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    for (int i = 0; i < perThread; i++) {
                        try {
                            String id = "t" + threadId + "-" + i;
                            cache.markOpsIdSeen(id, futureExp());
                            cache.isOpsIdSeen(id);
                        } catch (Throwable ex) {
                            synchronized (errors) {
                                errors.add(ex);
                            }
                        }
                    }
                });
            }

            ready.await(5, TimeUnit.SECONDS);
            go.countDown();
            pool.shutdown();
            pool.awaitTermination(10, TimeUnit.SECONDS);

            assertThat(errors).as("no exceptions from concurrent access").isEmpty();
        }
    }
}
