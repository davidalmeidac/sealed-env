/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * Replay-protection cache for unseal tokens.
 *
 * <p>Implementations MUST be thread-safe — {@link SealedEnv#unseal} may be
 * called concurrently from multiple threads within the same JVM.
 *
 * <p>The default implementation is {@link InProcessReplayCache}: a bounded,
 * in-process LRU backed by a {@link java.util.concurrent.ConcurrentHashMap}.
 * To share replay state across JVM processes (e.g. multiple app nodes), inject
 * a Redis- or database-backed implementation via
 * {@link SealedEnv.UnsealOptions#replayCache}.
 *
 * <p>Failure semantics: if {@link #markOpsIdSeen} throws, the SDK treats the
 * error as a cache-backend outage and throws {@code TOKEN_INVALID} with cause
 * {@code replay-cache-unavailable} (fail-closed). Callers who want fail-open
 * MUST provide an implementation whose {@code markOpsIdSeen} swallows errors.
 */
public interface ReplayCache {

    /**
     * Returns {@code true} if {@code opsId} has been seen within its TTL
     * window (i.e. it was previously recorded by {@link #markOpsIdSeen} and
     * has not yet expired).
     *
     * @param opsId the ops_id claim from the unseal token — never {@code null}
     * @return {@code true} if the id has already been used
     */
    boolean isOpsIdSeen(String opsId);

    /**
     * Records {@code opsId} as seen, associated with the token's absolute
     * expiry time.
     *
     * @param opsId              the ops_id claim — never {@code null}
     * @param expiresAtEpochMillis the token's {@code exp} claim converted to
     *                           epoch <em>milliseconds</em> (epoch seconds × 1000)
     * @throws RuntimeException  if the backing store is unavailable; the SDK
     *                           will surface this as {@code TOKEN_INVALID}
     *                           (cause: {@code replay-cache-unavailable})
     */
    void markOpsIdSeen(String opsId, long expiresAtEpochMillis);
}
