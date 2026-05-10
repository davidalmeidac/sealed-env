/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * Sealed interface over the supported KDF parameter shapes.
 *
 * <p>Argon2id uses {@code t/m/p}; scrypt uses {@code N/r/p}. Renderers in
 * the format module emit the canonical per-algorithm string.
 */
public sealed interface KdfParams permits KdfParams.Argon2id, KdfParams.Scrypt {

    KdfAlgorithm algorithm();

    /** Argon2id parameters per RFC 9106. */
    record Argon2id(int t, int m, int p) implements KdfParams {
        public Argon2id {
            if (t < 1 || m < 1024 || p < 1) {
                throw new IllegalArgumentException(
                        "sealed-env: argon2id parameters out of range");
            }
        }

        @Override
        public KdfAlgorithm algorithm() {
            return KdfAlgorithm.ARGON2ID;
        }

        public String wire() {
            return "t=" + t + ",m=" + m + ",p=" + p;
        }
    }

    /** scrypt parameters per RFC 7914. {@code N} must be a power of two. */
    record Scrypt(int N, int r, int p) implements KdfParams {
        public Scrypt {
            if (N < 1024 || (N & (N - 1)) != 0 || r < 1 || p < 1) {
                throw new IllegalArgumentException(
                        "sealed-env: scrypt parameters out of range");
            }
        }

        @Override
        public KdfAlgorithm algorithm() {
            return KdfAlgorithm.SCRYPT;
        }

        public String wire() {
            return "N=" + N + ",r=" + r + ",p=" + p;
        }
    }

    /** Render the canonical {@code KDF-PARAMS} value for this params object. */
    default String wire() {
        if (this instanceof Argon2id a) return a.wire();
        if (this instanceof Scrypt s) return s.wire();
        throw new IllegalStateException("unknown KdfParams variant: " + getClass());
    }

    /** Default params for the Java writer (Argon2id, calibrated to <500ms desktop). */
    static Argon2id defaultArgon2id() {
        return new Argon2id(3, 65536, 4);
    }

    /** Default params for cross-stack files written by the Node writer (bumped to N=131072 in 0.1.1, SEC-002). */
    static Scrypt defaultScrypt() {
        return new Scrypt(131072, 8, 1);
    }
}
