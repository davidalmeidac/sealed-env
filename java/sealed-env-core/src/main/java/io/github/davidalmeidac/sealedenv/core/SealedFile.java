/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

import java.util.Optional;

/**
 * Parsed representation of a {@code .env.sealed} v1 file.
 *
 * <p>Constructed by the parser, consumed by the encryption pipeline, and
 * rendered back to text by the serializer. All byte arrays are owned by the
 * record — callers MUST treat them as defensively wiped after use.
 *
 * @see <a href="../../../../../../../SPEC.md">.env.sealed v1 specification</a>
 */
public record SealedFile(
        int version,
        Mode mode,
        KdfAlgorithm kdf,
        KdfParams kdfParams,
        byte[] salt,
        byte[] nonce,
        Optional<byte[]> epochCommit,
        Optional<ChallengeBind> challengeBind,
        byte[] aadDigest,
        Optional<byte[]> hmac,
        String created,
        Optional<String> rotated,
        byte[] ciphertext) {

    public SealedFile {
        if (version != 1) {
            throw new IllegalArgumentException("only v1 supported, got " + version);
        }
        if (kdf != kdfParams.algorithm()) {
            throw new IllegalArgumentException(
                    "kdf and kdfParams disagree: " + kdf + " vs " + kdfParams.algorithm());
        }
    }

    /** Whether {@code CHALLENGE-BIND} is enabled (enterprise mode only). */
    public enum ChallengeBind {
        ENABLED("enabled"),
        DISABLED("disabled");

        private final String wire;

        ChallengeBind(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }

        public static ChallengeBind fromWire(String wire) {
            for (ChallengeBind c : values()) {
                if (c.wire.equals(wire)) {
                    return c;
                }
            }
            throw new SealedEnvException(
                    SealedEnvException.Code.INVALID_FIELD,
                    "sealed-env: invalid CHALLENGE-BIND \"" + wire + "\"");
        }
    }
}
