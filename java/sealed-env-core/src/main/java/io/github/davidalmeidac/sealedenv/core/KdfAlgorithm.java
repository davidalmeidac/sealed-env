/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * KDF algorithm identifier as written in {@code .env.sealed}.
 *
 * <p>Both implementations MUST be able to read both. The Java implementation
 * writes {@link #ARGON2ID} by default (Bouncy Castle ships it natively); the
 * Node implementation writes {@link #SCRYPT} (Node 22 stdlib has no Argon2id).
 * Each can read what the other writes.
 */
public enum KdfAlgorithm {
    ARGON2ID("argon2id"),
    SCRYPT("scrypt");

    private final String wire;

    KdfAlgorithm(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }

    public static KdfAlgorithm fromWire(String wire) {
        for (KdfAlgorithm k : values()) {
            if (k.wire.equals(wire)) {
                return k;
            }
        }
        throw new IllegalArgumentException("sealed-env: unsupported KDF \"" + wire + "\"");
    }
}
