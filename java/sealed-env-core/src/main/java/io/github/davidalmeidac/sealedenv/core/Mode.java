/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * Security mode of a sealed file.
 *
 * <ul>
 *   <li>{@link #BASIC} – AES-256-GCM with master key only.</li>
 *   <li>{@link #TEAM} – Adds explicit HMAC-SHA256 integrity tag and audit trail.</li>
 *   <li>{@link #ENTERPRISE} – Adds TOTP-bound unseal token + deploy challenge.</li>
 * </ul>
 *
 * The mode is part of the AAD, so a {@code basic} file cannot be silently
 * parsed as {@code enterprise} to bypass TOTP — the GCM tag verification
 * fails before any plaintext is exposed.
 *
 * @see <a href="../../../../../../../SPEC.md">.env.sealed v1 specification §3</a>
 */
public enum Mode {
    BASIC("basic"),
    TEAM("team"),
    ENTERPRISE("enterprise");

    private final String wire;

    Mode(String wire) {
        this.wire = wire;
    }

    /** Lowercase token as written in the magic line. */
    public String wire() {
        return wire;
    }

    public static Mode fromWire(String wire) {
        for (Mode m : values()) {
            if (m.wire.equals(wire)) {
                return m;
            }
        }
        throw new IllegalArgumentException("sealed-env: unknown mode \"" + wire + "\"");
    }
}
