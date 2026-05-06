/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * Format-level constants. All values are pinned by the {@code .env.sealed} v1
 * specification — modifying them silently breaks cross-stack interop.
 */
public final class Constants {

    private Constants() {
        throw new AssertionError("no instances");
    }

    public static final int FILE_FORMAT_VERSION = 1;
    public static final String MAGIC_LINE_PREFIX = "SEALED-ENV-V1";

    /** AES-256-GCM nonce length (bytes). */
    public static final int NONCE_LEN = 12;

    /** Salt length (bytes). */
    public static final int SALT_LEN = 16;

    /** AES-256 key length (bytes). */
    public static final int KEY_LEN = 32;

    /** HMAC-SHA256 output length (bytes). */
    public static final int MAC_LEN = 32;

    /** AES-GCM auth tag length (bytes). */
    public static final int GCM_TAG_LEN = 16;

    /** TOTP secret length per RFC 4226 recommendation. */
    public static final int TOTP_SECRET_LEN = 20;

    /** Maximum age of an unseal token (seconds). */
    public static final int MAX_UNSEAL_TOKEN_AGE_SECONDS = 600;

    /** HKDF info strings — versioned to allow future format upgrades. */
    public static final String HKDF_INFO_ENC = "sealed-env:v1:enc";
    public static final String HKDF_INFO_MAC = "sealed-env:v1:mac";

    /** TOTP verifier domain-separation tag. */
    public static final String TOTP_VERIFY_TAG = "verify-v1";
}
