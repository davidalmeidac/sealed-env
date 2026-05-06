/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.core;

/**
 * The single exception type thrown by {@code sealed-env}.
 *
 * <p>We intentionally use a single class with a {@link Code} discriminator
 * rather than a hierarchy. Callers can {@code switch} on {@link #code()}.
 *
 * <p>For decryption failures the message is deliberately collapsed into one
 * string to avoid timing or oracle leaks to attackers probing keys.
 */
public final class SealedEnvException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Stable error codes. The wire form is the enum name. */
    public enum Code {
        PARSE_ERROR,
        UNSUPPORTED_VERSION,
        UNKNOWN_MODE,
        MISSING_FIELD,
        INVALID_FIELD,
        UNSUPPORTED_KDF,
        MISSING_KEY,
        MISSING_TOKEN,
        TOKEN_EXPIRED,
        TOKEN_INVALID,
        DEPLOY_MISMATCH,
        DECRYPT_FAILED,
        CONFIG_ERROR
    }

    private final Code code;

    public SealedEnvException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public SealedEnvException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }

    /**
     * The single user-facing decryption failure. Same message regardless of
     * which check actually failed (oracle defense).
     */
    public static SealedEnvException decryptFailed() {
        return new SealedEnvException(
                Code.DECRYPT_FAILED,
                "sealed-env: file is corrupted, tampered, or wrong key");
    }
}
