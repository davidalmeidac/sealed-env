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

    /**
     * Optional sub-classification for {@link Code#TOKEN_INVALID} errors.
     *
     * <p>Values used by the replay-cache path:
     * <ul>
     *   <li>{@code "replay"} — token's ops_id was already seen in the cache
     *   <li>{@code "replay-cache-unavailable"} — cache backend threw during markOpsIdSeen
     * </ul>
     *
     * <p>Existing constructors leave this {@code null} — backwards-compatible.
     */
    private final String reason;

    public SealedEnvException(Code code, String message) {
        super(message);
        this.code = code;
        this.reason = null;
    }

    public SealedEnvException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.reason = null;
    }

    /**
     * Constructor with an explicit reason sub-classifier.
     *
     * @param code    top-level error code
     * @param message human-readable description (must not contain secrets)
     * @param reason  optional sub-classification string (e.g. {@code "replay"})
     */
    public SealedEnvException(Code code, String message, String reason) {
        super(message);
        this.code = code;
        this.reason = reason;
    }

    public Code code() {
        return code;
    }

    /**
     * Optional sub-classification for this exception.
     *
     * @return the reason string, or {@code null} if not set
     */
    public String reason() {
        return reason;
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
