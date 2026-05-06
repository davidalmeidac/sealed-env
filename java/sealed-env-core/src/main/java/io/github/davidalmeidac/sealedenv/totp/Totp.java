/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.time.Clock;

/**
 * RFC 6238 TOTP — SHA-1, 30s step, 6 digits, ±1 step skew on verify.
 *
 * <p>The use of SHA-1 is mandated by RFC 6238 and is widely deployed in
 * authenticator apps. SHA-1 is not used anywhere else in {@code sealed-env}.
 */
public final class Totp {

    private static final int STEP_SECONDS = 30;
    private static final int DIGITS = 6;

    private Totp() {
        throw new AssertionError("no instances");
    }

    public static String generateCode(byte[] secret, long unixSeconds) {
        long counter = unixSeconds / STEP_SECONDS;
        return hotp(secret, counter);
    }

    public static boolean verifyCode(byte[] secret, String code, Clock clock) {
        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }
        long now = clock.instant().getEpochSecond();
        long counter = now / STEP_SECONDS;
        for (int skew = -1; skew <= 1; skew++) {
            String expected = hotp(secret, counter + skew);
            if (constantTimeEqual(expected, code)) {
                return true;
            }
        }
        return false;
    }

    public static boolean verifyCode(byte[] secret, String code) {
        return verifyCode(secret, code, Clock.systemUTC());
    }

    private static String hotp(byte[] secret, long counter) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);
            int offset = hash[hash.length - 1] & 0x0f;
            int truncated =
                    ((hash[offset] & 0x7f) << 24)
                            | ((hash[offset + 1] & 0xff) << 16)
                            | ((hash[offset + 2] & 0xff) << 8)
                            | (hash[offset + 3] & 0xff);
            int code = truncated % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", code);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA1 unavailable", e);
        }
    }

    private static boolean constantTimeEqual(String a, String b) {
        if (a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }
}
