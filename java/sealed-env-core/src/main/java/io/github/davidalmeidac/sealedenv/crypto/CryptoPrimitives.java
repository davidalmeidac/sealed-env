/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.crypto;

import io.github.davidalmeidac.sealedenv.core.Constants;
import io.github.davidalmeidac.sealedenv.core.KdfParams;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * All cryptographic primitives, in one auditable place.
 *
 * <p>Wrappers exist for two reasons:
 * <ol>
 *   <li>Pin specific algorithms — never let a caller pick a weaker one.</li>
 *   <li>Make the audit surface a single class.</li>
 * </ol>
 *
 * <p>Bouncy Castle is required only for Argon2id (the JDK ships AES-GCM,
 * HKDF-equivalent via Mac, HMAC, scrypt, and SecureRandom natively).
 *
 * @see <a href="../../../../../../../SPEC.md">.env.sealed v1 specification §5</a>
 */
public final class CryptoPrimitives {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoPrimitives() {
        throw new AssertionError("no instances");
    }

    /** OS CSPRNG-backed random bytes. */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        SECURE_RANDOM.nextBytes(out);
        return out;
    }

    /** Constant-time byte-array equality. Returns false on length mismatch. */
    public static boolean constantTimeEqual(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** SHA-256. */
    public static byte[] sha256(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** HMAC-SHA256. */
    public static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /**
     * HKDF-SHA256 (RFC 5869). Performs Extract+Expand as a single operation.
     * Implemented directly (no Bouncy Castle dependency for this primitive)
     * so we can audit it line-by-line.
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, String info, int length) {
        byte[] saltOrEmpty = (salt == null || salt.length == 0) ? new byte[32] : salt;
        // Extract
        byte[] prk = hmacSha256(saltOrEmpty, ikm);
        // Expand
        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        int hashLen = 32; // SHA-256
        int n = (length + hashLen - 1) / hashLen;
        if (n > 255) {
            throw new IllegalArgumentException("HKDF: requested too many bytes");
        }
        byte[] okm = new byte[length];
        byte[] previous = new byte[0];
        int written = 0;
        for (int i = 1; i <= n; i++) {
            byte[] input = new byte[previous.length + infoBytes.length + 1];
            System.arraycopy(previous, 0, input, 0, previous.length);
            System.arraycopy(infoBytes, 0, input, previous.length, infoBytes.length);
            input[input.length - 1] = (byte) i;
            previous = hmacSha256(prk, input);
            int copy = Math.min(hashLen, length - written);
            System.arraycopy(previous, 0, okm, written, copy);
            written += copy;
        }
        return okm;
    }

    /**
     * Derive a 32-byte key from the master secret using the file's KDF.
     * Both Argon2id and scrypt are supported.
     */
    public static byte[] deriveMasterKey(byte[] masterKey, byte[] salt, KdfParams params) {
        if (params instanceof KdfParams.Argon2id a) {
            return argon2id(masterKey, salt, a);
        }
        if (params instanceof KdfParams.Scrypt s) {
            return SCrypt.generate(masterKey, salt, s.N(), s.r(), s.p(), Constants.KEY_LEN);
        }
        throw new IllegalStateException("unknown KdfParams variant: " + params.getClass());
    }

    private static byte[] argon2id(byte[] password, byte[] salt, KdfParams.Argon2id a) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(a.t())
                .withMemoryAsKB(a.m())
                .withParallelism(a.p())
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);
        byte[] out = new byte[Constants.KEY_LEN];
        gen.generateBytes(password, out);
        return out;
    }

    /** AES-256-GCM encryption. Returns ciphertext concatenated with the 16-byte tag. */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("AES key must be 32 bytes");
        }
        if (nonce.length != Constants.NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be 12 bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(Constants.GCM_TAG_LEN * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    /** AES-256-GCM decryption. Throws {@link SealedEnvException#decryptFailed()} on tag mismatch. */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad) {
        if (ciphertextWithTag.length < Constants.GCM_TAG_LEN) {
            throw SealedEnvException.decryptFailed();
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(Constants.GCM_TAG_LEN * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            throw SealedEnvException.decryptFailed();
        }
    }

    /** Best-effort wipe of a buffer. JVM may have moved memory, but worth doing. */
    public static void wipe(byte[] buf) {
        if (buf != null) {
            java.util.Arrays.fill(buf, (byte) 0);
        }
    }
}
