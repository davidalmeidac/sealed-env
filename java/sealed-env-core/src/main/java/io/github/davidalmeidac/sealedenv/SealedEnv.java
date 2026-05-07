/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv;

import io.github.davidalmeidac.sealedenv.core.Constants;
import io.github.davidalmeidac.sealedenv.core.KdfAlgorithm;
import io.github.davidalmeidac.sealedenv.core.KdfParams;
import io.github.davidalmeidac.sealedenv.core.Mode;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException.Code;
import io.github.davidalmeidac.sealedenv.core.SealedFile;
import io.github.davidalmeidac.sealedenv.core.SealedFile.ChallengeBind;
import io.github.davidalmeidac.sealedenv.crypto.CryptoPrimitives;
import io.github.davidalmeidac.sealedenv.format.SealedFileParser;
import io.github.davidalmeidac.sealedenv.format.SealedFileSerializer;
import io.github.davidalmeidac.sealedenv.totp.UnsealToken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * High-level API: {@link #seal}, {@link #unseal}, {@link #loadSealed}.
 *
 * <p>The Java implementation writes Argon2id by default (Bouncy Castle) and
 * reads both Argon2id and scrypt — interoperating cleanly with files written
 * by the Node implementation.
 */
public final class SealedEnv {

    private SealedEnv() {
        throw new AssertionError("no instances");
    }

    /** Options for {@link #seal}. */
    public static final class SealOptions {
        public byte[] plaintext;
        public byte[] masterKey;
        public Mode mode;
        public byte[] totpSecret;        // required for ENTERPRISE
        public byte[] signingKey;        // required for TEAM/ENTERPRISE
        public Boolean challengeBind;    // null defaults to true for ENTERPRISE
        public KdfParams kdfParams;      // null → default Argon2id
    }

    /** Options for {@link #unseal}. */
    public static final class UnsealOptions {
        public SealedFile file;
        public byte[] masterKey;
        public byte[] signingKey;        // required for TEAM/ENTERPRISE
        public String unsealToken;       // required for ENTERPRISE
        public String deployId;          // required when CHALLENGE-BIND=enabled
    }

    /** Result of {@link #seal}: parsed file + serialized text form. */
    public record SealResult(SealedFile file, String serialized) {
    }

    public static SealResult seal(SealOptions opts) {
        validateMasterKey(opts.masterKey);

        if (opts.mode == Mode.ENTERPRISE
                && (opts.totpSecret == null || opts.totpSecret.length < 16)) {
            throw new SealedEnvException(Code.CONFIG_ERROR,
                    "enterprise mode requires totpSecret (>=16 bytes)");
        }
        if ((opts.mode == Mode.TEAM || opts.mode == Mode.ENTERPRISE)
                && (opts.signingKey == null || opts.signingKey.length < 16)) {
            throw new SealedEnvException(Code.CONFIG_ERROR,
                    opts.mode + " mode requires signingKey (>=16 bytes)");
        }

        KdfParams params = opts.kdfParams != null
                ? opts.kdfParams : KdfParams.defaultArgon2id();
        byte[] salt = CryptoPrimitives.randomBytes(Constants.SALT_LEN);
        byte[] nonce = CryptoPrimitives.randomBytes(Constants.NONCE_LEN);
        String created = Instant.now().toString();

        byte[] derivedKey = CryptoPrimitives.deriveMasterKey(opts.masterKey, salt, params);
        byte[] encKey = null;
        try {
            encKey = CryptoPrimitives.hkdf(derivedKey, salt, Constants.HKDF_INFO_ENC, Constants.KEY_LEN);

            // Enterprise: derive the salt-bound epoch and commit to it.
            // The token will carry the epoch (NOT the TOTP secret).
            Optional<byte[]> epochCommit = Optional.empty();
            Optional<ChallengeBind> challengeBind = Optional.empty();
            if (opts.mode == Mode.ENTERPRISE) {
                epochCommit = Optional.of(buildEpochCommit(derivedKey, opts.totpSecret, salt));
                boolean cbEnabled = opts.challengeBind == null || opts.challengeBind;
                challengeBind = Optional.of(cbEnabled
                        ? ChallengeBind.ENABLED : ChallengeBind.DISABLED);
            }

            // Draft file (without ciphertext / digest / hmac yet) so we can
            // canonically build the AAD over metadata.
            SealedFile draft = new SealedFile(
                    1, opts.mode, params.algorithm(), params, salt, nonce,
                    epochCommit, challengeBind,
                    new byte[32], Optional.empty(),
                    created, Optional.empty(), new byte[0]);

            byte[] aad = SealedFileSerializer.buildAad(draft);
            byte[] aadDigest = CryptoPrimitives.sha256(aad);
            byte[] ciphertext = CryptoPrimitives.aesGcmEncrypt(encKey, nonce, opts.plaintext, aad);

            Optional<byte[]> hmac = Optional.empty();
            if (opts.mode == Mode.TEAM || opts.mode == Mode.ENTERPRISE) {
                byte[] macKey = CryptoPrimitives.hkdf(
                        opts.signingKey, salt, Constants.HKDF_INFO_MAC, Constants.KEY_LEN);
                try {
                    byte[] message = concat(aad, ciphertext);
                    hmac = Optional.of(CryptoPrimitives.hmacSha256(macKey, message));
                } finally {
                    CryptoPrimitives.wipe(macKey);
                }
            }

            SealedFile file = new SealedFile(
                    1, opts.mode, params.algorithm(), params, salt, nonce,
                    epochCommit, challengeBind, aadDigest, hmac,
                    created, Optional.empty(), ciphertext);
            return new SealResult(file, SealedFileSerializer.serialize(file));
        } finally {
            CryptoPrimitives.wipe(encKey);
            CryptoPrimitives.wipe(derivedKey);
        }
    }

    public static byte[] unseal(UnsealOptions opts) {
        validateMasterKey(opts.masterKey);
        SealedFile file = opts.file;

        byte[] derivedKey = CryptoPrimitives.deriveMasterKey(
                opts.masterKey, file.salt(), file.kdfParams());
        try {
            // Operator-error pre-checks (explicit, not collapsed into DECRYPT_FAILED)
            if (file.mode() == Mode.TEAM || file.mode() == Mode.ENTERPRISE) {
                if (opts.signingKey == null) {
                    throw new SealedEnvException(Code.MISSING_KEY,
                            file.mode() + " mode requires signing key");
                }
            }
            if (file.mode() == Mode.ENTERPRISE && opts.unsealToken == null) {
                throw new SealedEnvException(Code.MISSING_TOKEN,
                        "enterprise mode requires unseal token");
            }

            // HMAC verification — fail loud (integrity is not an oracle)
            if (file.mode() == Mode.TEAM || file.mode() == Mode.ENTERPRISE) {
                byte[] macKey = CryptoPrimitives.hkdf(
                        opts.signingKey, file.salt(), Constants.HKDF_INFO_MAC, Constants.KEY_LEN);
                try {
                    byte[] aad = SealedFileSerializer.buildAad(file);
                    byte[] expected = CryptoPrimitives.hmacSha256(
                            macKey, concat(aad, file.ciphertext()));
                    if (file.hmac().isEmpty()
                            || !CryptoPrimitives.constantTimeEqual(expected, file.hmac().get())) {
                        throw SealedEnvException.decryptFailed();
                    }
                } finally {
                    CryptoPrimitives.wipe(macKey);
                }
            }

            // Enterprise: verify unseal token carries an epoch matching
            // the file's EPOCH-COMMIT. The TOTP secret never appears
            // in the token — the carried `enterpriseEpoch` is a salt-
            // bound HMAC derivative.
            if (file.mode() == Mode.ENTERPRISE) {
                UnsealToken.VerifyResult result = UnsealToken.verify(
                        new UnsealToken.VerifyInput(
                                opts.unsealToken,
                                derivedKey,
                                opts.deployId,
                                file.challengeBind().orElse(ChallengeBind.ENABLED)
                                        == ChallengeBind.ENABLED));
                byte[] expectedCommit = buildEpochCommitFromEpoch(derivedKey, result.enterpriseEpoch());
                if (file.epochCommit().isEmpty()
                        || !CryptoPrimitives.constantTimeEqual(
                        expectedCommit, file.epochCommit().get())) {
                    throw SealedEnvException.decryptFailed();
                }
                CryptoPrimitives.wipe(result.enterpriseEpoch());
            }

            // AAD digest defense in depth (GCM tag would also catch this)
            byte[] aad = SealedFileSerializer.buildAad(file);
            byte[] computedDigest = CryptoPrimitives.sha256(aad);
            if (!CryptoPrimitives.constantTimeEqual(computedDigest, file.aadDigest())) {
                throw SealedEnvException.decryptFailed();
            }

            byte[] encKey = CryptoPrimitives.hkdf(
                    derivedKey, file.salt(), Constants.HKDF_INFO_ENC, Constants.KEY_LEN);
            try {
                return CryptoPrimitives.aesGcmDecrypt(
                        encKey, file.nonce(), file.ciphertext(), aad);
            } finally {
                CryptoPrimitives.wipe(encKey);
            }
        } finally {
            CryptoPrimitives.wipe(derivedKey);
        }
    }

    /** Options for {@link #loadSealed}. */
    public static final class LoadOptions {
        public Path path;             // default: ./.env.sealed
        public boolean populateSystem = false;  // do NOT mutate JVM env by default
        public String masterKeyVar = "SEALED_ENV_KEY";
        public String signingKeyVar = "SEALED_ENV_SIGNING_KEY";
        public String unsealTokenVar = "SEALED_ENV_UNSEAL_TOKEN";
        public String deployIdVar = "SEALED_ENV_DEPLOY_ID";
    }

    /**
     * Read {@code .env.sealed} from disk, decrypt with env-var-supplied keys,
     * and return the parsed key/value pairs. Unlike Node's {@code loadSealed},
     * this does NOT mutate {@link System#getenv()} (immutable in JVM); use
     * {@link #applyToSystemProperties} if you want JVM-wide accessibility.
     */
    public static Map<String, String> loadSealed(LoadOptions opts) {
        if (opts == null) opts = new LoadOptions();
        Path path = opts.path != null ? opts.path : Path.of(".env.sealed");
        String masterKeyStr = System.getenv(opts.masterKeyVar);
        if (masterKeyStr == null || masterKeyStr.isEmpty()) {
            throw new SealedEnvException(Code.MISSING_KEY,
                    "sealed-env: environment variable " + opts.masterKeyVar + " is required");
        }
        byte[] masterKey = decodeKeyMaterial(masterKeyStr, opts.masterKeyVar);
        String signingKeyStr = System.getenv(opts.signingKeyVar);
        byte[] signingKey = signingKeyStr == null
                ? null : decodeKeyMaterial(signingKeyStr, opts.signingKeyVar);
        String unsealToken = System.getenv(opts.unsealTokenVar);
        String deployId = System.getenv(opts.deployIdVar);

        String text;
        try {
            text = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new SealedEnvException(Code.CONFIG_ERROR,
                    "sealed-env: unable to read " + path + ": " + e.getMessage());
        }
        SealedFile parsed = SealedFileParser.parse(text);

        UnsealOptions u = new UnsealOptions();
        u.file = parsed;
        u.masterKey = masterKey;
        u.signingKey = signingKey;
        u.unsealToken = unsealToken;
        u.deployId = deployId;
        byte[] plaintextBytes = unseal(u);
        try {
            String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
            Map<String, String> parsedEnv = parseDotenv(plaintext);
            if (opts.populateSystem) {
                applyToSystemProperties(parsedEnv);
            }
            return parsedEnv;
        } finally {
            CryptoPrimitives.wipe(plaintextBytes);
            CryptoPrimitives.wipe(masterKey);
            if (signingKey != null) CryptoPrimitives.wipe(signingKey);
        }
    }

    /**
     * Convenience: copy each entry into {@link System#setProperty}, but only
     * if the property is not already set (explicit values take precedence).
     */
    public static void applyToSystemProperties(Map<String, String> env) {
        for (var e : env.entrySet()) {
            if (System.getProperty(e.getKey()) == null) {
                System.setProperty(e.getKey(), e.getValue());
            }
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    /**
     * Compute the salt-bound enterprise epoch (used at seal/mint time):
     * {@code enterprise_epoch = HMAC(totpSecret, salt || "epoch-v1")}.
     * Caller is responsible for wiping the returned buffer.
     */
    static byte[] buildEnterpriseEpoch(byte[] totpSecret, byte[] salt) {
        byte[] tag = Constants.EPOCH_DERIVE_TAG.getBytes(StandardCharsets.UTF_8);
        return CryptoPrimitives.hmacSha256(totpSecret, concat(salt, tag));
    }

    /**
     * Compute the file-side epoch commitment:
     * {@code epoch_commit = HMAC(derivedKey, enterprise_epoch || "epoch-commit-v1")}.
     */
    private static byte[] buildEpochCommitFromEpoch(byte[] derivedKey, byte[] enterpriseEpoch) {
        byte[] tag = Constants.EPOCH_COMMIT_TAG.getBytes(StandardCharsets.UTF_8);
        return CryptoPrimitives.hmacSha256(derivedKey, concat(enterpriseEpoch, tag));
    }

    /**
     * Compose: derive epoch from totpSecret + salt, then commit it under derivedKey.
     * Used at seal time. Wipes the intermediate epoch.
     */
    private static byte[] buildEpochCommit(byte[] derivedKey, byte[] totpSecret, byte[] salt) {
        byte[] epoch = buildEnterpriseEpoch(totpSecret, salt);
        try {
            return buildEpochCommitFromEpoch(derivedKey, epoch);
        } finally {
            CryptoPrimitives.wipe(epoch);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void validateMasterKey(byte[] masterKey) {
        if (masterKey == null) {
            throw new SealedEnvException(Code.CONFIG_ERROR, "masterKey must not be null");
        }
        if (masterKey.length < 16) {
            throw new SealedEnvException(Code.CONFIG_ERROR,
                    "masterKey too short (minimum 16 bytes, recommended 32)");
        }
    }

    private static byte[] decodeKeyMaterial(String s, String varName) {
        if (s.matches("[0-9a-fA-F]+") && s.length() % 2 == 0) {
            byte[] out = new byte[s.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }
        if (s.matches("[A-Za-z0-9+/]+={0,2}")) {
            try {
                return java.util.Base64.getDecoder().decode(s);
            } catch (IllegalArgumentException ignored) {
                // fall through
            }
        }
        throw new SealedEnvException(Code.CONFIG_ERROR,
                varName + " must be hex or base64 encoded");
    }

    /** Minimal dotenv parser — same semantics as the Node implementation. */
    private static Map<String, String> parseDotenv(String text) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String rawLine : text.replace("\r\n", "\n").split("\n", -1)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq <= 0) continue;
            String key = line.substring(0, eq).trim();
            if (!key.matches("[A-Za-z_][A-Za-z0-9_]*")) continue;
            String value = line.substring(eq + 1).trim();
            if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1)
                        .replace("\\n", "\n")
                        .replace("\\r", "\r")
                        .replace("\\t", "\t")
                        .replace("\\\"", "\"")
                        .replace("\\\\", "\\");
            } else if (value.length() >= 2 && value.startsWith("'") && value.endsWith("'")) {
                value = value.substring(1, value.length() - 1);
            } else {
                int hashIdx = value.indexOf(" #");
                if (hashIdx >= 0) value = value.substring(0, hashIdx).trim();
            }
            result.put(key, value);
        }
        return result;
    }

    /** For convenience in tests — direct delegation. */
    @SuppressWarnings("unused")
    private static KdfAlgorithm defaultKdf() {
        return KdfAlgorithm.ARGON2ID;
    }
}
