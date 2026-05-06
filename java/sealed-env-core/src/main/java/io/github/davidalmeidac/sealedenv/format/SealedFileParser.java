/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.format;

import io.github.davidalmeidac.sealedenv.core.KdfAlgorithm;
import io.github.davidalmeidac.sealedenv.core.KdfParams;
import io.github.davidalmeidac.sealedenv.core.Mode;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException.Code;
import io.github.davidalmeidac.sealedenv.core.SealedFile;
import io.github.davidalmeidac.sealedenv.core.SealedFile.ChallengeBind;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict reader for the {@code .env.sealed} v1 textual format.
 *
 * <p>Parsing is intentionally strict — any deviation from the spec fails. This
 * is a security file; sloppy parsing is a vulnerability. Both {@code KDF=scrypt}
 * (written by Node) and {@code KDF=argon2id} (written by Java) are accepted
 * for cross-stack interop.
 */
public final class SealedFileParser {

    private static final Pattern MAGIC = Pattern.compile("^SEALED-ENV-V(\\d+) MODE=([a-z]+)$");
    private static final Pattern KEY_NAME = Pattern.compile("^[A-Z][A-Z0-9-]*$");
    private static final Pattern BASE64 = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");
    private static final Pattern ARGON2_PARAMS =
            Pattern.compile("^t=(\\d+),m=(\\d+),p=(\\d+)$");
    private static final Pattern SCRYPT_PARAMS =
            Pattern.compile("^N=(\\d+),r=(\\d+),p=(\\d+)$");
    private static final Base64.Decoder B64 = Base64.getDecoder();

    private SealedFileParser() {
        throw new AssertionError("no instances");
    }

    public static SealedFile parse(String text) {
        String normalized = text.replace("\r\n", "\n");
        String[] lines = normalized.split("\n", -1);

        if (lines.length < 5) {
            throw new SealedEnvException(Code.PARSE_ERROR,
                    "sealed-env: file too short to be valid");
        }

        // ── Magic line
        Matcher magicMatch = MAGIC.matcher(lines[0]);
        if (!magicMatch.matches()) {
            throw new SealedEnvException(Code.PARSE_ERROR,
                    "sealed-env: invalid magic line");
        }
        int version = Integer.parseInt(magicMatch.group(1));
        if (version != 1) {
            throw new SealedEnvException(Code.UNSUPPORTED_VERSION,
                    "sealed-env: file format V" + version
                            + " is too new, please upgrade your sealed-env library");
        }
        Mode mode;
        try {
            mode = Mode.fromWire(magicMatch.group(2));
        } catch (IllegalArgumentException e) {
            throw new SealedEnvException(Code.UNKNOWN_MODE, e.getMessage());
        }

        // ── Metadata
        Map<String, String> metadata = new LinkedHashMap<>();
        int i = 1;
        for (; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) break;
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new SealedEnvException(Code.PARSE_ERROR,
                        "sealed-env: malformed metadata at line " + (i + 1));
            }
            String key = line.substring(0, eq);
            String value = line.substring(eq + 1);
            if (!KEY_NAME.matcher(key).matches()) {
                throw new SealedEnvException(Code.PARSE_ERROR,
                        "sealed-env: invalid metadata key at line " + (i + 1));
            }
            if (metadata.containsKey(key)) {
                throw new SealedEnvException(Code.PARSE_ERROR,
                        "sealed-env: duplicate metadata key \"" + key + "\"");
            }
            metadata.put(key, value);
        }
        if (i >= lines.length - 1) {
            throw new SealedEnvException(Code.PARSE_ERROR,
                    "sealed-env: missing separator or body");
        }

        // ── Body
        String bodyLine = lines[i + 1];
        if (bodyLine.isEmpty()) {
            throw new SealedEnvException(Code.PARSE_ERROR, "sealed-env: empty body");
        }
        byte[] ciphertext = decodeB64(bodyLine, "CIPHERTEXT");

        // ── Required fields
        KdfAlgorithm kdf;
        try {
            kdf = KdfAlgorithm.fromWire(required(metadata, "KDF"));
        } catch (IllegalArgumentException e) {
            throw new SealedEnvException(Code.INVALID_FIELD, e.getMessage());
        }
        KdfParams kdfParams = parseKdfParams(kdf, required(metadata, "KDF-PARAMS"));
        byte[] salt = decodeB64(required(metadata, "SALT"), "SALT");
        byte[] nonce = decodeB64(required(metadata, "NONCE"), "NONCE");
        byte[] aadDigest = decodeB64(required(metadata, "AAD-DIGEST"), "AAD-DIGEST");
        String created = required(metadata, "CREATED");

        // ── Conditional fields
        Optional<byte[]> totpVerifier = Optional.empty();
        Optional<ChallengeBind> challengeBind = Optional.empty();
        if (mode == Mode.ENTERPRISE) {
            totpVerifier = Optional.of(decodeB64(required(metadata, "TOTP-VERIFIER"), "TOTP-VERIFIER"));
            challengeBind = Optional.of(ChallengeBind.fromWire(required(metadata, "CHALLENGE-BIND")));
        }

        Optional<byte[]> hmac = Optional.empty();
        if (mode == Mode.TEAM || mode == Mode.ENTERPRISE) {
            hmac = Optional.of(decodeB64(required(metadata, "HMAC"), "HMAC"));
        }

        Optional<String> rotated = Optional.ofNullable(metadata.get("ROTATED"));

        return new SealedFile(
                1, mode, kdf, kdfParams, salt, nonce,
                totpVerifier, challengeBind, aadDigest, hmac,
                created, rotated, ciphertext);
    }

    private static String required(Map<String, String> meta, String key) {
        String v = meta.get(key);
        if (v == null) {
            throw new SealedEnvException(Code.MISSING_FIELD,
                    "sealed-env: missing required metadata field \"" + key + "\"");
        }
        return v;
    }

    private static KdfParams parseKdfParams(KdfAlgorithm kdf, String s) {
        return switch (kdf) {
            case ARGON2ID -> {
                Matcher m = ARGON2_PARAMS.matcher(s);
                if (!m.matches()) {
                    throw new SealedEnvException(Code.INVALID_FIELD,
                            "sealed-env: invalid argon2id KDF-PARAMS \"" + s + "\"");
                }
                try {
                    yield new KdfParams.Argon2id(
                            Integer.parseInt(m.group(1)),
                            Integer.parseInt(m.group(2)),
                            Integer.parseInt(m.group(3)));
                } catch (IllegalArgumentException e) {
                    throw new SealedEnvException(Code.INVALID_FIELD, e.getMessage());
                }
            }
            case SCRYPT -> {
                Matcher m = SCRYPT_PARAMS.matcher(s);
                if (!m.matches()) {
                    throw new SealedEnvException(Code.INVALID_FIELD,
                            "sealed-env: invalid scrypt KDF-PARAMS \"" + s + "\"");
                }
                try {
                    yield new KdfParams.Scrypt(
                            Integer.parseInt(m.group(1)),
                            Integer.parseInt(m.group(2)),
                            Integer.parseInt(m.group(3)));
                } catch (IllegalArgumentException e) {
                    throw new SealedEnvException(Code.INVALID_FIELD, e.getMessage());
                }
            }
        };
    }

    private static byte[] decodeB64(String s, String fieldName) {
        if (!BASE64.matcher(s).matches()) {
            throw new SealedEnvException(Code.INVALID_FIELD,
                    "sealed-env: invalid base64 in field \"" + fieldName + "\"");
        }
        try {
            return B64.decode(s);
        } catch (IllegalArgumentException e) {
            throw new SealedEnvException(Code.INVALID_FIELD,
                    "sealed-env: corrupt base64 in field \"" + fieldName + "\"");
        }
    }
}
