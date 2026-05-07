/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.format;

import io.github.davidalmeidac.sealedenv.core.Mode;
import io.github.davidalmeidac.sealedenv.core.SealedFile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Writer for the {@code .env.sealed} v1 format.
 *
 * <p>Output is byte-for-byte deterministic given identical inputs (salt,
 * nonce, timestamps). This matters for test-vector verification across
 * Node and Java implementations.
 */
public final class SealedFileSerializer {

    /** Standard base64 WITH padding — matches Node's {@code Buffer#toString("base64")}. */
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private SealedFileSerializer() {
        throw new AssertionError("no instances");
    }

    public static String serialize(SealedFile file) {
        List<String> lines = buildLines(file, true);
        lines.add("");
        lines.add(B64.encodeToString(file.ciphertext()));
        return String.join("\n", lines);
    }

    /**
     * Build the canonical AAD for the GCM cipher: magic + metadata
     * EXCLUDING the {@code AAD-DIGEST} and {@code HMAC} fields, joined by
     * {@code \n} with no trailing newline.
     */
    public static byte[] buildAad(SealedFile file) {
        List<String> lines = buildLines(file, false);
        return String.join("\n", lines).getBytes(StandardCharsets.UTF_8);
    }

    private static List<String> buildLines(SealedFile file, boolean includeDigestAndHmac) {
        List<String> lines = new ArrayList<>();
        lines.add("SEALED-ENV-V" + file.version() + " MODE=" + file.mode().wire());
        lines.add("KDF=" + file.kdf().wire());
        lines.add("KDF-PARAMS=" + file.kdfParams().wire());
        lines.add("SALT=" + B64.encodeToString(file.salt()));
        lines.add("NONCE=" + B64.encodeToString(file.nonce()));

        if (file.mode() == Mode.ENTERPRISE) {
            byte[] commit = file.epochCommit().orElseThrow(() ->
                    new IllegalStateException("enterprise file missing EPOCH-COMMIT"));
            lines.add("EPOCH-COMMIT=" + B64.encodeToString(commit));
            SealedFile.ChallengeBind cb = file.challengeBind()
                    .orElse(SealedFile.ChallengeBind.ENABLED);
            lines.add("CHALLENGE-BIND=" + cb.wire());
        }

        if (includeDigestAndHmac) {
            lines.add("AAD-DIGEST=" + B64.encodeToString(file.aadDigest()));
            if (file.mode() == Mode.TEAM || file.mode() == Mode.ENTERPRISE) {
                byte[] hmac = file.hmac().orElseThrow(() ->
                        new IllegalStateException(file.mode() + " file missing HMAC"));
                lines.add("HMAC=" + B64.encodeToString(hmac));
            }
        }

        lines.add("CREATED=" + file.created());
        file.rotated().ifPresent(r -> lines.add("ROTATED=" + r));
        return lines;
    }
}
