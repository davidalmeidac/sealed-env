/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.davidalmeidac.sealedenv.core.KdfAlgorithm;
import io.github.davidalmeidac.sealedenv.core.Mode;
import io.github.davidalmeidac.sealedenv.core.SealedFile;
import io.github.davidalmeidac.sealedenv.crypto.CryptoPrimitives;
import io.github.davidalmeidac.sealedenv.format.SealedFileParser;
import io.github.davidalmeidac.sealedenv.totp.UnsealToken;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-stack interop: take a {@code .env.sealed} file written by the Node
 * implementation and verify Java can decrypt it.
 *
 * <p>Tests are auto-skipped if the {@code test-vectors/v1/} directory is not
 * present (e.g. on a Java-only checkout). The {@code node} sibling project
 * regenerates vectors via {@code node scripts/gen-test-vector.mjs}.
 */
class CrossStackInteropTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Path VECTORS_DIR = Path.of("..", "..", "test-vectors", "v1");

    static boolean vectorsAvailable() {
        return Files.isDirectory(VECTORS_DIR);
    }

    private JsonNode loadVector(String name) throws Exception {
        Path p = VECTORS_DIR.resolve(name);
        return JSON.readTree(Files.readString(p, StandardCharsets.UTF_8));
    }

    @Test
    @EnabledIf("vectorsAvailable")
    @DisplayName("Java unseals a Node-sealed basic file")
    void javaReadsNodeBasic() throws Exception {
        JsonNode v = loadVector("node-basic.json");
        SealedFile file = SealedFileParser.parse(v.get("serialized").asText());

        // Sanity: Node honestly declares scrypt
        assertThat(file.kdf()).isEqualTo(KdfAlgorithm.SCRYPT);

        SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
        u.file = file;
        u.masterKey = HexFormat.of().parseHex(v.get("masterKeyHex").asText());

        byte[] plaintext = SealedEnv.unseal(u);
        assertThat(new String(plaintext, StandardCharsets.UTF_8))
                .isEqualTo(v.get("plaintext").asText());
    }

    @Test
    @EnabledIf("vectorsAvailable")
    @DisplayName("Java unseals a Node-sealed team file (HMAC roundtrip)")
    void javaReadsNodeTeam() throws Exception {
        JsonNode v = loadVector("node-team.json");
        SealedFile file = SealedFileParser.parse(v.get("serialized").asText());
        assertThat(file.kdf()).isEqualTo(KdfAlgorithm.SCRYPT);
        assertThat(file.hmac()).isPresent();

        SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
        u.file = file;
        u.masterKey = HexFormat.of().parseHex(v.get("masterKeyHex").asText());
        u.signingKey = HexFormat.of().parseHex(v.get("signingKeyHex").asText());

        byte[] plaintext = SealedEnv.unseal(u);
        assertThat(new String(plaintext, StandardCharsets.UTF_8))
                .isEqualTo(v.get("plaintext").asText());
    }

    @Test
    @EnabledIf("vectorsAvailable")
    @DisplayName("Java unseals a Node-sealed enterprise file (TOTP token roundtrip)")
    void javaReadsNodeEnterprise() throws Exception {
        JsonNode v = loadVector("node-enterprise.json");
        SealedFile file = SealedFileParser.parse(v.get("serialized").asText());
        assertThat(file.mode()).isEqualTo(Mode.ENTERPRISE);
        assertThat(file.kdf()).isEqualTo(KdfAlgorithm.SCRYPT);
        assertThat(file.hmac()).isPresent();
        assertThat(file.epochCommit()).isPresent();

        byte[] masterKey = HexFormat.of().parseHex(v.get("masterKeyHex").asText());
        byte[] signingKey = HexFormat.of().parseHex(v.get("signingKeyHex").asText());
        byte[] totpSecret = HexFormat.of().parseHex(v.get("totpSecretHex").asText());

        // Build the unseal token from the file's salt + the master key + the
        // TOTP secret committed in the vector. This is exactly what an
        // operator's CLI would do at deploy time. The salt MUST be passed
        // because the token's `epoch` is HMAC(totpSecret, salt || tag).
        byte[] derivedKey = CryptoPrimitives.deriveMasterKey(
                masterKey, file.salt(), file.kdfParams());
        String token = UnsealToken.build(new UnsealToken.BuildInput(
                derivedKey, totpSecret, file.salt(),
                /* deployId */ null, /* ttlSeconds */ 60));

        SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
        u.file = file;
        u.masterKey = masterKey;
        u.signingKey = signingKey;
        u.unsealToken = token;
        // CHALLENGE-BIND=disabled in the vector, so deployId is not required.

        byte[] plaintext = SealedEnv.unseal(u);
        assertThat(new String(plaintext, StandardCharsets.UTF_8))
                .isEqualTo(v.get("plaintext").asText());
    }
}
