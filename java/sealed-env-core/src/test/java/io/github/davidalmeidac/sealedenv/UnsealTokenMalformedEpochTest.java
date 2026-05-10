/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.davidalmeidac.sealedenv.core.SealedEnvException;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException.Code;
import io.github.davidalmeidac.sealedenv.crypto.CryptoPrimitives;
import io.github.davidalmeidac.sealedenv.totp.UnsealToken;

import com.fasterxml.jackson.databind.JsonNode;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SEC-007 mirror test: Java's Base64.getDecoder() MUST reject tokens whose
 * payload.epoch contains characters outside the standard base64 alphabet.
 *
 * <p>Mirrors the Node test in {@code node/tests/totp/token-base64-strict.test.ts}.
 * Both stacks MUST throw TOKEN_INVALID for the same class of malformed input.
 */
class UnsealTokenMalformedEpochTest {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final ObjectMapper JSON = new ObjectMapper();

    // Deterministic key material matching the Node tests
    private static final byte[] DERIVED_KEY = hexBytes("a".repeat(64));
    private static final byte[] TOTP_SECRET = hexBytes("c".repeat(40));
    private static final byte[] SALT = hexBytes("0".repeat(32)); // 16 zero bytes

    /** Build a valid token, then tamper the epoch field and re-sign. */
    private static String buildTamperedToken(String injectedPrefix) throws Exception {
        // Build a valid token with minimal TTL
        long now = System.currentTimeMillis() / 1000L;
        ObjectNode header = JSON.createObjectNode();
        header.put("alg", "HS256");
        header.put("typ", "sealed-env-unseal/v1");

        // Compute enterprise epoch
        byte[] tag = "epoch-v1".getBytes(StandardCharsets.UTF_8);
        byte[] saltAndTag = new byte[SALT.length + tag.length];
        System.arraycopy(SALT, 0, saltAndTag, 0, SALT.length);
        System.arraycopy(tag, 0, saltAndTag, SALT.length, tag.length);
        byte[] epochBytes = CryptoPrimitives.hmacSha256(TOTP_SECRET, saltAndTag);
        String epochB64 = Base64.getEncoder().encodeToString(epochBytes);

        ObjectNode payload = JSON.createObjectNode();
        payload.put("iss", "sealed-env-cli");
        payload.put("iat", now);
        payload.put("exp", now + 60);
        // Inject the bad prefix into epoch
        payload.put("epoch", injectedPrefix + epochB64);
        payload.putNull("deploy_id");
        payload.put("ops_id", "test-ops-id");

        String headerB64 = URL_ENCODER.encodeToString(JSON.writeValueAsBytes(header));
        String payloadB64 = URL_ENCODER.encodeToString(JSON.writeValueAsBytes(payload));

        byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.UTF_8);
        byte[] sig = CryptoPrimitives.hmacSha256(DERIVED_KEY, signingInput);

        return "usl_" + headerB64 + "." + payloadB64 + "." + URL_ENCODER.encodeToString(sig);
    }

    @Test
    @DisplayName("tab in epoch → TOKEN_INVALID (SEC-007)")
    void rejectsTabInEpoch() throws Exception {
        String tampered = buildTamperedToken("\t");
        assertThatThrownBy(() ->
                UnsealToken.verify(new UnsealToken.VerifyInput(
                        tampered, DERIVED_KEY, null, false))
        )
                .isInstanceOf(SealedEnvException.class)
                .satisfies(e -> assertThat(((SealedEnvException) e).code())
                        .isEqualTo(Code.TOKEN_INVALID));
    }

    @Test
    @DisplayName("newline in epoch → TOKEN_INVALID (SEC-007)")
    void rejectsNewlineInEpoch() throws Exception {
        String tampered = buildTamperedToken("\n");
        assertThatThrownBy(() ->
                UnsealToken.verify(new UnsealToken.VerifyInput(
                        tampered, DERIVED_KEY, null, false))
        )
                .isInstanceOf(SealedEnvException.class)
                .satisfies(e -> assertThat(((SealedEnvException) e).code())
                        .isEqualTo(Code.TOKEN_INVALID));
    }

    @Test
    @DisplayName("non-base64 char (!) in epoch → TOKEN_INVALID (SEC-007)")
    void rejectsInvalidCharInEpoch() throws Exception {
        String tampered = buildTamperedToken("!");
        assertThatThrownBy(() ->
                UnsealToken.verify(new UnsealToken.VerifyInput(
                        tampered, DERIVED_KEY, null, false))
        )
                .isInstanceOf(SealedEnvException.class)
                .satisfies(e -> assertThat(((SealedEnvException) e).code())
                        .isEqualTo(Code.TOKEN_INVALID));
    }

    @Test
    @EnabledIf("crossStackVectorAvailable")
    @DisplayName("cross-stack vector: enterprise-token-malformed-epoch.json → TOKEN_INVALID")
    void rejectsMalformedEpochCrossStackVector() throws Exception {
        Path vectorPath = Path.of("..", "..", "test-vectors", "v1",
                "enterprise-token-malformed-epoch.json");
        JsonNode v = JSON.readTree(Files.readString(vectorPath, StandardCharsets.UTF_8));
        String token = v.get("token").asText();
        byte[] derivedKey = HexFormat.of().parseHex(v.get("derivedKeyHex").asText());

        assertThatThrownBy(() ->
                UnsealToken.verify(new UnsealToken.VerifyInput(token, derivedKey, null, false))
        )
                .isInstanceOf(SealedEnvException.class)
                .satisfies(e -> assertThat(((SealedEnvException) e).code())
                        .isEqualTo(Code.TOKEN_INVALID));
    }

    static boolean crossStackVectorAvailable() {
        return Files.exists(Path.of("..", "..", "test-vectors", "v1",
                "enterprise-token-malformed-epoch.json"));
    }

    // Helper

    private static byte[] hexBytes(String hex) {
        return HexFormat.of().parseHex(hex);
    }
}
