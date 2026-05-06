/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv;

import io.github.davidalmeidac.sealedenv.core.KdfAlgorithm;
import io.github.davidalmeidac.sealedenv.core.KdfParams;
import io.github.davidalmeidac.sealedenv.core.Mode;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException;
import io.github.davidalmeidac.sealedenv.core.SealedFile;
import io.github.davidalmeidac.sealedenv.format.SealedFileParser;
import io.github.davidalmeidac.sealedenv.totp.Totp;
import io.github.davidalmeidac.sealedenv.totp.UnsealToken;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * In-process smoke tests. Verifies that the Java implementation can seal +
 * unseal in all three modes without round-tripping through Node. Cross-stack
 * interop is tested separately in {@code CrossStackInteropTest}.
 */
class SealedEnvSmokeTest {

    private static byte[] hex(String h) {
        return HexFormat.of().parseHex(h);
    }

    /** Lower Argon2id parameters for fast tests — security-irrelevant here. */
    private static KdfParams fastParams() {
        return new KdfParams.Argon2id(1, 4096, 1);
    }

    @Nested
    @DisplayName("basic mode")
    class Basic {

        @Test
        @DisplayName("encrypt → decrypt roundtrip")
        void roundtrip() {
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "API_KEY=basic-secret\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.mode = Mode.BASIC;
            opts.kdfParams = fastParams();

            SealedEnv.SealResult result = SealedEnv.seal(opts);
            assertThat(result.serialized()).startsWith("SEALED-ENV-V1 MODE=basic");
            assertThat(result.serialized()).contains("\nKDF=argon2id\n");

            SealedFile parsed = SealedFileParser.parse(result.serialized());
            SealedEnv.UnsealOptions uOpts = new SealedEnv.UnsealOptions();
            uOpts.file = parsed;
            uOpts.masterKey = opts.masterKey;
            assertThat(new String(SealedEnv.unseal(uOpts), StandardCharsets.UTF_8))
                    .isEqualTo("API_KEY=basic-secret\n");
        }

        @Test
        @DisplayName("wrong master key fails to decrypt")
        void wrongKey() {
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "X=1\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.mode = Mode.BASIC;
            opts.kdfParams = fastParams();
            String serialized = SealedEnv.seal(opts).serialized();

            SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
            u.file = SealedFileParser.parse(serialized);
            u.masterKey = hex("bb".repeat(32));

            assertThatThrownBy(() -> SealedEnv.unseal(u))
                    .isInstanceOf(SealedEnvException.class)
                    .hasMessageContaining("corrupted, tampered, or wrong key");
        }
    }

    @Nested
    @DisplayName("team mode")
    class Team {

        @Test
        @DisplayName("encrypt → decrypt roundtrip")
        void roundtrip() {
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "TEAM_SECRET=hello\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.signingKey = hex("bb".repeat(32));
            opts.mode = Mode.TEAM;
            opts.kdfParams = fastParams();
            String serialized = SealedEnv.seal(opts).serialized();

            assertThat(serialized).contains("\nHMAC=");

            SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
            u.file = SealedFileParser.parse(serialized);
            u.masterKey = opts.masterKey;
            u.signingKey = opts.signingKey;
            assertThat(new String(SealedEnv.unseal(u), StandardCharsets.UTF_8))
                    .isEqualTo("TEAM_SECRET=hello\n");
        }

        @Test
        @DisplayName("wrong signing key is rejected")
        void wrongSigningKey() {
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "X=1\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.signingKey = hex("bb".repeat(32));
            opts.mode = Mode.TEAM;
            opts.kdfParams = fastParams();
            String serialized = SealedEnv.seal(opts).serialized();

            SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
            u.file = SealedFileParser.parse(serialized);
            u.masterKey = opts.masterKey;
            u.signingKey = hex("cc".repeat(32));

            assertThatThrownBy(() -> SealedEnv.unseal(u))
                    .isInstanceOf(SealedEnvException.class)
                    .hasMessageContaining("corrupted, tampered, or wrong key");
        }
    }

    @Nested
    @DisplayName("enterprise mode")
    class Enterprise {

        @Test
        @DisplayName("full flow: seal → build token → unseal")
        void fullFlow() {
            byte[] totpSecret = hex("0102030405060708090a0b0c0d0e0f1011121314");

            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "PROD_KEY=enterprise\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.signingKey = hex("bb".repeat(32));
            opts.totpSecret = totpSecret;
            opts.mode = Mode.ENTERPRISE;
            opts.challengeBind = true;
            opts.kdfParams = fastParams();
            String serialized = SealedEnv.seal(opts).serialized();
            assertThat(serialized).contains("\nTOTP-VERIFIER=");
            assertThat(serialized).contains("\nCHALLENGE-BIND=enabled\n");

            SealedFile file = SealedFileParser.parse(serialized);

            // Operator builds an unseal token using a freshly derived key
            byte[] derivedKey = io.github.davidalmeidac.sealedenv.crypto.CryptoPrimitives
                    .deriveMasterKey(opts.masterKey, file.salt(), file.kdfParams());
            String token = UnsealToken.build(new UnsealToken.BuildInput(
                    derivedKey, totpSecret, "deploy-abc123", 60));

            SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
            u.file = file;
            u.masterKey = opts.masterKey;
            u.signingKey = opts.signingKey;
            u.unsealToken = token;
            u.deployId = "deploy-abc123";

            assertThat(new String(SealedEnv.unseal(u), StandardCharsets.UTF_8))
                    .isEqualTo("PROD_KEY=enterprise\n");
        }

        @Test
        @DisplayName("wrong deploy_id is rejected with DEPLOY_MISMATCH")
        void wrongDeploy() {
            byte[] totpSecret = hex("0102030405060708090a0b0c0d0e0f1011121314");
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "X=1\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.signingKey = hex("bb".repeat(32));
            opts.totpSecret = totpSecret;
            opts.mode = Mode.ENTERPRISE;
            opts.kdfParams = fastParams();
            SealedEnv.SealResult sr = SealedEnv.seal(opts);

            byte[] derivedKey = io.github.davidalmeidac.sealedenv.crypto.CryptoPrimitives
                    .deriveMasterKey(opts.masterKey, sr.file().salt(), sr.file().kdfParams());
            String token = UnsealToken.build(new UnsealToken.BuildInput(
                    derivedKey, totpSecret, "deploy-A", 60));

            SealedEnv.UnsealOptions u = new SealedEnv.UnsealOptions();
            u.file = sr.file();
            u.masterKey = opts.masterKey;
            u.signingKey = opts.signingKey;
            u.unsealToken = token;
            u.deployId = "deploy-B";

            assertThatThrownBy(() -> SealedEnv.unseal(u))
                    .isInstanceOf(SealedEnvException.class)
                    .extracting("code")
                    .isEqualTo(SealedEnvException.Code.DEPLOY_MISMATCH);
        }
    }

    @Nested
    @DisplayName("TOTP")
    class TotpTests {

        @Test
        @DisplayName("verifyCode accepts the current code")
        void acceptsCurrent() {
            byte[] secret = hex("0102030405060708090a0b0c0d0e0f1011121314");
            long now = Instant.now().getEpochSecond();
            String code = Totp.generateCode(secret, now);
            Clock fixed = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
            assertThat(Totp.verifyCode(secret, code, fixed)).isTrue();
        }

        @Test
        @DisplayName("verifyCode rejects a wrong code")
        void rejectsWrong() {
            byte[] secret = hex("0102030405060708090a0b0c0d0e0f1011121314");
            assertThat(Totp.verifyCode(secret, "000000")).isFalse();
        }
    }

    @Nested
    @DisplayName("format parser")
    class Parser {

        @Test
        @DisplayName("rejects malformed magic line")
        void malformedMagic() {
            String bad = "NOT-SEALED\nKDF=scrypt\nKDF-PARAMS=N=1024,r=8,p=1\nSALT=AA==\nNONCE=AA==\n";
            assertThatThrownBy(() -> SealedFileParser.parse(bad))
                    .isInstanceOf(SealedEnvException.class);
        }

        @Test
        @DisplayName("rejects unknown mode")
        void unknownMode() {
            String bad =
                    "SEALED-ENV-V1 MODE=hacker\nKDF=scrypt\nKDF-PARAMS=N=1024,r=8,p=1\nSALT=AA==\nNONCE=AA==\n";
            assertThatThrownBy(() -> SealedFileParser.parse(bad))
                    .isInstanceOf(SealedEnvException.class);
        }

        @Test
        @DisplayName("accepts both scrypt and argon2id KDF tags")
        void acceptsBothKdfs() {
            // Java seals → argon2id; we just check the type round-trips
            SealedEnv.SealOptions opts = new SealedEnv.SealOptions();
            opts.plaintext = "X=1\n".getBytes(StandardCharsets.UTF_8);
            opts.masterKey = hex("aa".repeat(32));
            opts.mode = Mode.BASIC;
            opts.kdfParams = fastParams();
            SealedFile a = SealedFileParser.parse(SealedEnv.seal(opts).serialized());
            assertThat(a.kdf()).isEqualTo(KdfAlgorithm.ARGON2ID);

            opts.kdfParams = new KdfParams.Scrypt(1024, 1, 1);
            SealedFile s = SealedFileParser.parse(SealedEnv.seal(opts).serialized());
            assertThat(s.kdf()).isEqualTo(KdfAlgorithm.SCRYPT);
        }
    }
}
