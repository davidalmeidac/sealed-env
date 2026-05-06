# `.env.sealed` File Format Specification — v1

**Status:** Draft 1
**Last updated:** 2026-05-05
**Authors:** David Almeida

This document specifies the binary layout, cryptographic primitives, and
operational semantics of the `.env.sealed` file format, version 1.

Both the Node.js and Java implementations of `sealed-env` MUST follow this
specification exactly. A file written by the Node implementation MUST be
readable by the Java implementation, and vice versa.

---

## 1. Goals

1. **Cross-stack interoperability.** Node and Java teams share the same file.
2. **Tamper-evident.** Modification of the ciphertext or metadata is detected.
3. **Self-describing.** The file declares its mode and parameters, no out-of-band config.
4. **Human-greppable header.** Engineers can `cat` it and know the version/mode.
5. **Forward-compatible.** v2 must coexist with v1 readers (which gracefully refuse).

## 2. File layout (high level)

```
+-----------------------------------------------------------+
| LINE 1   Magic + version + mode                           |
| LINE 2-N Metadata (key=value, ASCII, one per line)        |
| LINE N+1 Empty line (separator)                           |
| LINE N+2 Body (one base64-encoded ciphertext line)        |
+-----------------------------------------------------------+
```

The file is **plain UTF-8 text**. No binary bytes. This is intentional:
- `git diff` shows changed lines
- A reviewer can spot fishy header changes
- Editors and pipes work without surprises

## 3. Magic line (line 1)

```
SEALED-ENV-V1 MODE=<mode>
```

Where `<mode>` is one of:

| Mode value | Description |
|------------|-------------|
| `basic` | AES-256-GCM only. Master key = sole secret. |
| `team` | Adds explicit HMAC + audit log. |
| `enterprise` | Adds TOTP-based unseal token bound to a deploy challenge. |

Readers MUST reject the file if:
- The magic prefix is not exactly `SEALED-ENV-V1` (case-sensitive)
- The mode is unknown
- The line ends with characters other than the listed format

## 4. Metadata (lines 2..N)

A series of `KEY=VALUE` lines. The order is significant for HMAC computation
(see §6). Lines MUST appear in the order listed below; missing optional fields
are simply skipped (the order remains stable).

| # | Key | Required in mode | Format |
|---|-----|------------------|--------|
| 1 | `KDF` | all | One of `argon2id`, `scrypt` |
| 2 | `KDF-PARAMS` | all | For argon2id: `t=<int>,m=<int>,p=<int>`. For scrypt: `N=<int>,r=<int>,p=<int>` |
| 3 | `SALT` | all | base64, 16 bytes raw |
| 4 | `NONCE` | all | base64, 12 bytes raw |
| 5 | `TOTP-VERIFIER` | enterprise only | base64, 32 bytes (HMAC-SHA256 commitment) |
| 6 | `CHALLENGE-BIND` | enterprise only | `enabled` or `disabled` |
| 7 | `AAD-DIGEST` | all | base64, 32 bytes (SHA-256 of associated data) |
| 8 | `HMAC` | team and enterprise | base64, 32 bytes |
| 9 | `CREATED` | all | ISO-8601 UTC timestamp |
| 10 | `ROTATED` | optional | ISO-8601 UTC timestamp; absent if never rotated |

Key names are uppercase ASCII with hyphens. Values do not contain `=`, `\n`, or
spaces. Whitespace around `=` is NOT allowed.

## 5. Cryptographic primitives

| Primitive | Choice | Parameters |
|-----------|--------|------------|
| Symmetric cipher | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit auth tag |
| Key derivation | **Argon2id** (preferred) or **scrypt** (interim) | argon2id default: t=3, m=65536, p=4 · scrypt default: N=32768, r=8, p=1 |
| Subkey derivation | HKDF-SHA256 | RFC 5869, info strings listed in §6 |
| Integrity (team mode) | HMAC-SHA256 | over concatenation defined in §6 |
| TOTP (enterprise mode) | RFC 6238 | SHA-1, 30s step, 6 digits, ±1 step skew |
| Random | OS CSPRNG | `crypto.randomBytes` in Node, `SecureRandom.getInstanceStrong()` in Java |

**Forbidden:** AES-CBC, PBKDF2, MD5, SHA-1 (except inside RFC 6238 TOTP),
PKCS#1 v1.5 padding, custom RNG.

## 6. Encryption procedure

### Inputs
- `master_key` (operator-provided, ≥32 bytes after KDF) — base material
- `plaintext` (the contents of the original `.env`)
- `mode` (`basic` | `team` | `enterprise`)
- For enterprise: `totp_secret` (20 bytes random)
- For team/enterprise: `signing_key` (operator-provided, separate from master)

### Steps

1. Generate `salt = randomBytes(16)`.
2. Generate `nonce = randomBytes(12)`.
3. `derived_key = argon2id(master_key, salt, kdf_params)` → 32 bytes.
4. `enc_key = HKDF(derived_key, salt=salt, info="sealed-env:v1:enc", L=32)`.
5. `aad = utf8(magic_line || metadata_canonical_form)`.
   `aad_digest = SHA-256(aad)`.
6. `ciphertext_with_tag = AES-256-GCM-encrypt(enc_key, nonce, plaintext, aad)`.
7. If `mode == enterprise`:
   - `totp_verifier = HMAC-SHA256(derived_key, totp_secret || "verify-v1")`.
8. If `mode in (team, enterprise)`:
   - `mac_key = HKDF(signing_key, salt=salt, info="sealed-env:v1:mac", L=32)`.
   - `hmac = HMAC-SHA256(mac_key, magic_line || metadata_without_HMAC || ciphertext_with_tag)`.
9. Write file in the layout of §2 with all metadata fields populated.

### Canonical form

The "metadata canonical form" used in step 5 is the metadata lines joined by
`\n` (Unix newline), with NO trailing newline, in the order specified in §4.
Always exclude the `HMAC` line itself when computing the HMAC over metadata.

## 7. Decryption procedure

### Inputs
- File path
- `master_key` (env var `SEALED_ENV_KEY`)
- For team/enterprise: `signing_key` (env var `SEALED_ENV_SIGNING_KEY`)
- For enterprise: `unseal_token` (env var `SEALED_ENV_UNSEAL_TOKEN`)

### Steps

1. Parse file, fail if magic line malformed.
2. Validate `mode` matches expectation (or accept what file declares).
3. Reconstitute `derived_key` via Argon2id over master_key + parsed salt.
4. **HMAC verification (team+):** recompute HMAC and compare with
   `crypto.timingSafeEqual` (Node) / `MessageDigest.isEqual` (Java).
   Fail loud if mismatch.
5. **Enterprise unseal verification:**
   - Parse the unseal token (JWT-like, see §9).
   - Verify token signature with `derived_key`.
   - Verify `token.exp > now`.
   - Verify `HMAC-SHA256(derived_key, token.totp_secret || "verify-v1") ==
     stored TOTP-VERIFIER`. Constant-time compare.
   - If `CHALLENGE-BIND=enabled`: verify `token.deploy_id` matches the
     current deploy challenge (provided by CI as `SEALED_ENV_DEPLOY_ID`).
6. **AAD reconstruction:** rebuild `aad` from magic + metadata (excluding HMAC),
   compute SHA-256, compare with stored `AAD-DIGEST`. Fail if mismatch.
7. `enc_key = HKDF(derived_key, salt, "sealed-env:v1:enc", 32)`.
8. `plaintext = AES-256-GCM-decrypt(enc_key, nonce, ciphertext_with_tag, aad)`.
   GCM authentication failure → fail loud.
9. Parse `plaintext` as a standard `.env` file (KEY=value lines, comments
   starting with `#`, quoted values, escapes per dotenv conventions).

### Failure modes

All decryption failures MUST surface a single error message: `"sealed-env:
file is corrupted, tampered, or wrong key"`. Do NOT leak which step failed —
that's a side-channel for attackers probing keys.

## 8. KDF parameters (`KDF-PARAMS`)

Format: `t=<int>,m=<int>,p=<int>` where:

- `t` — iterations (Argon2 `time_cost`)
- `m` — memory in KB (Argon2 `memory_cost`)
- `p` — parallelism (Argon2 `parallelism`)

Defaults (suitable for desktop hardware in 2026):

```
t=3, m=65536 (64 MB), p=4
```

For CI runners with limited memory, operators may write files with reduced
params (e.g. `t=4, m=16384, p=2`). Readers MUST honor whatever is in the file.

Recommended minimum: `t=2, m=16384, p=1`.

## 9. Unseal token format (enterprise mode)

The unseal token is a compact, signed payload that the operator generates
locally and the application verifies at startup.

### Structure (JWS Compact Serialization, no JWT alg quirks)

```
usl_<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

**Header:**
```json
{ "alg": "HS256", "typ": "sealed-env-unseal/v1" }
```

**Payload:**
```json
{
  "iss": "sealed-env-cli",
  "iat": 1717024500,
  "exp": 1717024560,
  "totp_secret": "<base64-of-totp-seed>",
  "deploy_id": "<sha-256-of-commit-or-null>",
  "ops_id": "<random-uuid-v4>"
}
```

**Signature:**
`HMAC-SHA256(derived_key, base64url(header) + "." + base64url(payload))`

### Constraints

- `exp - iat ≤ 600` seconds (max 10 minutes lifetime)
- `ops_id` must be unique; readers SHOULD maintain a short-term replay cache
- If `CHALLENGE-BIND=enabled`, `deploy_id` MUST be present and verified

## 10. Security properties (claims)

A correctly implemented reader/writer pair guarantees:

1. **Confidentiality.** Without `master_key`, the ciphertext is
   indistinguishable from random under chosen-plaintext attack.
2. **Integrity.** Any modification of header, metadata, or ciphertext is
   detected at decryption time (GCM tag + optional HMAC + AAD digest).
3. **Mode-binding.** A `basic` file cannot be silently parsed as `enterprise`
   to bypass TOTP — the `mode` is part of the AAD.
4. **No replay across deploys** (enterprise + CHALLENGE-BIND). A captured
   unseal token is only valid for its bound deploy.
5. **Forward secrecy on rotation.** After `rotate`, old files cannot be
   decrypted with the new key (and vice versa). Old files should be deleted.

## 11. Implementation conformance test vectors

A reference set of test vectors lives in `/test-vectors/v1/` (separate
directory in the repo). Each vector contains:
- `input.env` — plaintext
- `master.key` — fixed test key
- `output.env.sealed` — expected file (deterministic with mocked salt+nonce)
- `decrypt-result.txt` — expected plaintext after roundtrip

**Both Node and Java implementations MUST pass all vectors before release.**

## 12. Versioning

This is `SEALED-ENV-V1`. Future versions:

- `V2` will be incompatible. Readers seeing `V2` magic but only supporting
  `V1` MUST refuse with `"sealed-env: file format too new, upgrade your library"`.
- `V1` writers MUST NOT emit fields not specified here, even if known.

## 13. Out of scope (this version)

- Streaming encryption (entire file is encrypted/decrypted in one pass)
- Multi-recipient encryption (use age or PGP for that use case)
- Asymmetric encryption (we use symmetric throughout)
- Hardware-backed keys (planned for v2)
- Quantum-resistant primitives (planned for v3 when standards stabilize)

## 14. References

- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) — AEAD interface
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) — TOTP
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) — password hashing
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — GCM mode
