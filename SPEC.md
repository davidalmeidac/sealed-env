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
| 5 | `EPOCH-COMMIT` | enterprise only | base64, 32 bytes (HMAC-SHA256 commitment to the salt-bound enterprise epoch — see §6) |
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
   - `enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")`.
   - `epoch_commit = HMAC-SHA256(derived_key, enterprise_epoch || "epoch-commit-v1")`.
   - The file commits to `epoch_commit`. The TOTP secret itself never appears
     in any persisted artifact (file or token). The salt binding ensures a
     leaked epoch is only useful against this specific file generation.
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
   - Verify `HMAC-SHA256(derived_key, token.epoch || "epoch-commit-v1") ==
     stored EPOCH-COMMIT`. Constant-time compare. The token carries
     `enterprise_epoch` (a salt-bound HMAC derivative of the operator's
     TOTP secret), NOT the TOTP secret itself.
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
  "epoch": "<base64-of-32-byte-enterprise-epoch>",
  "deploy_id": "<sha-256-of-commit-or-null>",
  "ops_id": "<random-uuid-v4>"
}
```

Where:

```
enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
```

The `enterprise_epoch` is a **salt-bound HMAC derivative** of the operator's
TOTP secret — never the secret itself. This is the central security property
of the unseal protocol: a leaked token (e.g., from CI logs, container env
dumps, or stack traces) does NOT give the attacker the TOTP secret. Without
the secret, the attacker cannot recompute `enterprise_epoch` for files with
a different salt (i.e., future re-sealings), so the blast radius of a
leaked token is bounded to the specific file generation that produced it.

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

## 11. Token format (canonical)

### 11.1 The reader's problem

A developer adopting `sealed-env` lands on this page asking one question:

> "I have a `.env.sealed` in CI. What single value do I paste into a CI
> secret so my app boots?"

Prior to v1's token format, the answer involved 2-3 separate environment
variables (`SEALED_ENV_KEY`, `SEALED_ENV_SIGNING_KEY`, optionally
`SEALED_ENV_TOTP_SECRET`). Operators routinely pasted them in the wrong
slot, forgot one, or shipped them via different channels and lost
correlation. The credential interface MUST be one paste, like a Stripe
`sk_live_*` key — complexity inside, simplicity outside.

The answer for v1 is a single string: `SEALED_ENV_TOKEN=sealed_env_<mode>_<checksum>_<payload>`.

This section is the canonical contract for that string. Node, Java, and
Rust implementations MUST produce and consume **byte-identical** tokens
from the same inputs.

### 11.2 Wire shape

```
sealed_env_<mode>_<checksum>_<payload>
```

| Component | Bytes | Description |
|-----------|-------|-------------|
| `sealed_env_` | 11 ASCII | Literal prefix. Never changes across format versions. Greppable in CI logs. |
| `<mode>` | 1 ASCII | One of `b`, `t`, `e`, `u`, `d`. See §11.6. |
| `_` | 1 ASCII | Separator. |
| `<checksum>` | 4 ASCII | Lowercase hex. See §11.4. |
| `_` | 1 ASCII | Separator. |
| `<payload>` | variable | base64url-no-padding of CBOR map. See §11.5. |

The prefix `sealed_env_` is **literal and version-stable**. A future
format revision will live inside `<mode>` / payload schema, not in the
prefix. This guarantees that grep rules in CI log scrubbers written in
2026 still match tokens emitted in 2030.

#### Mode characters

| `<mode>` | Tier | Meaning |
|----------|------|---------|
| `b` | A · Root | `basic` vault — master key only |
| `t` | A · Root | `team` vault — master + signing |
| `e` | A · Root | `enterprise` vault — master + signing + TOTP secret |
| `u` | A · Unseal | Re-wrap of the legacy JWS unseal token (see §9) |
| `d` | B · Deploy | Ephemeral deploy token (see §12) |

Tier A tokens are long-lived secrets that belong in a password manager,
KMS, or Studio keychain. Tier B tokens are short-lived (TTL ≤ 600s) and
designed to be pasted into CI per deploy.

### 11.3 Charset and length

- Allowed bytes in the entire token string: `[a-zA-Z0-9_-]`. This is the
  base64url alphabet plus `_` as a separator. The token survives shell
  quoting, environment variables, GitHub Actions secret rendering, and
  URL embedding without escaping.
- Maximum total length: **512 bytes**. This leaves headroom for the
  0.4.0 operator-identity extension (Ed25519 pubkey + signature add
  ~96 bytes) and future fields. Implementations MUST reject tokens
  longer than 512 bytes before any parsing.
- Minimum total length: `len("sealed_env_x_xxxx_") + len(shortest payload)`
  ≈ 30 bytes. A token shorter than this is structurally invalid.

### 11.4 Checksum

The checksum is **typo detection, NOT a security control.** Its only job
is to fail fast and loud when an operator pastes `sealed_env_t_…` with
one character corrupted by a shell, a chat client, or a copy-paste error.
The cryptographic gate that prevents forgery is the Tier B `sig` field
(§12.5) plus `exp` and optional `nonce` — not the checksum.

#### Formula

```
checksum_bytes = HMAC-SHA256(
  key   = "sealed-env:token-checksum:v1",
  msg   = payload_text                          ; see below
)[0:2]                                          ; first 2 bytes
checksum     = lowercase_hex(checksum_bytes)    ; 4 ASCII chars
```

Where `payload_text` is the **base64url-encoded payload STRING** — the
exact characters that appear in the token between the last `_` and the
end of the string. Implementations MUST NOT compute the checksum over
the raw CBOR bytes; the contract is over the wire-form payload string so
that a checksum mismatch correlates 1:1 with what the operator visually
sees.

The HMAC key `"sealed-env:token-checksum:v1"` is a domain-separation
literal. It is **public**. Its purpose is to prevent collisions with
HMACs used elsewhere in the protocol (e.g., the Tier B `sig`); it is not
a secret.

#### Reject behavior

If checksum mismatches, the implementation MUST reject the token
**before** any base64url decoding or CBOR parsing. The error class is
`TOKEN_INVALID` with cause `"checksum-mismatch"`. No timing-attack
discipline is required — this is a typo check.

### 11.5 Payload encoding

```
payload_text = base64url-no-padding( CBOR( mode_specific_map ) )
```

CBOR encoding MUST follow RFC 8949 §4.2.1 "Core Deterministic Encoding
Requirements":

1. Integers use shortest-form representation (no leading zero bytes).
2. Byte strings use major type 2 (no indefinite-length).
3. Text strings use major type 3 (no indefinite-length).
4. Maps use major type 5 with definite length (no indefinite-length).
5. Map keys are sorted by **bytewise lexicographic order of their
   canonical CBOR encoding**.
6. No tag wrappers unless explicitly required (none are in this version).

The deterministic ordering rule is the load-bearing one. Two
implementations encoding the same map MUST produce byte-identical CBOR.

#### Sort order for text-string keys (practical rule)

A CBOR text-string of length `n < 24` is encoded as `0x60+n` followed by
the UTF-8 bytes. Therefore, when all keys are short text strings:

1. **Shorter keys sort first.** A 2-char key precedes a 3-char key
   because `0x62 < 0x63`.
2. Within the same length, sort lexicographically on the UTF-8 bytes.

Examples:

```
"m"  (0x61 0x6d) < "s" (0x61 0x73) < "t" (0x61 0x74)
"ek" (length 2)
  < "exp", "sig" (length 3, "exp" < "sig" because 'e' < 's')
  < "nonce"    (length 5)
  < "vault_id" (length 8)
```

For text strings of length ≥ 24, the prefix becomes `0x78 <len>`; the
"shorter first" rule still holds. This format version uses no keys with
length ≥ 24.

### 11.6 Per-mode payload schemas

All keys are text strings. All cryptographic material is encoded as
byte strings (major type 2), never hex or base64.

#### Mode `b` — basic

```cbor
{
  "m": <bstr 32>      ; master_key
}
```

Canonical key order: `m`.

#### Mode `t` — team

```cbor
{
  "m": <bstr 32>,     ; master_key
  "s": <bstr 32>      ; signing_key
}
```

Canonical key order: `m, s` (both length 1; `m` < `s`).

#### Mode `e` — enterprise

```cbor
{
  "m": <bstr 32>,     ; master_key
  "s": <bstr 32>,     ; signing_key
  "t": <bstr 20>      ; totp_secret (RFC 6238)
}
```

Canonical key order: `m, s, t`.

#### Mode `u` — unseal

A wire-form re-wrap of the legacy JWS Compact unseal token described in
§9. The CBOR map carries the same payload fields plus the detached
signature as a separate byte-string field. Reading and writing this mode
is a non-breaking translation: a `u`-mode token can be losslessly
serialized back to the JWS Compact form for legacy verifiers, and vice
versa.

```cbor
{
  "iss":       <tstr>,     ; "sealed-env-cli"
  "iat":       <uint>,     ; unix seconds
  "exp":       <uint>,     ; unix seconds
  "epoch":     <tstr>,     ; standard-base64 of 32-byte enterprise_epoch
                           ; (same encoding as the JWS payload field, NOT base64url)
  "deploy_id": <tstr | null>,
  "ops_id":    <tstr>,     ; UUID v4
  "sig":       <bstr 32>   ; HMAC-SHA256(derived_key, base64url(header)+"."+base64url(payload))
                           ; recomputed when re-wrapping
}
```

Canonical key order per §11.5. Lengths are 3 (`iat`, `exp`, `iss`,
`sig`), 5 (`epoch`), 6 (`ops_id`), 9 (`deploy_id`). Within length 3:
`e` (0x65) < `i` (0x69) < `s` (0x73), and `iat` < `iss` lexicographically.
Final order: **exp, iat, iss, sig, epoch, ops_id, deploy_id**.

Implementations MUST NOT use the JWT `alg=none` shortcut. The `sig` field
is mandatory and verified per §9.

#### Mode `d` — deploy (Tier B)

See §12.5 for the full deploy-mode contract. The CBOR map is:

```cbor
{
  "ek":       <bstr 32>,   ; ephemeral derived key (= derived_key, see §12.5)
  "exp":      <uint>,      ; unix seconds — token expiry
  "sig":      <bstr 32>,   ; HMAC-SHA256 over payload-without-sig (see §12.5)
  "nonce":    <bstr 16>,   ; replay protection (always present)
  "vault_id": <bstr 32>    ; SHA-256("sealed-env:vault-id:v1" || salt), see §12.4
}
```

Canonical key order: **ek, exp, sig, nonce, vault_id**.

Derivation: `ek` is length 2, all others ≥ 3, so `ek` is first. Within
length-3 keys `exp` < `sig` (`e` 0x65 < `s` 0x73). Then `nonce` (5) and
`vault_id` (8). Final order matches.

### 11.7 Parser algorithm

A conformant reader MUST execute the steps in this exact order. Each
step has a single, named reject point. The reject point determines the
error class surfaced to the caller.

```
INPUT: token (UTF-8 bytes)

1. len(token) ≤ 512 ............................. else TOKEN_INVALID(too-long)
2. token starts with "sealed_env_" .............. else TOKEN_INVALID(bad-prefix)
3. every byte ∈ [a-zA-Z0-9_-] ................... else TOKEN_INVALID(bad-charset)
4. split on "_" → ["sealed","env",mode,cksum,payload_text]
   ............................................. else TOKEN_INVALID(bad-shape)
5. mode ∈ {"b","t","e","u","d"} ................. else TOKEN_INVALID(bad-mode)
6. len(cksum)==4 ∧ cksum matches §11.4 .......... else TOKEN_INVALID(checksum-mismatch)
7. cbor_bytes = base64url-decode(payload_text) .. else TOKEN_INVALID(bad-base64)
8. map = cbor-decode(cbor_bytes), deterministic . else TOKEN_INVALID(bad-cbor)
9. validate map against mode schema (§11.6) ..... else TOKEN_INVALID(bad-payload)
10. mode == "d" → §12.7 verify procedure
    mode == "u" → §9 verify procedure
    mode ∈ {b,t,e} → use keys to decrypt .env.sealed per §7
```

The single user-facing error message remains the §7 rule:
`"sealed-env: file is corrupted, tampered, or wrong key"`. The
fine-grained `cause` codes above are for telemetry and operator
debugging only — they MUST NOT be exposed in untrusted contexts.

Step 4 splits on `_` from the left and stops after the first 5 fields:
the payload alphabet is base64url which uses `-` and never `_`, so the
`_` separator parsing is unambiguous.

### 11.8 Forward compatibility

Readers MUST silently ignore **unknown CBOR map keys** in the payload.
A future version may add operator-identity (`signer_id`, `signer_sig`)
or workload-identity (`oidc_aud`) fields; existing readers parse them
into "the rest" and continue with the keys they understand.

What forward-compat does NOT cover:

- A new `<mode>` character. New modes require a reader upgrade. Tokens
  with unknown modes are rejected at step 5 of §11.7.
- A breaking change to an existing key's type or semantics. This would
  ship as a new mode character, not a key reinterpretation.
- The wire prefix `sealed_env_`. That is permanent.

### 11.9 Backward compatibility

Implementations MUST continue to read vaults whose credentials are
delivered via the legacy environment variables:

| Legacy env var | Vault mode | Status |
|----------------|------------|--------|
| `SEALED_ENV_KEY` | basic, team, enterprise | DEPRECATED — supported through 0.x |
| `SEALED_ENV_SIGNING_KEY` | team, enterprise | DEPRECATED — supported through 0.x |
| `SEALED_ENV_TOTP_SECRET` | enterprise | DEPRECATED — supported through 0.x |
| `SEALED_ENV_UNSEAL_TOKEN` | enterprise (unseal) | DEPRECATED — supported through 0.x |

Precedence rules:

1. If `SEALED_ENV_TOKEN` is set, parse it per §11.7. Use its keys. Ignore
   any legacy variables present in the environment.
2. Else if any legacy variable is set, use the legacy flow. Emit a
   **one-time stderr warning** containing the literal substring
   `"legacy-credential-format"` plus a link to the `sealed-env
   migrate-token` command.
3. Else fail with a clear "no credentials provided" message that
   mentions `SEALED_ENV_TOKEN`.

The legacy path is **scheduled for removal in 1.0.0**. The 0.x line
honors it. No new features land in the legacy path.

### 11.10 Test vectors

The byte-identical fixtures for §11 live at
`test-vectors/v1/credential-modernization-*.json`. Each fixture file is
self-describing (see its schema below) and references the SPEC
subsection it exercises. The fixture suite covers every reject point in
§11.7 plus the happy path for every mode.

#### 11.10.1 Fixture schema

```jsonc
{
  "name": "<filename without .json>",
  "purpose": "<one-line description>",
  "spec_section": "§11.x or §12.x",
  "vault": {
    "salt_hex": "<32 hex>",
    "master_key_hex": "<64 hex>",
    "signing_key_hex": "<64 hex, omit for basic>",
    "totp_secret_hex": "<40 hex, omit for non-enterprise>",
    "serialized": "<full .env.sealed contents or reference>"
  },
  "token": "<sealed_env_*_*_* | null>",
  "config_file_contents": "<.sealed-env.config.json contents | null>",
  "expected": {
    "result": "decrypt_ok | reject_pre_decrypt | reject_sig_fail |
               reject_vault_mismatch | reject_expired | reject_replay |
               parse_ok_ignore_unknown | decrypt_ok_with_warning",
    "plaintext_hex": "<hex if decrypt_ok>",
    "error_class": "<TOKEN_INVALID | TOKEN_EXPIRED | CONFIG_ERROR | ...>",
    "error_cause": "<specific cause from §11.7>",
    "warning_substring": "<for legacy-still-works>"
  }
}
```

The full fixture roster is enumerated in §12.10.

## 12. Deploy mode and ephemeral tokens (canonical)

### 12.1 Motivation — Tier A vs Tier B

A long-lived root credential pasted into a CI secret is a security smell.
If GitHub Actions logs leak, if a developer's laptop is compromised, or
if the CI provider itself is breached, the attacker walks away with the
ability to decrypt every `.env.sealed` produced from that vault — forever
or until the operator notices and rotates. Long-lived `sealed_env_t_*`
tokens belong in password managers and KMS, not in CI runners.

Tier B introduces a **short-lived deploy token**:

| Tier | Token prefix | TTL | Storage | CI? |
|------|--------------|-----|---------|-----|
| A · Root | `sealed_env_{b,t,e}_*` | infinite | password manager / KMS / Studio keychain | only if `deploy_mode=static` |
| B · Deploy | `sealed_env_d_*` | 60s – 600s | one-shot env var per deploy | yes — designed for this |

The operator mints a Tier B token from a Tier A unlock on their local
machine (CLI prompts for passphrase + TOTP if enterprise), pastes it into
the CI run's environment as `SEALED_ENV_DEPLOY_TOKEN`, the deploy runs,
the token expires. A leaked deploy token grants exactly one decrypt
window of N seconds against exactly one vault.

### 12.2 `.sealed-env.config.json` schema

A new file sits next to `.env.sealed`. It is **committable** — it
contains no secret material. It records the operator's deploy policy
for this vault.

```json
{
  "deploy_mode": "ephemeral",
  "deploy_ttl_max_seconds": 60,
  "require_totp_on_mint": false,
  "allow_long_lived_for_dev": true,
  "nonce_state_backend": null
}
```

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `deploy_mode` | enum | see §12.3 | `static` / `ephemeral` / `workload-identity`. CLI rejects tokens of insufficient tier. |
| `deploy_ttl_max_seconds` | int | `60` | Operator-chosen ceiling on `--ttl`. Max permitted by the format: `600`. CLI MUST refuse `--ttl` values above this field. |
| `require_totp_on_mint` | bool | `false` (`true` for enterprise vaults) | Forces 6-digit TOTP entry on every `mint-deploy`. |
| `allow_long_lived_for_dev` | bool | `true` | If `false`, the local operator cannot decrypt with a Tier A token directly; they MUST mint a Tier B token even for local development. |
| `nonce_state_backend` | string \| null | `null` | URI of a Redis/DynamoDB backend that records seen nonces. When set, the reader enforces single-use across CI jobs. When `null`, only TTL bounds replay. |

#### Validation rules

1. Unknown top-level fields MUST be **silently ignored** for forward
   compatibility with 0.4.0 (which adds `require_signed_tokens`,
   `authorized_signers`, and similar identity fields).
2. `deploy_ttl_max_seconds` outside `[1, 600]` is a config error
   (`CONFIG_ERROR`, cause `"ttl-out-of-range"`).
3. `deploy_mode` not in `{"static", "ephemeral", "workload-identity"}`
   is a config error (`CONFIG_ERROR`, cause `"bad-deploy-mode"`).
4. For an **enterprise** vault, `deploy_mode == "static"` is a config
   error (cause `"enterprise-requires-ephemeral"`). See §12.3.
5. Missing fields take the defaults in the table above.

### 12.3 Default `deploy_mode` per vault mode

| Vault mode | Default `deploy_mode` | Rationale |
|------------|------------------------|-----------|
| `basic` | `static` | Hobby / solo dev. Preserve original simplicity. Operator may opt up to `ephemeral`. |
| `team` | `static` | Operator may opt up to `ephemeral`. |
| `enterprise` | `ephemeral` **MANDATORY** | The TOTP requirement already implies human-in-the-loop per deploy; long-lived tokens annul that threat model. A `.sealed-env.config.json` declaring `deploy_mode: "static"` for an enterprise vault MUST be rejected as invalid. |

The CLI's `init` command MUST write a `.sealed-env.config.json` with the
appropriate defaults at vault creation time.

### 12.4 Vault ID

Every Tier B token names the vault it was minted against. The reader
verifies the name before doing any cryptography. The vault name is
deterministic from the file's public salt.

```
vault_id = SHA-256( "sealed-env:vault-id:v1" || salt )
```

- `"sealed-env:vault-id:v1"` is a 23-byte ASCII literal (no NUL
  terminator). It provides domain separation so that `vault_id` cannot
  be confused with any other SHA-256 output in the protocol.
- `salt` is the raw 16-byte salt from the `.env.sealed` header (the
  decoded value of the `SALT=` line), not the base64 form.
- Output is the full 32-byte SHA-256 digest.

#### Vault ID is NOT a secret

`vault_id` is a **scoping identifier**, not a security boundary. It is:

1. **Publicly derivable.** The salt it commits to is already visible
   in cleartext in the `.env.sealed` file header. Anyone with the
   `.env.sealed` can compute the `vault_id` in one SHA-256.
2. **Designed to be visible in Tier B tokens.** A deploy token names
   the vault it targets; that name is on the wire by design.
3. **Not relied on for integrity or authenticity.** The cryptographic
   gate that prevents forgery is the `sig` field (§12.5) combined with
   `exp` (§12.7 step 3) and the optional nonce check (§12.8). Removing
   `vault_id` from a forged token would not make it accepted; rewriting
   `vault_id` to point at a different vault would not bypass `sig`
   either, because `sig` is computed over the bytes that include
   `vault_id`.

Implementations MUST NOT treat `vault_id` as authenticating anything on
its own. Its only job is to fail fast and loud when an operator pastes
a deploy token meant for vault A into a deploy of vault B.

### 12.5 Tier B payload

Recall the wire-form schema (§11.6, mode `d`):

```cbor
{
  "ek":       <bstr 32>,
  "exp":      <uint>,
  "sig":      <bstr 32>,
  "nonce":    <bstr 16>,
  "vault_id": <bstr 32>
}
```

#### Field semantics

| Field | Purpose |
|-------|---------|
| `ek` | The 32-byte AES-256-GCM key the verifier uses to decrypt the body of `.env.sealed`. See "Ephemeral key interpretation" below. |
| `exp` | Unsigned unix seconds. The instant past which the reader MUST reject the token. |
| `sig` | HMAC-SHA256 binding `ek`, `exp`, `nonce`, `vault_id` to the master key + salt. Forgery gate. |
| `nonce` | Per-mint random 16 bytes. Always present on the wire. Used by §12.8 if a state backend is configured; advisory otherwise. |
| `vault_id` | Per §12.4. Scoping identifier. |

#### Ephemeral key interpretation (locked)

```
ek = derived_key
```

Where `derived_key` is the same 32-byte output produced by §6 step 3 of
this SPEC (the KDF applied to the master key with the file's salt and
KDF params). **The Tier B token wraps the derived key behind a TTL and a
signature.** This is the simplest viable design and was chosen over an
HKDF-with-fresh-nonce variant for three reasons:

1. **No extra wire field.** No `derivation_nonce` to carry.
2. **No extra computation.** Verifier already computes `derived_key` for
   normal decrypts.
3. **The TTL is the freshness gate.** A leaked Tier B token grants
   decrypts only until `exp`. After `exp`, the token is dead even
   though `derived_key` is unchanged. To rotate the underlying key, the
   operator runs `sealed-env rotate`, which generates a fresh salt and
   therefore a fresh `derived_key`.

Compromise scope: a captured Tier B token = N seconds of decrypt
capability against one vault. Rotating the vault (new salt) invalidates
every outstanding Tier B token for that vault — they reference the old
`vault_id`.

#### Signature derivation

The `sig` field binds the other four fields to the master key.

```
hmac_key = HKDF-SHA256(
  IKM    = master_key,
  salt   = salt,
  info   = "sealed-env:deploy-sig:v1",
  length = 32
)

payload_without_sig = CBOR-encode-deterministic({
  "ek":       <ek>,
  "exp":      <exp>,
  "nonce":    <nonce>,
  "vault_id": <vault_id>
})        ; key order per §11.5: ek, exp, nonce, vault_id

sig = HMAC-SHA256(hmac_key, payload_without_sig)
```

The wire-form payload contains all five keys (including `sig`) sorted
per §11.5: **ek, exp, sig, nonce, vault_id**. The verifier reconstructs
`payload_without_sig` by re-encoding the map with the `sig` key removed
(four keys, sorted as **ek, exp, nonce, vault_id**) and re-running the
HMAC. The recomputation MUST be byte-identical to the minter's encoding;
this is why deterministic CBOR per §11.5 is mandatory and not advisory.

The HKDF `info` string `"sealed-env:deploy-sig:v1"` is a public
domain-separation literal. It ensures the `sig` HMAC key cannot collide
with any other HMAC key derived from the same master+salt elsewhere in
the protocol.

### 12.6 Mint procedure

`sealed-env mint-deploy --vault <path> --ttl <duration>` performs:

```
INPUT: vault path, requested ttl, operator credentials (Tier A unlock)

1. Read .env.sealed → extract salt, kdf_params.
2. Read .sealed-env.config.json (sibling). Validate per §12.2.
3. requested_ttl ≤ config.deploy_ttl_max_seconds .... else CONFIG_ERROR(ttl-cap)
4. If config.require_totp_on_mint, prompt for 6-digit code; verify per §9.
5. derived_key = KDF(master_key, salt, kdf_params)        ; §6 step 3
6. nonce      = randomBytes(16)
7. now        = current unix seconds
8. exp        = now + requested_ttl
9. vault_id   = SHA-256("sealed-env:vault-id:v1" || salt) ; §12.4
10. ek        = derived_key                               ; §12.5
11. payload_without_sig = cbor({ek, exp, nonce, vault_id})
12. hmac_key  = HKDF(master_key, salt, "sealed-env:deploy-sig:v1", 32)
13. sig       = HMAC-SHA256(hmac_key, payload_without_sig)
14. payload   = cbor({ek, exp, sig, nonce, vault_id})
15. token     = "sealed_env_d_" || hex(HMAC(...)[0:2]) || "_" || base64url(payload)  ; §11.4
16. Emit token on stdout. Do NOT log to any file.
```

The mint procedure MUST run entirely in process memory. No intermediate
artifact (especially not `derived_key` or `ek`) is written to disk.

### 12.7 Verify procedure

`sealed-env decrypt` with `SEALED_ENV_DEPLOY_TOKEN` set performs:

```
INPUT: vault path, deploy token, optional config

1. Parse token per §11.7 steps 1-9 ............. errors as defined there.
2. mode == "d" ................................. else TOKEN_INVALID(wrong-mode)
3. exp > now ................................... else TOKEN_EXPIRED
4. Read .env.sealed → salt, kdf_params, ciphertext.
5. local_vault_id = SHA-256("sealed-env:vault-id:v1" || salt)
6. constant_time_compare(token.vault_id, local_vault_id)
   ............................................. else TOKEN_INVALID(vault-mismatch)
7. If config.nonce_state_backend is set:
     If backend.has_seen(token.nonce) ........... → TOKEN_INVALID(replay)
     backend.record(token.nonce, ttl=exp-now)
   (If the backend itself errors, fail closed: TOKEN_INVALID, cause
    "replay-cache-unavailable". This mirrors §SEC-006 fail-closed
    semantics for the unseal replay cache.)
8. hmac_key = HKDF(master_key, salt, "sealed-env:deploy-sig:v1", 32)
   payload_without_sig = re-encode the CBOR map without "sig" (§11.5)
   expected_sig = HMAC-SHA256(hmac_key, payload_without_sig)
   constant_time_compare(token.sig, expected_sig)
   ............................................. else TOKEN_INVALID(sig)
9. enc_key  = HKDF(token.ek, salt, "sealed-env:v1:enc", 32)  ; §6 step 4
10. plaintext = AES-256-GCM-decrypt(enc_key, nonce, ciphertext, aad)
    ............................................. else per §7 step 8
```

The signature check at step 8 MUST use a constant-time comparison
(e.g. Node `crypto.timingSafeEqual`, Java `MessageDigest.isEqual`, Rust
`subtle::ConstantTimeEq`). The `vault_id` check at step 6 SHOULD also
use a constant-time comparison; it is not strictly load-bearing for
authenticity (see §12.4), but constant-time keeps the implementation
uniformly disciplined.

Note that step 8 requires the verifier to hold the **master key**, not
just `ek`. This is intentional: a Tier B verifier needs the master key
in process memory to authenticate the deploy token, then uses `ek` only
to derive the AES key. The master key arrives by the same path it does
today (`SEALED_ENV_KEY` or, post-§11, the `m` field of a Tier A
`sealed_env_t_*` companion token). When the Tier A side is itself
unavailable (workload-identity scenario), the master key arrives via the
minter service per §12.9.

### 12.8 Replay protection

`nonce` is **always** on the wire. Whether replay is enforced depends
on the vault's `.sealed-env.config.json`:

| `nonce_state_backend` | Effect |
|------------------------|--------|
| `null` (default) | Replay bounded only by TTL. Re-using a token within `[now, exp)` succeeds. Suitable for short TTLs (≤ 60s) where the replay window is operationally negligible. |
| `<redis-uri>` or `<dynamodb-uri>` | The reader records every consumed nonce in the backend keyed by `(vault_id, nonce)` with TTL = `exp - now`. A second presentation of the same nonce is rejected at step 7 of §12.7. |

The state backend MUST support atomic check-and-set semantics. A
non-atomic check followed by a separate write is vulnerable to a TOCTOU
race in concurrent deploys.

This is opt-in for two reasons:

1. **Operational cost.** Many deployments do not have a shared
   Redis/DynamoDB available, especially solo-dev setups.
2. **Fail-closed footprint.** When the backend is configured but
   unavailable, decrypt MUST fail (cause `"replay-cache-unavailable"`).
   That tradeoff is correct for high-stakes deploys and excessive for
   hobby projects.

The reader MUST emit a one-time stderr warning containing the literal
substring `"deploy-replay-disabled"` when `nonce_state_backend` is
`null` AND `deploy_mode == "ephemeral"`, so operators of
ephemeral-but-stateless deploys learn that they are relying on TTL
alone.

### 12.9 Workload identity (informative, future)

> **Status:** non-normative for 0.3.0. Sketch only. A separate PR will
> spec the minter service in detail.

For CI pipelines that want neither long-lived secrets nor manual
operator-in-the-loop minting, the workload-identity mode looks like:

```
GitHub Actions OIDC token
          │
          ▼
     Minter service (lambda / cloud function)
          │  validates OIDC claims (repo, ref, env)
          │  holds Tier A credentials in cloud KMS
          │  mints sealed_env_d_* with short TTL
          ▼
     CI run uses token, decrypts, deploys
```

Properties:

- The minter service is **not** shipped with `sealed-env` core. It is
  stack-agnostic and lives as a reference implementation + recipes.
- The CI pipeline never holds Tier A material; it only ever holds a
  fresh Tier B token bounded by TTL.
- The minter validates OIDC claims (e.g. only the `main` branch of
  `org/repo` can mint a production deploy token).

This section will become normative in a future SPEC revision. For
0.3.0, `deploy_mode: "workload-identity"` is a reserved value: readers
that encounter it MUST refuse with `CONFIG_ERROR`, cause
`"workload-identity-not-implemented"`, until the minter contract is
specified.

### 12.10 Test vectors

The byte-identical fixtures for §11 and §12 live at
`test-vectors/v1/credential-modernization-*.json`. Each fixture has the
schema documented in §11.10.1. The roster:

| Filename | `expected.result` | Exercises |
|----------|-------------------|-----------|
| `credential-modernization-basic-valid.json` | `decrypt_ok` | §11.6 mode `b`, §11.7 happy path |
| `credential-modernization-team-valid.json` | `decrypt_ok` | §11.6 mode `t`, §11.7 happy path |
| `credential-modernization-enterprise-valid.json` | `decrypt_ok` | §11.6 mode `e`, Tier A unlock |
| `credential-modernization-tier-b-deploy-valid.json` | `decrypt_ok` | §12.5–§12.7 happy path |
| `credential-modernization-wrong-checksum.json` | `reject_pre_decrypt` | §11.4 typo detection |
| `credential-modernization-tampered-payload.json` | `reject_sig_fail` | §12.5 / §12.7 step 8 |
| `credential-modernization-wrong-vault-id.json` | `reject_vault_mismatch` | §12.4 / §12.7 step 6 |
| `credential-modernization-expired.json` | `reject_expired` | §12.7 step 3 |
| `credential-modernization-replay-after-nonce-seen.json` | `reject_replay` | §12.7 step 7 / §12.8 |
| `credential-modernization-future-fields-ignored.json` | `parse_ok_ignore_unknown` | §11.8 forward-compat |
| `credential-modernization-legacy-key-still-works.json` | `decrypt_ok_with_warning` | §11.9 backward-compat |

All fixtures use FIXED key material so reruns are byte-stable:

| Material | Value |
|----------|-------|
| `master_key_hex` | `aa` × 32 (32 bytes of 0xaa) |
| `signing_key_hex` | `bb` × 32 |
| `totp_secret_hex` | `cc` × 20 |
| `salt_hex` | `00` × 16 (matches existing `enterprise-token-malformed-epoch.json`) |
| Tier B `exp` (valid) | `4102444800` (2100-01-01T00:00:00Z) |
| Tier B `exp` (expired) | `1000000000` (2001-09-09) |
| Tier B `nonce` | `11` × 16 |

The generator script `node/scripts/gen-credential-modernization-vectors.mjs`
produces all 11 fixtures deterministically. It contains its own minimal
CBOR encoder (no npm dependency) covering the major types used here and
asserts byte-equality across a double-encode pass before writing.

## 13. Implementation conformance test vectors

A reference set of test vectors lives in `/test-vectors/v1/` (separate
directory in the repo). Each vector contains:
- `input.env` — plaintext
- `master.key` — fixed test key
- `output.env.sealed` — expected file (deterministic with mocked salt+nonce)
- `decrypt-result.txt` — expected plaintext after roundtrip

**Both Node and Java implementations MUST pass all vectors before release.**

## 14. Versioning

This is `SEALED-ENV-V1`. Future versions:

- `V2` will be incompatible. Readers seeing `V2` magic but only supporting
  `V1` MUST refuse with `"sealed-env: file format too new, upgrade your library"`.
- `V1` writers MUST NOT emit fields not specified here, even if known.

## 15. Out of scope (this version)

- Streaming encryption (entire file is encrypted/decrypted in one pass)
- Multi-recipient encryption (use age or PGP for that use case)
- Asymmetric encryption (we use symmetric throughout)
- Hardware-backed keys (planned for v2)
- Quantum-resistant primitives (planned for v3 when standards stabilize)

## 16. References

- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) — AEAD interface
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) — TOTP
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) — password hashing
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — GCM mode
