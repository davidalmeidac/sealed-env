# sealed-env Secret Patterns

This document is the canonical specification of every sensitive string
sealed-env emits or consumes, intended for integration with secret-scanning
tools (gitleaks, trufflehog, GitHub Secret Scanning Partner Program,
GitGuardian community detectors, etc.).

If you maintain a secret-scanning tool and want to add sealed-env coverage,
this is the file you should mirror. The patterns here are **stable** —
any breaking change to a regex will be announced in `CHANGELOG.md` under
a `[BREAKING]` heading and tagged `secret-patterns` in the release.

---

## Quick reference

| ID | Description | Prefix | Length | Charset |
|---|---|---|---|---|
| `SE-T1` | Credential token (basic/team/enterprise/unseal/deploy) | `sealed_env_<mode>_` | 48–512 | base64url + `_` separators |
| `SE-T2` | Unseal token (TOTP-bound, HS256) | `usl_` | 200–512 | base64url + `.` separators |
| `SE-K1` | Master key (env var) | `SEALED_ENV_KEY=` | 64 hex chars | `[0-9a-fA-F]` |
| `SE-K2` | Signing key (env var) | `SEALED_ENV_SIGNING_KEY=` | 64 hex chars | `[0-9a-fA-F]` |
| `SE-K3` | TOTP secret (env var) | `SEALED_ENV_TOTP_SECRET=` | 16–64 base32 chars | `[A-Z2-7]+={0,6}` |

If a string matches any pattern in this table, **treat it as a high-severity
secret leak**. None of these values are intended to appear in source control,
logs, public dashboards, or shared documents.

---

## SE-T1 — Credential Token

Used to authenticate to `sealed-env` operations (basic/team/enterprise modes)
or to issue an unseal request. The token's payload is base64url-encoded CBOR
and may contain the master key, the signing key, or — historically, in
versions affected by CVE-2026-45091 — the operator's TOTP secret.

**Severity if leaked**: critical. Possession of any non-expired token grants
full ability to decrypt the corresponding `.env.sealed` file, subject only
to replay-cache deduplication and (for unseal-mode tokens) salt binding.

### Regex (Perl-compatible)

```
sealed_env_[btued]_[0-9a-fA-F]{4}_[A-Za-z0-9_-]{20,500}
```

### Structure

```
sealed_env_<mode>_<cksum>_<payload>
            │      │       └── base64url(CBOR(payload_map))
            │      └── 4 hex chars (2-byte HMAC checksum, lowercase)
            └── single ASCII letter: b | t | e | u | d
```

| Mode | Meaning | Carries (in payload CBOR map) |
|---|---|---|
| `b` | Basic mode credential | `m` = master key (32-byte raw) |
| `t` | Team mode credential | `m` + `s` (signing key, 32-byte raw) |
| `e` | Enterprise mode credential | `m` + `s` + (pre-CVE-2026-45091 only) `t` (TOTP secret) |
| `u` | Unseal token (legacy CBOR form, pre-`usl_`) | `iss` + `ops_id` + `sig` |
| `d` | Deploy token | `ek` + `exp` + `sig` + `nonce` + `vault_id` |

### Positive examples (will match)

```
sealed_env_b_c0dd_oWFtWCCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg
sealed_env_t_9ccb_omFtWCCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmF
sealed_env_e_7ddf_o2FtWCCqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmFzWCC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u2F0VMzMzMzMzMzMzMzMzMzMzMzMzMzM
sealed_env_d_fe9d_pWJla1gghM8TfZPBuN1CE86hBnPlN-ovwTNsgDxnawCl8by6gcBjZXhwGvSGVwBjc2lnWCCGJ_VhXLSAzNqBT5zDR-E4JFctflkdoaJIBe7UOid1xw
```

### Negative examples (must NOT match)

```
sealed_env_x_abcd_payload          # invalid mode 'x'
sealed_env_b_GGGG_payload          # invalid checksum chars
sealed_env_b_c0dd_short            # payload too short
sealed-env-b-c0dd-payload          # dash separators (wrong format)
SEALED_ENV_b_c0dd_payload          # wrong case on prefix
prefix_sealed_env_b_c0dd_payload   # not at boundary
```

### Length cap

Per `SPEC §11.7 step 1`, tokens are capped at 512 chars total. A
candidate longer than 512 is rejected at parse time. Detectors MAY
also use this as an upper bound to reduce backtracking.

---

## SE-T2 — Unseal Token

JWS-shaped token (HS256) used in enterprise mode to authorize a single
`unseal` operation against a specific salted `.env.sealed` file. Payload
contains a salt-bound HMAC derivative of the TOTP secret — never the
TOTP secret itself (post-CVE-2026-45091).

**Severity if leaked**: high. A leaked unseal token is replay-protected
(opsId is single-use) and TTL-bound (≤ 600s), but a freshly captured
token within its TTL grants one decrypt attempt against the bound salt.

### Regex (Perl-compatible)

```
usl_[A-Za-z0-9_-]{40,200}\.[A-Za-z0-9_-]{40,400}\.[A-Za-z0-9_-]{40,100}
```

### Structure

```
usl_<header_b64>.<payload_b64>.<sig_b64>
     │            │              └── base64url(HMAC-SHA256(derivedKey, header||"."||payload))
     │            └── base64url(JSON{iss, iat, exp, epoch, deploy_id, ops_id})
     └── base64url(JSON{alg:"HS256", typ:"sealed-env-unseal/v1"})
```

### Positive example (will match)

```
usl_eyJhbGciOiJIUzI1NiIsInR5cCI6InNlYWxlZC1lbnYtdW5zZWFsL3YxIn0.eyJpc3MiOiJzZWFsZWQtZW52LWNsaSIsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjoxNzY3MjI2MjAwLCJlcG9jaCI6IlpKVFA3TmZRZUFwa3JBMD0iLCJkZXBsb3lfaWQiOm51bGwsIm9wc19pZCI6IjAxSEFHWlpUWiJ9.qgzqvHrmZCS69Tm-ahGU_QEsoRfOT_jjIZSR-XIm6Y8
```

### Negative examples (must NOT match)

```
usl_short                          # too short, no dots
usl_a.b.c                          # parts too short
usl_aaaa.bbbb.cccc                 # parts still too short (entropy floor)
USL_eyJ...                         # wrong case
xusl_eyJ...                        # not at boundary
```

### False-positive mitigation

The `usl_` prefix is short (4 chars including underscore). To reduce false
positives, the regex requires:

1. Three base64url sections separated by literal `.`
2. Each section at least 40 chars (typical real tokens are 50+/150+/43)
3. No characters outside the base64url alphabet inside sections

A 3-second sanity check after a candidate match: decode the **first**
section as base64url → parse as JSON → confirm `alg === "HS256"` and
`typ === "sealed-env-unseal/v1"`. This is the recommended **verifier**
step for GitHub Secret Scanning Partner submissions.

---

## SE-K1 — Master Key

The symmetric AES-GCM key that decrypts a `.env.sealed` file. Lives in
`.env.local` or a secret manager during local dev; on CI/production it
is mounted via the platform's secret store and consumed via the
`SEALED_ENV_KEY` env var.

**Severity if leaked**: critical. The master key alone is sufficient to
decrypt any file sealed in `basic` mode and to bypass `team` mode HMAC
when combined with a leaked signing key. Enterprise mode requires the
TOTP secret on top, but the master key remains a primary credential.

### Regex (Perl-compatible)

```
SEALED_ENV_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?
```

The captured group `\1` is the secret material.

### Positive examples (will match)

```
SEALED_ENV_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SEALED_ENV_KEY="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
SEALED_ENV_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
```

### Negative examples (must NOT match)

```
SEALED_ENV_KEY=<your_key_here>     # placeholder, not hex
SEALED_ENV_KEY=abc                 # too short
# SEALED_ENV_KEY=0123...           # commented out (gitleaks default: still flagged — that's correct)
EXAMPLE_KEY=0123...                # wrong var name
```

### Notes

- The hex form is the canonical encoding. sealed-env CLIs accept exactly
  64 hex chars (32 bytes); anything else throws `CONFIG_ERROR`.
- The `<your_key_here>` placeholder convention is documented in README
  and is the recommended marker for example values in shared docs.
- Detectors SHOULD strip surrounding quotes when reporting the match.

---

## SE-K2 — Signing Key

A 32-byte HMAC key used in `team` and `enterprise` modes to sign the
sealed file body (independent from the master key, so a master-key leak
does not by itself permit tampering).

**Severity if leaked**: high. Combined with a leaked master key, allows
arbitrary tampering. On its own, allows forging valid HMACs but not
decryption.

### Regex (Perl-compatible)

```
SEALED_ENV_SIGNING_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?
```

### Positive examples (will match)

```
SEALED_ENV_SIGNING_KEY=babababababababababababababababababababababababababababababababa
SEALED_ENV_SIGNING_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
```

### Negative examples (must NOT match)

Same shape as SE-K1: any non-64-hex value, placeholders, or wrong var name.

---

## SE-K3 — TOTP Secret

The base32-encoded shared secret used as the second factor in enterprise
mode (RFC 6238 TOTP). Typically 16, 26, or 32 base32 characters depending
on the operator's authenticator app preferences (16 = 80-bit, 32 = 160-bit
per RFC 4226).

**Severity if leaked**: critical (in enterprise mode). Combined with a
master key, fully defeats the second-factor property.

### Regex (Perl-compatible)

```
SEALED_ENV_TOTP_SECRET\s*[=:]\s*["']?([A-Z2-7]{16,64}={0,6})(?![A-Z2-7])["']?
```

The captured group `\1` is the secret material.

### Positive examples (will match)

```
SEALED_ENV_TOTP_SECRET=JBSWY3DPEHPK3PXP
SEALED_ENV_TOTP_SECRET="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SEALED_ENV_TOTP_SECRET=ORSXG5BAONUGCZDPO5XXEZJB
```

### Negative examples (must NOT match)

```
SEALED_ENV_TOTP_SECRET=<paste_otpauth_secret_here>     # placeholder
SEALED_ENV_TOTP_SECRET=jbswy3dpehpk3pxp                # lowercase (not RFC 4648 base32)
GOOGLE_TOTP_SECRET=JBSWY3DPEHPK3PXP                    # different var
SEALED_ENV_TOTP_SECRET=                                # empty value
```

### Notes

- Base32 with padding (`=`) is accepted but uncommon for TOTP secrets
  shorter than 40 chars.
- RFC 4648 base32 charset is `[A-Z2-7]`; lowercase variants exist but
  sealed-env normalizes to uppercase on input and emits uppercase only.
- Detectors flagging this pattern should also flag any nearby
  `otpauth://` URI as the same secret in a different encoding (covered
  by a separate, optional pattern `SE-K3-URI` if vendors want it —
  see "Optional extensions" below).

---

## Optional extensions

These are not part of the core 5 patterns but may be useful for some
vendors:

### `SE-K3-URI` — `otpauth://` URI containing the TOTP secret

```
otpauth://totp/[^?]*\?[^"\s]*secret=([A-Z2-7]{16,64}={0,6})
```

Used by `sealed-env init --mode enterprise` to render the QR code for
the operator to scan into their authenticator app. Carries the same
`SEALED_ENV_TOTP_SECRET` value in the `secret=` query parameter.

### `SE-K1-RAW-BASE64` — master key in base64 form

sealed-env's wire format **never** uses base64 for the master key —
hex is the only accepted form. This pattern is intentionally **NOT**
specified to avoid false positives against arbitrary base64 strings.

---

## How to test your detector against this spec

A reference corpus lives at:

```
tests/secret-patterns/positive/   ← these MUST match
tests/secret-patterns/negative/   ← these MUST NOT match
```

(The corpus is added in a follow-up commit; this spec is the source of
truth, the corpus is the executable validation.)

Acceptable detector performance:

- **Recall on positives**: 100% (every documented positive case must match).
- **Precision on negatives**: 100% (no documented negative case may match).
- **Backtracking budget**: each regex must complete in < 10ms on a 10MB
  input on a 2024-era laptop. If your regex flavor doesn't support
  bounded quantifiers, switch to a verifier pass.

---

## Reporting a missed leak or a false positive

If you find a real leak in the wild that this spec didn't catch, or a
false positive on a clearly non-sealed-env string, open a GitHub issue
on the sealed-env repo titled:

```
[secret-patterns] <SE-T1|SE-T2|SE-K1|SE-K2|SE-K3> {missed|fp} — <short description>
```

Include the literal string (redacted if real), the file/context where
it appeared, and which tool reported it (or failed to). We treat
these as P1 — secret detectors that cry wolf erode operator trust;
silent misses are worse.

---

## Design notes — why these specific regex shapes

Two design choices worth flagging for downstream maintainers:

**1. `[=:]` instead of `=` only.** Secrets get leaked in YAML
(docker-compose, kubernetes manifests, GitHub Actions workflow files)
as often as in `.env` files. The character class catches both
`KEY=value` (dotenv) and `KEY: value` (YAML) without hurting
precision — the surrounding hex/base32 constraints already eliminate
generic config lines from matching.

**2. Negative lookahead after the captured hex/base32 block.**
A regex like `[0-9a-fA-F]{64}` happily matches the first 64 chars of
an 80-char hex string. That's a false positive: the operator likely
pasted a wrong value or duplicated the key. The lookahead
`(?![0-9a-fA-F])` rejects strings whose hex run continues past 64,
preserving precision without losing recall on real 64-char keys.

## Version history

| Date | Version | Change |
|---|---|---|
| 2026-05-22 | 1.0 | Initial publication. 5 core patterns + 1 optional extension. |
