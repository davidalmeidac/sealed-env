# Gitleaks upstream PR — sealed-env detection rules

This directory contains the source-of-truth files for the upstream
contribution to [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks),
adding the 6 secret patterns that `sealed-env` emits or consumes.

## What gets submitted upstream

| File in this dir | Destination in gitleaks/gitleaks |
|---|---|
| `sealed_env.go` | `cmd/generate/config/rules/sealed_env.go` |
| (entry in registry) | `cmd/generate/config/main.go` (add `rules.SealedEnvCredentialToken()` etc. alphabetically) |

## How to submit

```bash
# 1. Fork gitleaks/gitleaks under your account via the UI

# 2. Clone YOUR fork
git clone https://github.com/davidalmeidac/gitleaks.git /tmp/gitleaks-fork
cd /tmp/gitleaks-fork

# 3. Branch
git checkout -b add-sealed-env-rules

# 4. Copy the rule file
cp /path/to/sealed-env/tools/gitleaks-upstream-pr/sealed_env.go \
   cmd/generate/config/rules/sealed_env.go

# 5. Edit cmd/generate/config/main.go and add the 6 rule functions
#    alphabetically. Look for other Sxxx() entries and slot in:
#       rules.SealedEnvCredentialToken(),
#       rules.SealedEnvMasterKey(),
#       rules.SealedEnvSigningKey(),
#       rules.SealedEnvTotpOtpauthUri(),
#       rules.SealedEnvTotpSecret(),
#       rules.SealedEnvUnsealToken(),

# 6. Regenerate the TOML
make config/gitleaks.toml

# 7. Run tests
go test ./...

# 8. Commit and push to your fork
git add cmd/generate/config/rules/sealed_env.go cmd/generate/config/main.go config/gitleaks.toml
git commit -m "feat(rules): add sealed-env detection rules"
git push origin add-sealed-env-rules

# 9. Open an issue first describing the request:
#    https://github.com/gitleaks/gitleaks/issues/new
#    Title: "Add detection rules for sealed-env (npm + Maven Central)"
#    Body: see issue template below

# 10. Open the PR referencing the issue
#     https://github.com/gitleaks/gitleaks/compare/master...davidalmeidac:gitleaks:add-sealed-env-rules
```

## Issue template (paste when opening the GitHub issue)

```markdown
## Request: Add detection rules for sealed-env

[sealed-env](https://github.com/davidalmeidac/sealed-env) is an
open-source cross-stack (Node.js + Java + planned Rust) library for
encrypted `.env` files, published on npm and Maven Central.

A self-disclosed CVE last month (CVE-2026-45091, CVSS 9.1) reinforced
the importance of secret-pattern detection for the library's tokens
and keys — operators occasionally leak these in `.env.local` files
or CI logs.

I maintain a canonical regex specification at
[SECRET-PATTERNS.md](https://github.com/davidalmeidac/sealed-env/blob/main/SECRET-PATTERNS.md),
which is the source of truth for our own `sealed-env scan` CLI,
and would like to upstream the same 6 patterns into gitleaks' default
config:

- `SE-T1`: credential tokens (`sealed_env_<mode>_<cksum>_<payload>`)
- `SE-T2`: unseal tokens (`usl_<header>.<payload>.<sig>`)
- `SE-K1`: master key in env var (`SEALED_ENV_KEY=<64 hex>`)
- `SE-K2`: signing key in env var (`SEALED_ENV_SIGNING_KEY=<64 hex>`)
- `SE-K3`: TOTP secret in env var (`SEALED_ENV_TOTP_SECRET=<base32>`)
- `SE-K3-URI`: TOTP secret in `otpauth://` URI

PR follows. All rules ship with true-positive and false-positive
test cases derived from a corpus of 30 + 64 cases in our own repo
(100% recall / 100% precision verified).

Happy to iterate on the regex shapes if you'd prefer different
helpers or stricter entropy thresholds.
```

## PR template (paste when opening the PR)

```markdown
Closes #<issue-number>.

Adds 6 detection rules for [sealed-env](https://github.com/davidalmeidac/sealed-env),
an open-source cross-stack library (Node + Java, on npm + Maven Central)
for encrypted `.env` files. The maintainer self-disclosed CVE-2026-45091
last month, which is why the patterns warrant default-config inclusion
rather than living in a personal config.

## Rules added

| RuleID | Catches |
|---|---|
| `sealed-env-credential-token` | `sealed_env_<mode>_<cksum>_<payload>` |
| `sealed-env-unseal-token` | `usl_<header>.<payload>.<sig>` |
| `sealed-env-master-key` | `SEALED_ENV_KEY=<64 hex>` |
| `sealed-env-signing-key` | `SEALED_ENV_SIGNING_KEY=<64 hex>` |
| `sealed-env-totp-secret` | `SEALED_ENV_TOTP_SECRET=<base32>` |
| `sealed-env-totp-otpauth-uri` | `otpauth://totp/...?secret=<base32>` |

Each rule has true-positive samples derived from real test vectors and
false-positive cases that ensure placeholders, partial matches, and
look-alike patterns don't trigger.

Canonical spec: <https://github.com/davidalmeidac/sealed-env/blob/main/SECRET-PATTERNS.md>

## Testing

```bash
go test ./...
make config/gitleaks.toml  # regenerates the default TOML
```

The regenerated TOML diff is included; it adds 6 new `[[rules]]`
blocks alphabetically.
```

## What stays out of this PR

- `SE-K3-URI` (otpauth:// URI) is the only "optional extension" in our
  SECRET-PATTERNS.md. It's included here because the QR-render in
  `sealed-env init --mode enterprise` outputs an otpauth:// URI that
  some operators paste into chat / Slack / GitHub issues.
- We do **not** ship a generic PyPI token detector here — gitleaks
  already has `pypi-upload-token` rule, and our `SE-K4` (PyPI in
  `.pypirc`) is sealed-env-specific tooling that doesn't belong
  upstream.
- We do **not** modify any existing gitleaks rule.
