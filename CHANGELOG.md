# Changelog

All notable changes to `sealed-env` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The wire format (`SEALED-ENV-V1`) follows its own stability commitment:
files written today will remain readable forever. See [SPEC.md](./SPEC.md).

---

## [Unreleased]

---

## [0.1.0-alpha.4] — 2026-05-07

> **🚨 SECURITY: this release fixes a critical issue in `enterprise` mode.
> Prior versions (alpha.1, alpha.2, alpha.3) embedded the operator's TOTP
> secret in the JWS payload of every unseal token. JWS payload is base64-
> encoded JSON, NOT encrypted — anyone observing a token (CI logs, container
> env dumps, stack traces) could extract the secret and use it (with the
> master key) to mint unseal tokens for FUTURE deploys indefinitely.**
>
> **All `0.1.0-alpha.{1,2,3}` releases are deprecated on npm and Maven
> Central. If you adopted enterprise mode in any of those versions:**
>
> 1. **Rotate your TOTP secret.** Re-run `sealed-env init --mode enterprise`.
> 2. **Re-seal all `.env.sealed` files.** Old files use the deprecated wire
>    field (`TOTP-VERIFIER`) and won't decrypt with `0.1.0-alpha.4`.
> 3. **Update CI / production env to use the new package version.**
>
> The wire format intentionally breaks compatibility — files sealed before
> alpha.4 are NOT readable by alpha.4. Since the package was not yet adopted
> in the wild (only the author's own dogfooding), this seemed safer than a
> backward-compatible code path that would silently keep reading the
> insecure field on old files.

### Security

- **CRITICAL: TOTP secret no longer appears in unseal tokens.** The token
  payload now carries an `enterprise_epoch`:
  ```
  enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
  ```
  This is a salt-bound HMAC derivative — knowing it does NOT let an
  attacker recompute it for files with a different salt. The blast radius
  of a leaked token is reduced from "permanent compromise of all current
  and future enterprise files" to "compromise of one specific file
  generation, until re-seal".

- **Wire format field renamed:** `TOTP-VERIFIER` → `EPOCH-COMMIT`. The new
  field commits to the salt-bound epoch instead of the raw TOTP secret:
  ```
  epoch_commit = HMAC-SHA256(derived_key, enterprise_epoch || "epoch-commit-v1")
  ```

- **Token payload field renamed:** `totp_secret` → `epoch`. Old field is
  rejected. Any code or test that referenced the old field will fail at
  parse time, surfacing the upgrade as a hard error rather than silent
  insecurity.

- **Regression tests added** that fail if either:
  - The serialized file contains `TOTP-VERIFIER`, or
  - A minted token contains the literal TOTP secret in any common encoding
    (hex or base64), or the field name `totp_secret`.

### Migration

This release is **incompatible with files sealed by `0.1.0-alpha.{1,2,3}`**.
To migrate:

```sh
# 1. Decrypt with the old version
npx sealed-env@0.1.0-alpha.3 decrypt .env.sealed > /tmp/.env.plaintext

# 2. Upgrade
npm i -D sealed-env@0.1.0-alpha.4

# 3. Re-init keys (TOTP secret rotation is mandatory)
sealed-env init --mode enterprise

# 4. Re-seal with the new keys
sealed-env encrypt /tmp/.env.plaintext --mode enterprise

# 5. Securely wipe the plaintext
shred -u /tmp/.env.plaintext   # or: rm -P on macOS
```

### Credit

This issue was identified by an external reviewer comparing the actual JWS
payload of a minted token against the operator's `.env.local` TOTP secret
and confirming bit-for-bit equality. Thank you for the careful eyes.

---

## [0.1.0-alpha.3] — 2026-05-06

Operational ergonomics release — adds the day-to-day commands that
were missing for sysadmins and operators. No wire-format changes;
files sealed by previous `0.1.0-alpha.x` versions decrypt cleanly on
`0.1.0-alpha.3` and vice versa.

### Added

- **`sealed-env get <file> <KEY>`** — print one variable's value to
  stdout. Composable: `STRIPE_KEY=$(sealed-env get .env.sealed STRIPE_KEY)`.
  Exits 1 if the key is not found, with the available key list in the
  error message.
- **`sealed-env set <file> <KEY> <VALUE>`** — update or add a single
  variable and re-seal in place. Comments and key order in the
  underlying `.env` are preserved. The previous sealed file is backed
  up to `<file>.bak` before overwriting.
- **`sealed-env edit <file>`** — opens `$EDITOR` (defaults to `vi` on
  Linux/macOS, `notepad` on Windows) with the plaintext for in-place
  editing. The temp file lives in `/dev/shm` (tmpfs, RAM-backed) on
  Linux when available, falls back to the OS temp dir elsewhere. Mode
  `0600`, zeroed and unlinked on exit including SIGINT/SIGTERM. Re-seals
  with the same mode/keys as the source on save.
- **`sealed-env diff <old.sealed> <new.sealed>`** — show which keys
  were added, removed, or changed between two sealed files. Values
  are hidden by default to avoid leaking secrets in CI logs and PR
  comments. Pass `--show-values` to reveal them. Long values are
  truncated at 60 characters. Exit code 0 if identical, 1 if different.
- **`init --mode enterprise` now renders a scannable QR code**
  directly in the terminal for the TOTP `otpauth://` URI. Point Google
  Authenticator / Authy / 1Password / Bitwarden at the screen and it
  pairs in under a second. The URI is still printed below the QR as a
  fallback for terminals that don't render Unicode half-block
  characters correctly.

### Refactored

- Internal: shared `decrypt → parse → reseal` helpers in
  `src/cli/utils/io.ts`. All five operational commands (decrypt, get,
  set, edit, diff) now go through one set of well-tested primitives,
  removing roughly 200 lines of duplication and ensuring consistent
  error handling across commands.

### Fixed

- **Smoke test `tampered HMAC is rejected`** had a ~1/64 chance of
  silently passing without actually tampering the HMAC, when the
  original first base64 character of the HMAC happened to be `'A'`
  and the test replaced it with the same character. The test now
  picks a guaranteed-different replacement.

### Documentation

- **New `docs/07-operational-guide.md`** — walks non-developers
  (sysadmins, managers, founders) through the five common workflows
  with no cryptography background required. Covers reading secrets,
  rotating leaked keys, comparing PR changes, onboarding a new
  developer, and how to integrate sealed-env into application code
  via the Spring Boot starter or the Node loader.
- **New `docs/08-cicd-recipes.md`** — copy-paste configurations for
  GitHub Actions (basic + enterprise mode with token minting and
  `::add-mask::`), GitLab CI (Protected + Masked variables, dotenv
  artifacts), AWS (ECS/Fargate, Lambda extension, EC2 with IAM +
  systemd), Google Cloud (Cloud Run, GKE with External Secrets
  Operator), Vercel, Netlify, Fly.io, Render, Heroku, Docker (with
  the rule that the master key must never be baked into the image),
  Kubernetes (`Secret` + `envFrom` + ESO), and bare-metal SSH.
  Includes a 5-point audit checklist.

### Dependencies

- **New runtime dependency: `qrcode-terminal@0.12.0`** — pure JS,
  zero transitive dependencies, MIT licensed, ~80 KB. Used only by
  the `init --mode enterprise` flow to render the TOTP QR code. Core
  cryptography and the `decrypt` / `get` / `set` / `edit` / `diff`
  paths remain dependency-free.

---

## [0.1.0-alpha.2] — 2026-05-06

Iteration on usability and onboarding. No wire-format changes; files
sealed by `0.1.0-alpha.1` decrypt cleanly on `0.1.0-alpha.2` and vice
versa.

### Fixed

- **CLI: `encrypt --out`** no longer auto-suffixes the user-provided
  path with `.sealed`. Previously, `--out file.sealed.basic` produced
  `file.sealed.basic.sealed` (double suffix). Now `--out` is respected
  exactly as given. The default (when `--out` is omitted) is still
  `<input>.sealed`.
- **CLI: `unseal`** now accepts `--file <.env.sealed>` and extracts the
  salt and KDF parameters automatically. Previously an operator had to
  decode the salt manually from the file and pass it via `--salt <hex>`,
  which was the documented but practically unusable path for
  `enterprise` mode. The `--salt` flag is kept for backward
  compatibility, and a stderr warning is emitted when neither flag is
  used (the zero-salt sentinel only works in single-process flows).

### Added — Open Source

- **Hands-on demo scripts** under `/playground/` for all three modes
  plus tampering and cross-stack interop. Self-contained bash scripts
  that generate ephemeral keys, seal a sample `.env`, demonstrate each
  mode end-to-end, and verify the roundtrip. Cross-platform: Git Bash
  on Windows, native bash elsewhere.
- **Cross-stack test vector for `enterprise` mode**
  (`test-vectors/v1/node-enterprise.json`) plus a Java interop test
  that builds its own unseal token from the file's salt + the master
  key + the TOTP secret committed in the vector. Cross-stack
  conformance suite now covers all three modes.
- **Open-source repository hygiene**:
  - `CONTRIBUTING.md` — local setup for both Node and Java sides,
    commit convention, crypto change policy, spec change policy,
    adapter contribution guide.
  - `CODE_OF_CONDUCT.md` — adopts Contributor Covenant 2.1 verbatim
    by canonical link.
  - GitHub issue templates: structured bug report, feature request,
    and `config.yml` that disables blank issues and routes security
    disclosures to the GitHub Security Advisory flow.
  - GitHub pull request template with a security review checklist
    required when crypto code is touched.
- **GitHub Discussions** enabled for design questions.

### Documentation

- **Expanded comparison table** in the root README. Adds HashiCorp
  Vault, Doppler, AWS Secrets Manager, and `dotenv` proper to the
  comparison. Includes a "when to pick which" decision section and an
  explicit "what `sealed-env` is not" callout to set expectations
  against centralized vault tooling.
- **Bilingual public landing site** at
  [davidalmeidac.github.io/sealed-env](https://davidalmeidac.github.io/sealed-env/)
  (English + Spanish) deployed via GitHub Pages. Plain HTML/CSS,
  single small i18n script, no runtime dependencies.
- **ASCII-art diagrams** replacing the previous Mermaid diagrams
  across all docs. Renders correctly in GitHub, any terminal,
  `cat`/`less`, and inside `git diff` — no JavaScript renderer
  required, which matters for a security tool whose docs should
  remain legible even when the rendering layer is unavailable or
  untrusted.
- **Cross-stack architecture diagram**, three-modes side-by-side
  comparison, and a visual mode-decision flowchart added to the root
  README.
- **Six numbered docs guides** under `/docs/` (overview, threat
  model, Node quickstart, Java/Spring Boot quickstart, enterprise
  mode walkthrough, format anatomy).
- **README documentation links repaired** — the previous version
  pointed to files that did not exist in `/docs/`.

### Sponsorship

- `FUNDING.yml` configured with GitHub Sponsors and Ko-fi.
- Sponsorship section on the landing page with three explicit tiers
  and honest framing about what the funds enable (security research,
  new language adapters, maintainer time).

---

## [0.1.0-alpha.1] — 2026-05-06

First public release. Both the Node and Java implementations are
published to their respective registries on this version.

> **⚠️ Alpha designation**: the public API is stable but minor breaking
> changes are still possible until v1.0.0. The wire format
> (`SEALED-ENV-V1`) is **frozen** and will remain readable forever.

### Added

#### Node implementation — `sealed-env` on npm

- AES-256-GCM authenticated encryption with HKDF-SHA256 subkey derivation.
- scrypt key derivation (RFC 7914) with `N=32768, r=8, p=1` defaults
  (Node 22 stdlib does not ship Argon2id).
- HMAC-SHA256 integrity tag for `team` and `enterprise` modes with
  domain-separated signing key.
- TOTP unseal token (RFC 6238) for `enterprise` mode, signed with the
  file's derived key (master + salt) and bound to a deploy challenge.
- High-level API: `seal()`, `unseal()`, `loadSealed()`.
- CLI: `npx sealed-env seal/unseal/init`.
- Zero runtime dependencies. Works on Node 20 and 22 (Linux, macOS,
  Windows).
- Memory wiping (`wipe(buf)`) of derived keys after use.

#### Java implementation — `io.github.davidalmeidac:sealed-env-core` + `sealed-env-spring-boot-starter` on Maven Central

- Pure Java 17, single auditable crypto module
  (`CryptoPrimitives.java`) using JDK stdlib for AES-GCM, HKDF, HMAC,
  scrypt, and SecureRandom; Bouncy Castle only for Argon2id.
- Reads both `KDF=scrypt` (Node-written files) and `KDF=argon2id`
  (Java-written files) for cross-stack interop.
- Java writer defaults to `KDF=argon2id` (`t=3, m=65536, p=4`).
- Spring Boot 3 starter with autoconfiguration:
  - `EnvironmentPostProcessor` runs before property binding so `@Value`
    and `@ConfigurationProperties` see decrypted values.
  - Driven by `application.yml` properties under the `sealed-env`
    prefix (path, fail-fast, override, env-var name customization).
- High-level API mirrors the Node side: `SealedEnv.seal()`, `unseal()`,
  `loadSealed()`.
- Single error type (`SealedEnvException`) with a stable `Code` enum.
- Constant-time equality (`MessageDigest.isEqual`) for all
  secret comparisons; defensive memory wiping on derived keys.

#### Cross-stack interoperability

- Single canonical wire format (`SEALED-ENV-V1`) consumed by both
  implementations.
- Node-generated test vectors under `test-vectors/v1/` (`node-basic.json`,
  `node-team.json`) read by automated Java tests on every commit.
- Byte-for-byte spec compliance verified by the Java test suite.

#### CI/CD

- `Node CI` workflow: matrix Linux/macOS/Windows × Node 20/22.
- `Java CI` workflow: matrix Linux/macOS/Windows × JDK 17/21,
  regenerates Node test vectors on each run before invoking
  `mvn -B verify`.
- `Node Release` workflow: publishes to npm with provenance attestation
  and OIDC.
- `Java Release` workflow: GPG-signs artifacts and publishes to Maven
  Central via the Sonatype Central Portal.

### Security

- **Public threat model** (`THREAT_MODEL.md`) mapping each defense to a
  real 2024-2025 supply-chain incident: Shai-Hulud npm worm,
  tj-actions/changed-files compromise, GhostAction campaign, Spring
  Boot heap-dump CVEs, backup leaks, and TOTP AitM phishing.
- AAD construction includes the magic line and all metadata except
  the `AAD-DIGEST` and `HMAC` fields themselves; mode-binding is part
  of the AAD so a `basic` file cannot be silently parsed as
  `enterprise` to bypass TOTP.
- Mandatory failure mode: all decryption errors collapse to a single
  generic message (`"sealed-env: file is corrupted, tampered, or wrong key"`)
  to avoid oracle-style information leaks.
- Allowed primitives: AES-256-GCM, Argon2id, scrypt, HKDF-SHA256,
  HMAC-SHA256, RFC 6238 TOTP (SHA-1 used **only** inside RFC 6238 as
  the standard mandates).
- Forbidden primitives: AES-CBC, PBKDF2, MD5, SHA-1 (outside TOTP),
  PKCS#1 v1.5 padding, custom RNGs.

### Wire format

- `SEALED-ENV-V1` specification published in [SPEC.md](./SPEC.md) and
  committed to v1 stability — files written by this release will remain
  readable by all future v1 implementations.

### Brand

- Roman sigillum (wax seal) visual identity. Three SVG marks:
  full lockup, sigillum-only, and monochrome favicon variant. Color
  palette is sealing-wax red (`#A8201A`), cream paper (`#f1ebe0`), and
  deep ink (`#1a1612`). Latin motto: *Cvstos Arcani* — "Guardian of
  the secret".

[Unreleased]: https://github.com/davidalmeidac/sealed-env/compare/java-v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/davidalmeidac/sealed-env/compare/java-v0.1.0-alpha.1...java-v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/davidalmeidac/sealed-env/releases/tag/java-v0.1.0-alpha.1
