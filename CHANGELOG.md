# Changelog

All notable changes to `sealed-env` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The wire format (`SEALED-ENV-V1`) follows its own stability commitment:
files written today will remain readable forever. See [SPEC.md](./SPEC.md).

---

## [Unreleased]

### Added

- **Open-source repository hygiene** to support contributors:
  - `CONTRIBUTING.md` — local setup for both Node and Java sides, commit
    convention, crypto change policy, spec change policy, adapter
    contribution guide.
  - `CODE_OF_CONDUCT.md` — adopts Contributor Covenant 2.1 verbatim by
    canonical link.
  - GitHub issue templates: structured bug report, feature request, and
    a `config.yml` that disables blank issues and routes security
    disclosures to the GitHub Security Advisory flow.
  - GitHub pull request template with a security review checklist that
    is required when crypto code is touched.
- **GitHub Discussions** enabled for design questions and open-ended
  conversations not suited to the issue tracker.

### Documentation

- Bilingual public landing site at
  [davidalmeidac.github.io/sealed-env](https://davidalmeidac.github.io/sealed-env/)
  (English + Spanish) deployed via GitHub Pages. Plain HTML/CSS, single
  small i18n script, no runtime dependencies — coherent with the
  project's "zero deps" ethos.
- ASCII-art diagrams replacing the previous Mermaid diagrams across all
  docs. Renders correctly in GitHub, any terminal, `cat`/`less`, and
  inside `git diff` — no JavaScript renderer required, which matters
  for a security tool whose docs should remain legible even when the
  rendering layer is unavailable or untrusted.
- Cross-stack architecture diagram, three-modes side-by-side comparison,
  and a visual mode-decision flowchart added to the root README.
- README documentation links repaired (the previous version pointed to
  files that did not exist in `/docs/`).
- Six numbered docs guides under `/docs/`:
  - `01-overview.md` — what `sealed-env` is and isn't.
  - `02-threat-model.md` — coverage matrix mapped to real 2024-2026
    incidents.
  - `03-quickstart-node.md`, `04-quickstart-java.md`.
  - `05-enterprise-mode.md` — TOTP + deploy challenge walkthrough.
  - `06-format-anatomy.md` — `.env.sealed` byte layout.

### Sponsorship

- `FUNDING.yml` configured with GitHub Sponsors and Ko-fi.
- Sponsorship section on the landing page with three explicit tiers and
  honest framing about what the funds enable (security research, new
  language adapters, maintainer time).

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

[Unreleased]: https://github.com/davidalmeidac/sealed-env/compare/java-v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/davidalmeidac/sealed-env/releases/tag/java-v0.1.0-alpha.1
