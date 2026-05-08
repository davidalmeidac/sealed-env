# Threat Model: sealed-env

> Research-backed threat model based on real attacks observed in 2024-2026.
> Each threat is mapped to specific mitigations in the sealed-env design.

---

## Real attacks we are defending against

### 1. Shai-Hulud npm worm (Sept 2025 + Nov 2025 v2.0)

**What happened:**
- Self-replicating worm infected 500+ npm packages
- Payload (`setup_bun.js`, `bun_environment.js`) ran TruffleHog on the host
- Scanned filesystem for `GITHUB_TOKEN`, `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, etc.
- Exfiltrated to public GitHub repos with description "Sha1-Hulud: The Second Coming"
- Used stolen npm tokens to publish more infected packages → exponential spread
- Final tally: **25,000+ compromised repos**, hundreds of orgs

**What it teaches us:**
- A malicious npm install **WILL** scan your project dir for `.env` files
- A malicious npm install **WILL** read `process.env` at runtime
- Plaintext `.env` is dead. Cleartext secrets in env vars during install are dead.

### 2. tj-actions/changed-files (March 2025)

**What happened:**
- Attacker compromised a popular GitHub Action (23,000+ repos used it)
- Modified version tags retroactively to point to malicious commit
- Malicious script extracted secrets **from the Runner Worker process memory**
- Printed secrets in workflow logs → public for any repo with public workflows
- Stolen: AWS keys, GitHub PATs, npm tokens, RSA keys

**What it teaches us:**
- CI runners are not trusted execution environments
- Anything in `process.env` of CI is reachable by any action that runs
- Pinning to tags ≠ pinning to commits (attackers re-tag)

### 3. GhostAction Campaign (Sept 2025)

**What happened:**
- 327 GitHub user accounts compromised
- Attackers injected workflows named "Github Actions Security" (looking legit)
- Workflows POSTed entire CI env to attacker server
- 3,325 secrets stolen across 817 repos in days

**What it teaches us:**
- Attacker doesn't need to compromise a popular action — just one developer
- Workflow-level secrets exposure is catastrophic
- "Approval before deploy" controls are critical

### 4. Spring Boot Actuator heapdump exposure (ongoing, CVE-2025-53602 et al.)

**What happened:**
- Apps expose `/actuator/heapdump` accidentally
- Attackers download heap, analyze with Eclipse MAT / VisualVM / OQL
- Find: passwords, API keys, JWT tokens, DB strings, encryption keys
- All sitting in JVM memory as plain `String` objects (immutable, GC-survivable)

**What it teaches us:**
- Strings in Java memory are forensic gold
- A single misconfig (Actuator exposed) defeats encryption-at-rest
- Plaintext secrets must not survive boot

### 6. Token-payload exposure (lesson from sealed-env's own CVE-2026-45091)

**What happened (to us, May 2026):**

In `sealed-env` versions `0.1.0-alpha.{1,2,3}`, the operator's TOTP secret was
embedded **in plaintext (base64) inside the JWS payload of every minted unseal
token**. JWS is signed, not encrypted — anyone who could observe a token (CI
logs, container env dumps, `kubectl describe pod`, Sentry/Rollbar stack traces)
could decode the payload and extract the secret. Combined with the master key,
the leaked secret allowed minting **future** unseal tokens indefinitely.

The reviewer found it in 5 minutes by base32-encoding the bytes from
`payload.totp_secret` and comparing to the operator's `.env.local` value.

Affected versions are deprecated. Tracked as
**[CVE-2026-45091](https://nvd.nist.gov/vuln/detail/CVE-2026-45091)** /
[GHSA-x3r2-fj3r-g5mv](https://github.com/davidalmeidac/sealed-env/security/advisories/GHSA-x3r2-fj3r-g5mv).

**What it teaches us (and what we now do):**

- **JWT/JWS payloads are public.** The signature attests to integrity, not
  confidentiality. Any field placed in `.payload.*` is readable by anyone
  who sees the token. This is JOSE 101, but it's surprisingly easy to
  mis-design under pressure — especially when the verifier "needs" the
  secret to recompute a commitment.
- **Carry derived material, never raw secrets.** The fix replaced
  `payload.totp_secret` with `payload.epoch`, where:
  ```
  enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
  ```
  The salt binding shrinks the blast radius of a leaked token from
  "permanent compromise of all current AND future enterprise files" down
  to "compromise of one specific file generation, until re-seal". The
  raw TOTP secret never leaves the operator's machine.
- **Test for what you don't want to see, not just for what you do.** Our
  new regression suite asserts both Node and Java sides:
  - The serialized `.env.sealed` file does NOT contain `TOTP-VERIFIER` (old
    field name, semantically dangerous).
  - The minted token does NOT contain the literal secret in any common
    encoding (hex, base64, base32) or under the field name `totp_secret`.

  Negative assertions catch design regressions that positive assertions
  miss entirely.
- **External review pays for itself instantly.** The fix took 4 hours
  end-to-end. Not finding it would have meant shipping a broken second
  factor to every user. Make the bug-report path obvious and respond fast.

### 7. TOTP real-time relay (AitM phishing toolkits — Evilginx, Modlishka)

**What happened:**
- Attacker proxies the login page
- User submits TOTP code — attacker captures and relays in 30s window
- Microsoft Entra TOTP brute force (AuthQuake) — TOTPs guessable when validation has loose rate limits

**What it teaches us:**
- TOTP alone is **not** phishing-resistant
- TOTP tied to a service URL only works for web; CLI tools are weaker
- Need: bind TOTP to a specific operation (deploy ID, hash) — not just to time

---

## Threat-to-mitigation matrix

| # | Threat | Vector | sealed-env mitigation |
|---|--------|--------|----------------------|
| T1 | Plaintext `.env` scanned by malicious dep | npm postinstall, Shai-Hulud | `.env` never exists in CI/prod — only `.env.sealed`. Plaintext only on dev machine, gitignored, and even there optional |
| T2 | Public `.env.sealed` in repo | git leak | Cipher = AES-256-GCM with 256-bit random key. Without `SEALED_ENV_KEY` the file is opaque |
| T3 | `SEALED_ENV_KEY` leak via CI logs | tj-actions, GhostAction | enterprise mode requires **second factor** (TOTP unseal token) per deploy. Master key alone is insufficient |
| T4 | TOTP relay/replay attack | Evilginx-style | Unseal tokens are **bound to a deploy challenge** (commit SHA + timestamp + nonce). A captured token cannot be replayed for a different deploy |
| T5 | Heap dump exfiltration | exposed `/heapdump`, JVM dump | All decrypted values stored in `char[]` / `byte[]` (zerable). Wiped after Spring `Environment` ingestion. **Heap dump filter** (optional) replaces values with `***` |
| T6 | Memory analysis at runtime | live JVM forensics | Anti-debug guard (paranoid mode) refuses to start if JDWP/JVMTI debugger is attached |
| T7 | Backup/snapshot exfiltration | EBS snapshot, container export | The decrypted plaintext never lands on disk. Even swap is mitigated by `SealedString` (off-heap optional) |
| T8 | Supply-chain compromise of `sealed-env` itself | npm worm targeting us | Zero deps in Node version. All cryptography uses `node:crypto` (built-in). Provenance attestations (npm sigstore) on every release |
| T9 | Force-push of git tags on our action | tj-actions retag attack | We don't ship a GitHub Action — only an npm package with provenance. Users pin to digests, not tags |
| T10 | Replay of unseal token across deploys | stolen short-lived token | Token has `ops_id` claim — a single use binds it to a specific operation. Server-side (or client-side) replay cache rejects re-use |
| T11 | Brute-force unseal | repeated attempts | Rate limiter on `unseal` CLI: max 5 wrong codes per 5 minutes per master key. Then forced rotation |
| T12 | Side-channel timing on key compare | crypto bug | Use `crypto.timingSafeEqual` for all comparisons. Constant-time HMAC verification |
| T13 | Secret material in token payload | JWT/JWS misuse — carrying secrets where the spec only protects integrity | Token carries `enterprise_epoch = HMAC(totp_secret, salt \|\| tag)`, never the raw secret. File commits to `epoch_commit = HMAC(derived_key, epoch \|\| tag)`. Regression tests assert both Node + Java tokens never contain the literal secret in any encoding. Lesson learned the hard way; see threat #6 above |

---

## Defense-in-depth diagram

```
                     ATTACKER GOAL: read PROD secrets
                     ─────────────────────────────────

           ┌───── L1: Repo scanner finds .env.sealed ──┐
           │                                          │
           ▼                                          │
   Without SEALED_ENV_KEY → opaque ciphertext         │
           ✗ blocked                                  │
                                                      │
           ┌───── L2: CI compromise leaks env vars ───┘
           │
           ▼
   Has SEALED_ENV_KEY but no UNSEAL_TOKEN → enterprise mode rejects
           ✗ blocked                                  │
                                                      │
           ┌───── L3: Phished TOTP → got token ───────┘
           │
           ▼
   Token bound to (deploy_id, sha) — different deploy fails
           ✗ blocked (mostly)
                                                      │
           ┌───── L4: Compromise live JVM/heap ───────┘
           │
           ▼
   char[] zeroed after ingestion → "" instead of secret
   Heap dump filter masks remaining surface
           ✗ blocked (best-effort)

           ┌───── L5: Operator's machine is compromised ───┐
           │
           ▼
   Master key + TOTP secret on dev machine — local malware wins
   We document: USE A SEPARATE DEVICE FOR TOTP (phone authenticator)
   Mitigation: hardware-backed key storage in v0.3.0
```

---

## What we explicitly do NOT defend against

We are honest about the limits. v0.1.0 does not protect against:

| Out of scope | Why |
|---|---|
| Compromised operator's phone (TOTP seed exfiltration) | Mitigation = use FIDO2/YubiKey in v0.3.0 |
| Insider threat with master key + TOTP access | Mitigation = Shamir threshold sharing in v0.4.0 |
| OS-level keylogger reading TOTP at type-time | Out of scope — no software can fix host compromise |
| Side-channel hardware attacks (Spectre, Rowhammer) | Out of scope — rely on JVM/Node hardening |
| Malicious sealed-env CLI binary | Mitigation = npm provenance attestations + reproducible builds |

We document these clearly in README. Lying about scope erodes trust.

---

## Mitigation map per mode

### `basic` mode (defends against T1, T2 only)

```
master_key (env var) → AES-256-GCM → ciphertext
```

Equivalent to dotenvx. Suitable for personal/dev use.

### `team` mode (defends against T1, T2, T7, T8 partially)

```
master_key + signing_key → AES-256-GCM + HMAC-SHA256
+ audit log of secret accesses
+ heap dump filter on Spring Boot
+ memory wipe after ingestion
```

Suitable for small teams + staging.

### `enterprise` mode (defends against T1-T6, T8, T10-T12)

```
master_key (CI) + TOTP-derived unseal_token (operator) → derived_key
+ token bound to deploy challenge (sha + timestamp)
+ rate limiting on unseal attempts
+ audit log
+ memory hygiene
+ paranoid mode (anti-debug)
```

Required for production deployments handling money / PII / critical infrastructure.

---

## Cryptographic choices (justified)

| Choice | Why |
|---|---|
| AES-256-GCM | NIST-approved, authenticated, well-audited, hardware-accelerated |
| Argon2id (KDF) | Winner of PHC competition, resistant to GPU/ASIC, best-in-class for password-derived keys |
| HKDF-SHA256 (subkey derivation) | RFC 5869, deterministic key separation from master |
| HMAC-SHA256 (signing) | Strong, simple, faster than asymmetric for our use |
| TOTP (RFC 6238) | Universal authenticator support, no infrastructure required |
| `crypto.timingSafeEqual` | Prevents timing side-channels on comparisons |
| 16-byte random salt, 12-byte random nonce | Standards-compliant, never reused per-encryption |

We avoid:

- **AES-CBC** (no auth, padding oracle attacks)
- **PBKDF2** (slower against GPU than Argon2)
- **MD5/SHA1** anywhere
- **JWE/JOSE** (footgun-heavy, complexity not justified for our scope)

---

## Reading list (sources)

- [Shai-Hulud campaign analysis (Unit42)](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [npm threat landscape (Unit42)](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- [Sha1-Hulud 2.0 (Wiz)](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [tj-actions supply chain attack (Wiz)](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [GhostAction campaign (GitGuardian)](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [Hardening GitHub Actions (Wiz)](https://www.wiz.io/blog/github-actions-security-guide)
- [Spring Boot heap dump risks (DTS)](https://www.dts-solution.com/exposing-the-heap-a-security-deep-dive-into-java-heap-dumps-via-spring-actuators/)
- [Spring Actuator misconfig (Wiz)](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [TOTP phishing limitations (BeyondIdentity)](https://www.beyondidentity.com/phishing-101/totp)
- [AuthQuake TOTP brute force (WorkOS)](https://workos.com/blog/authquake-microsofts-mfa-system-vulnerable-to-totp-brute-force-attack)
- [dotenvx security model](https://dotenvx.com/)
