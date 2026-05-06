<div align="center">

<img src="./assets/logo-lockup.svg" alt="sealed-env" width="640" />

<br/>

**Stop committing `.env` files. Stop hoping a leak doesn't happen.**

A cross-stack, zero-trust secret management library for **Node.js** and **Java/Spring Boot** —
with optional TOTP-based unsealing for production deploys.

[![npm version](https://img.shields.io/npm/v/sealed-env?style=flat-square&color=1a1612&labelColor=c4471f&logo=npm&logoColor=f4ede0)](https://www.npmjs.com/package/sealed-env)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.davidalmeidac/sealed-env?style=flat-square&color=1a1612&labelColor=c4471f&logo=apachemaven&logoColor=f4ede0)](https://central.sonatype.com/artifact/io.github.davidalmeidac/sealed-env)
[![License](https://img.shields.io/badge/license-MIT-1a1612?style=flat-square&labelColor=c4471f)](LICENSE)
[![Threat model](https://img.shields.io/badge/threat--model-public-1a1612?style=flat-square&labelColor=c4471f)](THREAT_MODEL.md)

[Docs](docs/Home.md) · [Threat Model](THREAT_MODEL.md) · [File Format](SPEC.md) · [Security Policy](SECURITY.md)

</div>

---

## Why this exists

In **2025 alone**, supply-chain attacks on the JavaScript ecosystem stole **thousands of
plaintext secrets** from CI/CD pipelines and developer machines. The Shai-Hulud worm
(November 2025) compromised over **25,000 repositories** by scanning for `.env` files
and exfiltrating their contents to public GitHub repos.

The lesson is simple: **plaintext `.env` is dead**. And encrypted-at-rest alone isn't
enough — if the master key leaks (and they do — see the tj-actions and GhostAction
campaigns), the entire vault opens.

`sealed-env` solves both halves: it encrypts your secrets at rest, **and** it can require
a fresh TOTP code from a human operator before each production deploy. Even if your CI
pipeline is fully compromised, attackers cannot decrypt without the operator's phone.

## What you get

- A `.env.sealed` file format that's **identical across Node and Java**. Mix stacks freely.
- **Three security modes** the user picks: `basic` for dev, `team` for staging,
  `enterprise` for production with TOTP unseal.
- **Zero runtime dependencies** in the Node package. Only Node's built-in `crypto` and `fs`.
- A **published threat model** that says exactly what we defend against and what we don't.
- A **CLI** (`npx sealed-env`) and a **Spring Boot starter** (Java).

## Cross-stack architecture

```
   ┌─────────────────────────┐         ┌─────────────────────────┐
   │  Node side              │         │  Java side              │
   │  ────────────           │         │  ────────────           │
   │  • CLI: sealed-env seal │         │  • SealedEnv core lib   │
   │  • npm: sealed-env      │         │  • Spring Boot starter  │
   │  • writes KDF=scrypt    │         │  • writes KDF=argon2id  │
   └────────────┬────────────┘         └────────────┬────────────┘
                │                                   │
                │  both speak SEALED-ENV-V1         │
                │  (byte-for-byte spec compliance)  │
                ▼                                   ▼
            ┌────────────────────────────────────────┐
            │            .env.sealed                 │
            │  ───────────────────────────           │
            │  SEALED-ENV-V1 MODE=team               │
            │  KDF=<scrypt|argon2id>                 │
            │  KDF-PARAMS=...   SALT=...             │
            │  NONCE=...        AAD-DIGEST=...       │
            │  HMAC=...         CREATED=2026-...     │
            │                                        │
            │  <base64 ciphertext + GCM tag>         │
            └────────────────────────────────────────┘
                ▲                                   ▲
                │       a file written by one       │
                │       stack decrypts in the       │
                │       other — no conversion       │
                │                                   │
   ┌────────────┴────────────┐         ┌────────────┴────────────┐
   │  Node app reads it      │         │  Java app reads it      │
   │  (loadSealed())         │         │  (Spring Environment)   │
   └─────────────────────────┘         └─────────────────────────┘
```

## 30-second tour (Node)

```bash
# 1. Install
npm install sealed-env

# 2. Initialize a vault for your project
npx sealed-env init
# → generates a master key (saved locally to .env.local, gitignored)
# → if you choose 'enterprise' mode, also displays a QR code for your authenticator

# 3. Encrypt your existing .env
npx sealed-env encrypt .env
# → creates .env.sealed (commit this!)

# 4. Use it in code — no API change
import 'sealed-env/config';
console.log(process.env.STRIPE_API_KEY);  // works as if it were a normal .env
```

## 30-second tour (Spring Boot)

```xml
<dependency>
    <groupId>io.github.davidalmeidac</groupId>
    <artifactId>sealed-env-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

```yaml
# application.yml
sealed-env:
  file: .env.sealed
  key-source: env
```

```java
@Value("${stripe.api.key}")  // resolved transparently from .env.sealed
private String stripeKey;
```

## The three modes — visualized

```
   basic                    team                     enterprise
   ─────                    ────                     ──────────

   .env.sealed              .env.sealed              .env.sealed
        │                        │                        │
        ▼                        ▼                        ▼
   ┌─────────┐              ┌─────────┐              ┌─────────┐
   │ AES-GCM │              │  HMAC   │              │  HMAC   │
   │ decrypt │              │ verify  │              │ verify  │
   └────┬────┘              └────┬────┘              └────┬────┘
        │                        ▼                        ▼
        ▼                   ┌─────────┐              ┌─────────┐
   plaintext                │ AES-GCM │              │  TOTP   │
                            │ decrypt │              │  token  │
                            └────┬────┘              │ verify  │
                                 ▼                   └────┬────┘
                            plaintext                     ▼
                                                     ┌─────────┐
   ▲                        ▲                        │ deploy  │
   │ master_key             │ + signing_key          │  bind   │
                                                     └────┬────┘
                                                          ▼
                                                     ┌─────────┐
                                                     │ AES-GCM │
                                                     │ decrypt │
                                                     └────┬────┘
                                                          ▼
                                                     plaintext

                                                     ▲
                                                     │ + totp_secret
                                                     │ + deploy_id
```

## The three modes

|  | basic | team | enterprise |
|---|:---:|:---:|:---:|
| AES-256-GCM cipher | ✓ | ✓ | ✓ |
| Argon2id key derivation | ✓ | ✓ | ✓ |
| HMAC integrity tag | — | ✓ | ✓ |
| Audit log of secret access | — | ✓ | ✓ |
| TOTP unseal required | — | — | ✓ |
| Deploy-bound unseal tokens | — | — | ✓ |
| Replay protection | — | — | ✓ |
| Heap dump filter (Java) | — | ✓ | ✓ |
| Memory wipe after read | ✓ | ✓ | ✓ |
| Suitable for | personal projects | staging, small teams | production, fintech, PII |

Pick the one that fits your threat model. Upgrade later with one command:

```bash
npx sealed-env upgrade --to enterprise
```

## How `enterprise` mode works

```
┌──────────────┐  1. push     ┌──────────────┐
│   developer  │ ───────────▶ │   github     │
└──────────────┘              └──────────────┘
                                     │ 2. CI runs
                                     ▼
                              ┌──────────────┐
                              │  CI pipeline │  paused, waiting for unseal
                              └──────────────┘
                                     │
                                     │ 3. notifies operator
                                     ▼
                              ┌──────────────┐
                              │   operator   │  4. opens authenticator app,
                              │   (you)      │     reads 6-digit TOTP code
                              └──────────────┘
                                     │
                                     │ 5. runs:
                                     │    sealed-env unseal --totp 482914 \
                                     │      --deploy-id <commit-sha>
                                     ▼
                              ┌──────────────────────────────────────┐
                              │ unseal token (60s lifetime, bound to │
                              │ this specific deploy)                │
                              └──────────────────────────────────────┘
                                     │ 6. paste into CI form
                                     ▼
                              ┌──────────────┐
                              │ deploy runs  │  decrypts .env.sealed
                              │ to prod      │  with master_key + token
                              └──────────────┘

If the master key leaks AFTER the deploy → attacker still needs the operator's
TOTP. If the TOTP token leaks → useless for the next deploy (different commit).
```

## Comparison

|  | sealed-env | dotenvx | dotenv-vault | jasypt |
|---|---|---|---|---|
| Node + Java with shared format | **✓** | ✗ (Node only) | ✗ | ✗ (Java only) |
| Zero dependencies (Node) | **✓** | ✗ (8+ deps) | ✗ | n/a |
| TOTP unseal for production | **✓** | ✗ | ✗ | ✗ |
| Memory wipe after ingestion | **✓** | ✗ | ✗ | ✗ |
| Heap dump filter (Java) | **✓** | n/a | n/a | ✗ |
| Public threat model | **✓** | partial | partial | ✗ |
| Vendor-neutral (no service required) | **✓** | ✓ | ✗ (paid) | ✓ |
| Free / MIT | **✓** | ✓ | partial | ✓ |

## Documentation

- 📖 [Getting started](docs/Getting-Started.md)
- 🔐 [Threat model](THREAT_MODEL.md)
- 📐 [File format spec](SPEC.md)
- 🚀 [CI/CD integration recipes](docs/CI-CD-Recipes.md)
- ⚙️ [API reference (Node)](docs/API-Node.md)
- 🍃 [Spring Boot integration](docs/Spring-Boot.md)
- 🔄 [Migration from dotenv / dotenvx](docs/Migration.md)
- 🆘 [FAQ](docs/FAQ.md)

## Project status

**v0.1.0 — early.** API is mostly stable but minor breaking changes possible until v1.0.
Cryptographic format (`SEALED-ENV-V1`) is **frozen** and will remain readable forever.

**Roadmap:**

- [x] v0.1.0 — Node basic + enterprise modes, CLI, Spring Boot starter
- [ ] v0.2.0 — `team` mode + audit log + heap dump filter
- [ ] v0.3.0 — Hardware-backed keys (DPAPI / Keychain / Secret Service)
- [ ] v0.4.0 — FIDO2/YubiKey alternative to TOTP
- [ ] v0.5.0 — Shamir Secret Sharing (threshold unsealing)

## Contributing

This is a security-sensitive project. Contributions are very welcome but please read
[SECURITY.md](SECURITY.md) first. Crypto changes require explicit discussion.

## License

[MIT](LICENSE) — David Almeida, 2026.

---

<div align="center">
<sub>
Built openly in Bucaramanga, Colombia.<br/>
"Encrypt at rest. Authenticate at deploy. Wipe on read."
</sub>
</div>
