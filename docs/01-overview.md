# Overview

`sealed-env` is an encrypted-at-rest format for `.env` files, with optional
TOTP-bound unsealing for production deploys. It is **cross-stack**: a file
written by Node decrypts in Java, and vice versa.

## What problem does it solve?

```
                       ┌─────────────────────────┐
                       │   .env on disk          │
                       │   (plaintext)           │
                       └────────────┬────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
    compromised SSH key   accidental git push   backup leak / heap dump
              │                     │                     │
              └─────────────────────┴─────────────────────┘
                                    │
                                    ▼
                              ╔═══════════╗
                              ║  ATTACKER ║   total credential access
                              ╚═══════════╝
```

A plaintext `.env` is a single point of failure. Anything that grants read
access to the file system or process memory grants total credential access.

`sealed-env` flips that: the file on disk is **only useful with a separate
key**, and in `enterprise` mode, **only useful with a fresh TOTP code at
deploy time**.

## The three modes

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
        ▼                        ▼                        ▼
   plaintext                ┌─────────┐              ┌─────────┐
                            │ AES-GCM │              │  TOTP   │
                            │ decrypt │              │  token  │
                            └────┬────┘              │ verify  │
                                 ▼                   └────┬────┘
                            plaintext                     ▼
   inputs:                  inputs:                  ┌─────────┐
   • master_key             • master_key             │ deploy  │
                            • signing_key            │  bind   │
                                                     └────┬────┘
                                                          ▼
                                                     ┌─────────┐
                                                     │ AES-GCM │
                                                     │ decrypt │
                                                     └────┬────┘
                                                          ▼
                                                     plaintext

                                                     inputs:
                                                     • master_key
                                                     • signing_key
                                                     • unseal_token
                                                     • deploy_id (commit SHA)
```

| Mode | Compromise of master key alone | Compromise of all keys + filesystem | Replay across deploys |
|---|---|---|---|
| `basic` | Full breach | Full breach | N/A |
| `team` | Cannot decrypt (HMAC fails) | Full breach | N/A |
| `enterprise` | Cannot decrypt | Cannot decrypt without TOTP | Blocked |

## Cross-stack interop

```
  Dev (Node CLI)               .env.sealed              Spring Boot app
  ──────────────               ───────────              ───────────────

   sealed-env seal
   ──────────────▶ writes
                   ┌──────────────────────────┐
                   │  SEALED-ENV-V1 MODE=team │
                   │  KDF=scrypt              │
                   │  ...                     │
                   │  <ciphertext>            │
                   └──────────────────────────┘
                              │
                              │  file is plain UTF-8 text,
                              │  git diff–friendly
                              │
                              ▼  read at startup
                   ┌──────────────────────────┐
                   │  parse: KDF=scrypt? OK   │
                   │  HMAC verify             │
                   │  GCM decrypt             │
                   └──────────────────────────┘
                              │
                              ▼
                   ┌──────────────────────────┐
                   │  values exposed to       │
                   │  Spring Environment      │
                   └──────────────────────────┘
```

Both implementations honor the **same v1 specification**, byte-for-byte.

## Where to next

- [Threat model](./02-threat-model.md) — which attacks `sealed-env` defends against
- [Format spec](../SPEC.md) — the canonical wire format
- [Quick start: Node](./03-quickstart-node.md)
- [Quick start: Java + Spring Boot](./04-quickstart-java.md)
- [Enterprise mode walkthrough](./05-enterprise-mode.md) — TOTP + deploy binding
