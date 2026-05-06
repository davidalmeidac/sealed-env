# Overview

`sealed-env` is an encrypted-at-rest format for `.env` files, with optional
TOTP-bound unsealing for production deploys. It is **cross-stack**: a file
written by Node decrypts in Java, and vice versa.

## What problem does it solve?

```mermaid
flowchart LR
    A[".env on disk<br/>(plaintext)"] -->|"compromised<br/>SSH key"| B[Attacker]
    A -->|"checked into<br/>git by mistake"| B
    A -->|"backup leak"| B
    A -->|"production heap dump"| B
    style A fill:#fee
    style B fill:#400,color:#fff
```

A plaintext `.env` is a single point of failure. Anything that grants read
access to the file system or process memory grants total credential access.

`sealed-env` flips that: the file on disk is **only useful with a separate
key**, and in `enterprise` mode, **only useful with a fresh TOTP code at
deploy time**.

## The three modes

```mermaid
flowchart LR
    subgraph basic ["basic mode"]
        B1[".env.sealed"] --> B2["AES-256-GCM"]
        B2 --> B3["plaintext"]
        BM["master_key"] -.-> B2
    end

    subgraph team ["team mode"]
        T1[".env.sealed"] --> T2["HMAC verify"]
        T2 --> T3["AES-256-GCM"]
        T3 --> T4["plaintext"]
        TM["master_key"] -.-> T3
        TS["signing_key"] -.-> T2
    end

    subgraph enterprise ["enterprise mode"]
        E1[".env.sealed"] --> E2["HMAC verify"]
        E2 --> E3["TOTP token<br/>verify"]
        E3 --> E4["deploy challenge<br/>verify"]
        E4 --> E5["AES-256-GCM"]
        E5 --> E6["plaintext"]
        EM["master_key"] -.-> E5
        ES["signing_key"] -.-> E2
        ET["unseal_token<br/>(fresh TOTP)"] -.-> E3
        ED["deploy_id<br/>(commit SHA)"] -.-> E4
    end

    style basic fill:#f9f9f9,stroke:#999
    style team fill:#fff8e7,stroke:#c80
    style enterprise fill:#fbe7e7,stroke:#a02
```

| Mode | Compromise of master key alone | Compromise of all keys + filesystem | Replay across deploys |
|---|---|---|---|
| `basic` | Full breach | Full breach | N/A |
| `team` | Cannot decrypt (HMAC fails) | Full breach | N/A |
| `enterprise` | Cannot decrypt | Cannot decrypt without TOTP | Blocked |

## Cross-stack interop

```mermaid
sequenceDiagram
    participant DevNode as Dev (Node CLI)
    participant File as .env.sealed
    participant AppJava as Spring Boot app

    DevNode->>DevNode: seal({ plaintext, masterKey, mode: "team" })
    DevNode->>File: write SEALED-ENV-V1<br/>KDF=scrypt
    Note over File: file is plain UTF-8 text<br/>git diff–friendly

    AppJava->>File: read at startup
    AppJava->>AppJava: parse: KDF=scrypt? OK<br/>HMAC verify, GCM decrypt
    AppJava->>AppJava: expose values<br/>to Spring Environment
```

Both implementations honor the **same v1 specification**, byte-for-byte.

## Where to next

- [Threat model](./02-threat-model.md) — which attacks `sealed-env` defends against
- [Format spec](../SPEC.md) — the canonical wire format
- [Quick start: Node](./03-quickstart-node.md)
- [Quick start: Java + Spring Boot](./04-quickstart-java.md)
- [Enterprise mode walkthrough](./05-enterprise-mode.md) — TOTP + deploy binding
