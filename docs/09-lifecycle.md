# Project lifecycle — init, onboarding, deploy

This page walks through the **complete journey** of a project that
uses sealed-env, from the very first commit to the first production
deploy. The other docs cover individual pieces in depth — this one
ties them together as a single narrative so you can see how the
parts fit.

For stack-specific install steps, see
[03-quickstart-node.md](./03-quickstart-node.md) or
[04-quickstart-java.md](./04-quickstart-java.md). For
platform-specific deploys (GitHub Actions, Jenkins, AWS, Azure…) see
[08-cicd-recipes.md](./08-cicd-recipes.md). For the cryptographic
detail behind enterprise mode, see
[05-enterprise-mode.md](./05-enterprise-mode.md).

---

## The three phases

```
   ┌──────────────┐   ┌────────────────┐   ┌──────────────────┐
   │  1. Init     │ → │  2. Onboarding │ → │  3. Deploy       │
   │  (one time)  │   │  (per dev)     │   │  (every release) │
   └──────────────┘   └────────────────┘   └──────────────────┘
        ↑                    ↑                      ↑
   Greenfield           New teammate            Pipeline / SSH
   Bootstraps           clones repo +           pushes to prod
   keys, files,         receives master         using master key +
   gitignore            key via secure          (enterprise) a
                        channel                 short-lived unseal
                                                token
```

Each phase has a clear **input**, **output**, and **trust boundary**.
Knowing where each one lives makes the rest of the docs map cleanly
onto your actual workflow.

---

## Phase 1 — Init (one time, by the project owner)

The first person to add sealed-env to a project runs `init`. This
generates the keys, writes them to a gitignored local file, and
prints next-steps instructions.

### Basic mode (solo dev or private repo)

```bash
sealed-env init
```

Outcome:

```
✓ sealed-env initialized in /path/to/project (mode: basic)

Generated keys:
  SEALED_ENV_KEY=<64 hex chars>

Saved to /path/to/project/.env.local (gitignored).

Next steps:
  1. Create a .env file with your secrets (it will be gitignored)
  2. Run: sealed-env encrypt .env
  3. Commit .env.sealed (NOT .env or .env.local)
```

What `init` actually does:

| Action | Why |
|---|---|
| Generates a 32-byte master key (CSPRNG) | Cryptographic root of trust |
| Writes `.env.local` with mode `0600` | Auto-loader picks it up — no `export` needed |
| Appends `.env` and `.env.local` to `.gitignore` | Prevents accidental plaintext leaks |
| **Does not** create `.env.sealed` yet | You haven't written your `.env` yet — that's the next step |

> 💡 The auto-loader **only** reads `SEALED_ENV_*` variables from
> `.env.local`. It is NOT a generic dotenv loader. CI / explicit env
> vars always override `.env.local`, so production secrets never get
> accidentally pulled from a stray local file.

### Team mode (shared repo, multiple devs)

```bash
sealed-env init --mode team
```

Adds a second key — `SEALED_ENV_SIGNING_KEY` — for HMAC integrity.
Without it, anyone who reads the sealed file can decrypt; with it,
they also need the signing key to *modify* the sealed file without
breaking the integrity check on next decrypt.

### Enterprise mode (production-grade)

```bash
sealed-env init --mode enterprise
```

Adds a TOTP secret and prints a QR code right in your terminal:

```
✓ sealed-env initialized in /path/to/project (mode: enterprise)

Generated keys:
  SEALED_ENV_KEY=...
  SEALED_ENV_SIGNING_KEY=...
  TOTP secret (base32): JBSWY3DPEHPK3PXP

Scan this QR with your authenticator app (Google Authenticator,
Authy, 1Password, Bitwarden, etc.):

  ███▀▀▀█▀▀█▀█▀█▀▀▀█████
  ███   █  ▄▀▄ █   █████
  ...

If the QR does not render correctly in your terminal, paste this
URI or the base32 secret above into your authenticator manually:
  otpauth://totp/...
```

The TOTP code is **only** required at deploy time, not for day-to-day
development. See [05-enterprise-mode.md](./05-enterprise-mode.md) for
the deep dive.

### What gets committed (and what doesn't)

After `init` plus your first `sealed-env encrypt .env`:

```
project/
├── .env             ← gitignored, plaintext secrets
├── .env.local       ← gitignored, contains SEALED_ENV_KEY
├── .env.sealed      ← COMMITTED, ciphertext
├── .gitignore       ← updated by init
└── .sealed-env.json ← (only if you opt into keychain)
```

The first commit looks like:

```bash
git add .gitignore .env.sealed
git commit -m "chore: bootstrap sealed-env"
git push
```

Notice what's **not** in that commit: `.env` and `.env.local`. They
live only on your machine.

---

## Phase 2 — Onboarding (per dev, every time someone joins)

Now imagine a teammate joins. They clone the repo and find:
`.env.sealed` (encrypted, useless without the key) and `.gitignore`
(no plaintext secrets). They need the master key — but **not** over
Slack, email, or any other channel where it would be logged.

### Step 1 — Share the master key out-of-band

Pick **one** of these channels:

| Channel | Notes |
|---|---|
| **1Password / Bitwarden shared vault** | Best default. Audit log + revocation. |
| **Signal / iMessage** (E2E encrypted) | Acceptable for small teams. |
| **In person / paper QR code** | The most paranoid. Works for new hires you meet. |
| **Cloud KMS export to teammate's IAM identity** | Enterprise-grade — see your KMS docs. |

The full master key looks like a 64-character hex string:
`a1b2c3d4...e9f0`. Whoever has it can decrypt the file.

Avoid: Slack DMs, plain email, GitHub issues, stickies — anything
that ends up in logs, backups, or screenshots.

### Step 2 — Save it to `.env.local`

The new dev pastes the key into a local file:

```bash
echo "SEALED_ENV_KEY=<the key they received>" > .env.local
chmod 600 .env.local
```

If you're using team or enterprise mode, also include
`SEALED_ENV_SIGNING_KEY=...` (and for enterprise, the operator's own
TOTP secret if they will mint their own deploy tokens).

### Step 3 — Verify

```bash
sealed-env get .env.sealed SOME_KEY
```

If they get the value, onboarding worked. The auto-loader reads
`.env.local` automatically — no `export` step.

```
   ┌────────────────┐
   │ git clone      │
   └───────┬────────┘
           │
           ▼
   ┌────────────────┐
   │ .env.sealed    │   already in repo
   │ (ciphertext)   │
   └───────┬────────┘
           │
           │  + master key (out-of-band)
           ▼
   ┌────────────────┐
   │ .env.local     │   (mode 0600, gitignored)
   │ SEALED_ENV_KEY │
   └───────┬────────┘
           │
           ▼
   ┌────────────────┐
   │ sealed-env get │   auto-loads from .env.local
   │ → real value   │   no export needed
   └────────────────┘
```

### Optional — store the key in the OS keychain instead

If the dev would rather not keep the key in a flat file, they can
push it into the OS keychain (Windows DPAPI, macOS keychain, Linux
secret-tool):

```bash
# Save the key to .env.local once, then move it to the keychain
sealed-env keychain push
# This deletes the SEALED_ENV_KEY line from .env.local and writes
# .sealed-env.json (a marker file with `{ "storage": "keychain" }`)
```

`.sealed-env.json` is **safe to commit** — it contains no secrets,
only a flag telling future `sealed-env` invocations in this project
to look in the keychain. The actual secret material stays in the OS
secret store.

To opt out later: `sealed-env keychain clear`.

> 💡 The keychain is **strictly opt-in** since alpha.8. Without
> `.sealed-env.json` (or `SEALED_ENV_USE_KEYCHAIN=1`), the keychain
> code path is fully bypassed — no PowerShell / `security` /
> `secret-tool` spawn overhead.

### Onboarding checklist

When a new dev joins, the project owner should hand them:

- [ ] Clone URL (or repo invite)
- [ ] Master key, via a chosen secure channel
- [ ] (Team / enterprise) Signing key, same channel
- [ ] (Enterprise, only if they will deploy) Their own TOTP enrollment

That's it. They run `git clone`, paste the keys into `.env.local`,
and every `sealed-env` command works.

---

## Phase 3 — Deploy (every release, by CI or operator)

The deploy phase is where sealed-env's defense ceiling matters most.
The goal: get the plaintext secrets into the running process **without**
ever writing them to disk on the deploy host, into CI logs, or into a
container image layer.

### Two flavors of deploy

```
                        ┌──────────────────────┐
                        │  Basic / team mode   │
                        │  ─────────────────   │
                        │  Master key in CI    │
                        │  secret store. App   │
                        │  decrypts at start.  │
                        └──────────────────────┘
                                  vs
                        ┌──────────────────────┐
                        │  Enterprise mode     │
                        │  ─────────────────   │
                        │  Master key in CI +  │
                        │  short-lived TOTP-   │
                        │  bound unseal token  │
                        │  per deploy.         │
                        └──────────────────────┘
```

The basic flow is one moving part. Enterprise is two — a master key
that lives long-term in your secret store, plus a token that's minted
fresh for each deploy, tied to a TOTP code, and expires in seconds.

### Basic mode flow

```
   ┌──────────────────┐
   │ CI secret store  │   AWS Secrets Manager / Azure Key Vault /
   │ SEALED_ENV_KEY   │   GitHub Actions secrets / Jenkins creds…
   └────────┬─────────┘
            │
            │ (injected as env var into the deploy job)
            ▼
   ┌──────────────────┐
   │ deploy job /     │
   │ container start  │
   │                  │   sealed-env decrypt .env.sealed > .env
   │                  │   ./run-app
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ App reads .env   │
   └──────────────────┘
```

Or — for unattended deploys (K8s, autoscaling, serverless) —
**let the app read `.env.sealed` directly**:

- Spring Boot: add `sealed-env-spring-boot-starter`. The starter
  decrypts in-process at startup and exposes every key via Spring's
  `Environment`.
- Node: `import { loadSealedEnv } from 'sealed-env'` at the top of
  your entry file before any other module reads `process.env`.

This way no plaintext `.env` ever exists on disk — the decrypted
values live only in process memory.

> ⚠️ **Trade-off:** this is the convenient path, but the server
> ends up holding both the master key AND the sealed file. An
> attacker with read-access to both can decrypt offline indefinitely.
> If your deploys are operator-supervised, **Model A (host-side
> decrypt)** has a higher security ceiling. See
> [10-decrypt-strategies.md](./10-decrypt-strategies.md) for the
> full trade-off and `sealed-env deploy --remote`.

### Enterprise mode flow — TOTP-bound deploy

```
   ┌──────────────────┐                ┌──────────────────┐
   │ Operator's phone │                │ CI secret store  │
   │ TOTP authenticator│               │ SEALED_ENV_KEY   │
   │ (6-digit code)   │                │ SEALED_ENV_SIGN..│
   └────────┬─────────┘                │ SEALED_ENV_TOTP..│
            │                          └────────┬─────────┘
            │                                   │
            ▼                                   ▼
   ┌─────────────────────────────────────────────────────┐
   │ sealed-env unseal --totp <code> --deploy-id <sha>   │
   │   --ttl 300                                         │
   │                                                     │
   │ → mints SEALED_ENV_UNSEAL_TOKEN bound to:           │
   │     • this commit sha                               │
   │     • this 30-second TOTP window                    │
   │     • a 5-minute hard expiry                        │
   └────────────────────────┬────────────────────────────┘
                            │
                            ▼
   ┌─────────────────────────────────────────────────────┐
   │ sealed-env deploy -- docker compose up -d --build   │
   │                                                     │
   │ → validates token, decrypts .env.sealed, injects    │
   │   the plaintext env vars into the child process,    │
   │   wipes the master key from its own memory          │
   └─────────────────────────────────────────────────────┘
```

Why this is stronger than basic mode: **a leaked master key alone
cannot decrypt production secrets**. An attacker also needs the
operator's TOTP secret AND a valid TOTP code AND a fresh-enough mint
window. That gap closes a whole class of CI-compromise attacks.

### `sealed-env deploy` — the production wrapper

Since alpha.7 there's a one-liner that handles the whole choreography:

```bash
sealed-env deploy -- docker compose up -d --build
```

What it does on your behalf:

| Step | Detail |
|---|---|
| Auto-detects `deploy-id` | Reads `git rev-parse HEAD` |
| Refuses dirty working tree | Uncommitted changes wouldn't be in the build |
| Prompts for TOTP (hidden) | No echo, never logged |
| Mints the token in memory | Master key never touches stdout |
| Injects only plaintext vars | Token / signing key never reach the child |
| (Optional) polls health URL | `--health-url http://.../actuator/health` |

Equivalent hand-rolled `deploy.sh`: ~130 lines and several places where
the token can leak via `set -x` or accidental `echo`. The wrapper is
~5 lines on the caller side.

### CI/CD platforms

Each major platform has its own pattern for storing the master key
and minting the token. See [08-cicd-recipes.md](./08-cicd-recipes.md)
for copy-paste configs:

GitHub Actions • GitLab CI • Bitbucket Pipelines • CircleCI • Jenkins
• Azure (Container Apps / App Service / Functions / Pipelines) • AWS
(ECS / Lambda / EC2) • Google Cloud (Cloud Run / GKE) • Vercel •
Netlify • Fly.io • Render • Railway • Heroku • Docker • Kubernetes •
Generic SSH

The pattern is always the same:

1. Master key in the platform's native secret store.
2. (Enterprise) TOTP secret on the deploy job only.
3. Decrypt at the **latest possible moment** — in-process for
   unattended deploys (Model B), or via `deploy --remote` for
   operator-supervised deploys (Model A — higher security ceiling).
4. Cleanup any plaintext `.env` after the process boots.

For the security implications of choosing one over the other, see
[10-decrypt-strategies.md](./10-decrypt-strategies.md).

---

## Cross-cutting concerns

### The auto-loader

Every `sealed-env` CLI invocation runs an auto-loader that:

1. Looks for `.env.local` in the current directory.
2. If found, reads only `SEALED_ENV_*` variables.
3. Skips any variable already set in the actual environment.
4. (If `.sealed-env.json` exists with `{ "storage": "keychain" }`)
   pulls the master key from the OS keychain.

This means: you never `export SEALED_ENV_KEY=...` manually. You just
stay in the project directory and run `sealed-env get|set|edit|...`.

To opt out: `SEALED_ENV_NO_AUTOLOAD=1`.

### Mode upgrades

You can move basic → team → enterprise without re-encrypting:

```bash
# Currently basic, want to add team-mode HMAC integrity:
sealed-env upgrade --to team

# Currently team, want to add enterprise TOTP binding:
sealed-env upgrade --to enterprise
```

The upgrade reads the existing sealed file, generates the missing
keys, writes them to `.env.local`, and re-seals with the new mode.
Existing values are preserved.

### Rotation

If a key leaks, rotate:

```bash
sealed-env rotate
```

This generates a new master key (and signing key, if applicable),
re-encrypts the file in place, and updates `.env.local`. Old
ciphertext is left in `.env.sealed.bak` — useful if you need to
recover from a botched rotation, dangerous if you forget to clean
it up. Treat the `.bak` file as if it still contained the old secret.

For enterprise mode rotation also covers the TOTP secret — see the
"Rotation" section in
[05-enterprise-mode.md](./05-enterprise-mode.md).

---

## Cheat sheet

| You are… | Run this |
|---|---|
| Starting a new project | `sealed-env init` (or `--mode team` / `--mode enterprise`) |
| Adding your first secrets | Edit `.env`, then `sealed-env encrypt .env` |
| Joining an existing project | Receive master key out-of-band, save to `.env.local` |
| Reading a secret | `sealed-env get .env.sealed KEY` |
| Changing one secret | `sealed-env set .env.sealed KEY value` |
| Editing many at once | `sealed-env edit .env.sealed` |
| Reviewing changes in a PR | `sealed-env diff old.sealed new.sealed` |
| Deploying to production (basic) | `sealed-env decrypt .env.sealed` in CI |
| Deploying to production (enterprise) | `sealed-env deploy -- <run command>` |
| Rotating a leaked key | `sealed-env rotate` |
| Upgrading mode | `sealed-env upgrade --to <team\|enterprise>` |

---

## Where to go next

- [03-quickstart-node.md](./03-quickstart-node.md) — Node-specific install + load.
- [04-quickstart-java.md](./04-quickstart-java.md) — Spring Boot starter setup.
- [05-enterprise-mode.md](./05-enterprise-mode.md) — TOTP, deploy IDs, rotation playbook.
- [07-operational-guide.md](./07-operational-guide.md) — for sysadmins & founders, no code.
- [08-cicd-recipes.md](./08-cicd-recipes.md) — copy-paste configs for 17 platforms.
