# Decrypt strategies — host-side vs in-process

This page documents an architectural choice that has real security
consequences: **where** the master key meets the sealed file to
produce plaintext. There are two sensible answers, sealed-env
supports both, and the trade-off is significant enough to deserve
its own page rather than be hidden in a footnote.

If you skim only one section, read [Pick the right model for your
threat](#pick-the-right-model-for-your-threat) at the end.

---

## The two models

```
   ┌────────────────────────────────────────────────────────────┐
   │  Model A — host-side decrypt                              │
   │  ───────────────────────────────────                      │
   │                                                            │
   │  Decryption happens on the OPERATOR's machine (or CI       │
   │  runner). Only the resulting plaintext env vars cross      │
   │  into the production server, via an authenticated tunnel.  │
   │                                                            │
   │  Server never holds:  master key · signing key ·           │
   │                       .env.sealed                          │
   └────────────────────────────────────────────────────────────┘

   ┌────────────────────────────────────────────────────────────┐
   │  Model B — in-process decrypt                             │
   │  ────────────────────────────────────                     │
   │                                                            │
   │  The application binary on the production server reads     │
   │  .env.sealed (shipped with the image / git checkout) and   │
   │  decrypts it at startup using the master key, which the    │
   │  orchestrator (K8s, ECS, …) has injected as an env var.    │
   │                                                            │
   │  Server holds:  master key · signing key ·                 │
   │                 .env.sealed · plaintext (in RAM)           │
   └────────────────────────────────────────────────────────────┘
```

Both compile to the same plaintext at runtime. **The difference is
what an attacker who reads the server's filesystem and environment
variables walks away with.**

---

## What the attacker gets

Assume the attacker achieves a non-trivial but plausible level of
access on the production server: read access to the filesystem and
to the running process's environment. (Examples: LFI vulnerability,
stolen disk image, leaked backup, container escape into a sibling
namespace, misconfigured logging that captures `/proc/<pid>/environ`.)

| Capability | Model A (host-side) | Model B (in-process) |
|---|---|---|
| Reads env vars of the app process | Plaintext currently in use | **Plaintext + master key + signing key** |
| Reads the application's filesystem | (No sealed file present) | **`.env.sealed` cipher** |
| Memory of the app process | Plaintext currently in RAM | Plaintext currently in RAM |
| Network capture | (Tunnel encrypted, no key crosses) | (Tunnel encrypted, no key crosses) |
| **Steals everything they have access to and walks away** | Plaintext only — useful for as long as it stays valid | **Master key + ciphertext — decrypt indefinitely, offline** |

The crucial row is the last one. Model A leaves the attacker with
something **time-bound**: the secrets currently in use, no more. Model
B leaves the attacker with something **persistent**: the keys to
re-decrypt every version of the sealed file they ever obtain, forever,
without any further interaction with your systems.

Rotating the master key after a Model B breach **does not recover**
the secrets the attacker already stole. They have a copy.

---

## What enterprise mode changes for Model B

Enterprise mode does not eliminate Model B's weakness, but it
substantially mitigates it.

In enterprise mode, the master key alone is no longer sufficient to
decrypt: a TOTP-bound `unseal_token` is also required, and that token
has a hard 5-minute TTL. After expiry, even a complete copy of the
master key, signing key, and `.env.sealed` is **not enough** to
decrypt offline.

```
   Stolen during the unseal-token window (≤ 5 min):
   master + signing + valid token  →  decrypt works
                                       (so close the window quickly)

   Stolen after the unseal-token expired:
   master + signing + expired token  →  decrypt fails
                                         (Model B approaches Model A's
                                          ceiling once the window closes)
```

The window is small and the operator controls when it opens. For
many threat models, enterprise + Model B is sufficient — the attacker
must also exfiltrate the token before it expires, which limits the
attack to in-progress deploys rather than passive theft of disk
contents.

Basic and team modes do not have this property. **A leaked master
key in basic/team + Model B is decryptable forever.**

---

## When each model is the right answer

```
                     ┌─────────────────────────────┐
                     │  Start here:                │
                     │  Will you ever ssh into the │
                     │  production server during   │
                     │  a deploy?                  │
                     └──────────┬─────────┬────────┘
                                │YES      │NO
                       ┌────────┘         └────────┐
                       ▼                           ▼
              ┌────────────────┐         ┌────────────────────┐
              │ Use Model A    │         │ Will the app       │
              │ via            │         │ frequently restart │
              │ deploy --remote│         │ without an         │
              └────────────────┘         │ operator? (K8s     │
                                         │ rolling, ECS,      │
                                         │ Heroku, Cloud Run) │
                                         └────┬───────┬───────┘
                                              │YES    │NO
                                     ┌────────┘       └────┐
                                     ▼                     ▼
                             ┌──────────────┐    ┌──────────────────┐
                             │ Use Model B  │    │ Either works.    │
                             │ + enterprise │    │ Default to A.    │
                             │ mode (TOTP)  │    └──────────────────┘
                             └──────────────┘
```

The shortest summary:

- **Model A is strictly more secure** at rest on the server. If you
  can run an operator-supervised deploy (or a CI runner with SSH
  reach), prefer it.
- **Model B is more operationally convenient** when the app must
  restart unattended — autoscaling, K8s rolling restart, a serverless
  cold start. It pairs with enterprise mode to close most of its gap.
- **Don't pick by aesthetics.** Pick by which kind of failure
  scenario you're more worried about.

---

## Mapping to the modes

| Mode \ Strategy | Model A | Model B |
|---|---|---|
| **basic** | ✅ Recommended for solo / private repo deploys | ⚠️ Acceptable for low-stakes apps. Master key on server is the trade-off |
| **team** | ✅ Recommended | ⚠️ Same as basic, plus tampering detection |
| **enterprise** | ✅ Strongest combination | ✅ Recommended for K8s / serverless / autoscaling |

Three concrete recipes the rest of this doc spells out:

1. **basic + Model A** for solo developers deploying to a single VPS.
2. **team + Model A** via CI host-side decrypt for shared repos.
3. **enterprise + Model B** for K8s / Cloud Run / Lambda where the app
   must survive operator-less restarts.

---

## Recipe: Model A with `sealed-env deploy --remote`

The CLI command that makes Model A first-class. Replaces a hand-rolled
deploy.sh that would otherwise have to: dial SSH, ship plaintext,
clean up.

### What it does

```
   ┌────────────────────────────────┐
   │ sealed-env deploy --remote     │
   │   user@prod-server             │
   │   --totp 847392                │
   │   -- ./up.sh                   │
   └─────────────┬──────────────────┘
                 │
                 │ 1. Validate working tree clean
                 │    (deploy_id = git rev-parse HEAD)
                 ▼
   ┌────────────────────────────────┐
   │ Mint unseal token (in memory)  │
   │ TTL=300s, bound to commit sha  │
   └─────────────┬──────────────────┘
                 │
                 │ 2. Decrypt .env.sealed locally
                 ▼
   ┌────────────────────────────────┐
   │ Plaintext env vars in memory   │
   │ (master key never touches      │
   │  network or disk again)        │
   └─────────────┬──────────────────┘
                 │
                 │ 3. Open SSH connection
                 ▼
   ┌────────────────────────────────┐
   │ ssh user@prod-server \         │
   │   "env $VARS ./up.sh"          │
   │                                │
   │ Plaintext travels through      │
   │ SSH-encrypted tunnel.          │
   └─────────────┬──────────────────┘
                 │
                 │ 4. Remote child process
                 ▼
   ┌────────────────────────────────┐
   │ App process on server          │
   │   • env vars in process memory │
   │   • no master key on disk      │
   │   • no .env.sealed on disk     │
   │   (or: present but never read  │
   │    by the app — see below)     │
   └────────────────────────────────┘
```

### Command shape

```sh
sealed-env deploy --remote <user@host> \
                  [--file .env.sealed] \
                  [--totp <code>] \
                  [--ssh-key ~/.ssh/id_ed25519] \
                  [--ssh-port 22] \
                  [--health-url <url>] \
                  [--health-timeout 30] \
                  [--allow-dirty] \
                  -- <command> [args...]
```

| Flag | Default | Meaning |
|---|---|---|
| `--remote <user@host>` | (required for Model A) | SSH destination |
| `--file` | `.env.sealed` | Path to the sealed file (read locally) |
| `--totp` | (prompt if enterprise mode) | 6-digit TOTP code |
| `--ssh-key` | `~/.ssh/id_*` (system default) | Identity file |
| `--ssh-port` | `22` | SSH port |
| `--health-url` | (none) | After deploy, poll this URL to verify rollout |
| `--health-timeout` | `30` (seconds) | Polling timeout |
| `--allow-dirty` | `false` | Allow deploy with uncommitted changes (NOT recommended) |
| `-- <cmd>` | (required) | Command to run on the remote host |

### Behaviour

1. **Pre-flight on local machine.**
   - `git rev-parse HEAD` for `deploy_id`.
   - Refuse if working tree is dirty (unless `--allow-dirty`).
   - Validate SSH connectivity to `<user@host>` before doing crypto.
   - In enterprise mode, prompt for TOTP if `--totp` not provided
     (TTY input, no echo, never logged).
2. **Mint unseal token in operator memory.**
   - Token bound to (deploy_id, totp window, ttl=300s).
   - Token is **never written** to disk or stdout.
3. **Decrypt locally.**
   - Read `.env.sealed`, validate token, decrypt to a `Map<String,
     String>` of plaintext env vars.
   - The master/signing/TOTP keys are zeroed in memory after this
     step.
4. **Open SSH connection.**
   - Establishes an authenticated, encrypted tunnel.
   - Spawns the remote command with the decrypted env vars passed
     via the `env` argument (visible only to the spawned child, not
     persisted anywhere on the remote host).
5. **Stream stdout/stderr.**
   - The remote command's output flows through the SSH connection
     to the operator's terminal.
6. **(Optional) Health check.**
   - After the remote command exits, poll `--health-url` until the
     service responds 200 or the timeout elapses.
   - Failure exits non-zero so the operator's deploy script can
     react.

### What ends up where

| Artefact | Operator machine | Network | Server |
|---|---|---|---|
| Master key | RAM during deploy, then zeroed | Never | Never |
| Signing key | RAM during deploy, then zeroed | Never | Never |
| TOTP secret | RAM during deploy, then zeroed | Never | Never |
| Unseal token | RAM during deploy, then zeroed | Never | Never |
| `.env.sealed` | Repo checkout | (Optional: not needed) | Optional — if present, server never reads it |
| Plaintext env vars | RAM during deploy | Through SSH tunnel | RAM of spawned child process |

The server's footprint is intentionally minimal: nothing on disk
that, by itself or in combination with anything else on the server,
yields the plaintext.

### Failure modes the wrapper handles for you

| Hand-rolled `deploy.sh` failure | What `deploy --remote` does |
|---|---|
| Forgetting `set -o nounset` so a typo'd variable silently expands to `""` | Strict validation: every key in `.env.sealed` must be in the env passed to ssh |
| `set -x` accidentally enabled, leaks secrets to logs | Wrapper never echoes secrets, even with `--debug` |
| Token visible in CI logs because of `echo $TOKEN` | Token never crosses stdout |
| SSH connection hangs and operator can't tell why | Connection is validated up-front; explicit timeout and error |
| Working tree dirty — deploy doesn't match the deploy_id token bound to it | Refuses to deploy unless `--allow-dirty` |

### What stays the operator's responsibility

- Managing SSH keys (the wrapper uses your SSH agent / config).
- Rotating credentials when they leak (the wrapper detects nothing
  about the validity of secrets at the destination — that's a
  separate audit concern).
- Reviewing what `<command>` actually does on the remote host.

---

## Recipe: Model B for K8s / serverless

When operator-supervised deploys are not feasible — autoscaling, K8s
rolling restart, Lambda cold start — the app must boot itself with
the sealed file already accessible. Use enterprise mode to keep the
window of exposure tight.

```
   ┌────────────────────────────────────────────────────────────┐
   │ At deploy time (one-shot, by your CI):                    │
   │                                                            │
   │   1. Mint unseal_token bound to (deploy_id, totp, 5min).   │
   │   2. Inject as env var into the orchestrator (K8s Secret,  │
   │      ECS task definition secret, etc.).                    │
   │   3. Pod starts → app reads .env.sealed + master key +     │
   │      unseal_token from env → decrypts.                     │
   │   4. Token expires after 5 minutes. Restart after expiry   │
   │      requires a fresh deploy.                              │
   └────────────────────────────────────────────────────────────┘
```

The 5-minute window is the trade-off. Inside that window, an
attacker with full server access can decrypt. After the window, the
material is inert. **For 99% of an app's lifetime — every minute
that isn't the first 5 of its life — Model B with enterprise is
indistinguishable from Model A in attacker yield.**

If a pod must restart after the token expires, your CI re-runs the
mint step. The pod fails until the new token is in place. This is
the price of unattended deploys plus enterprise security.

For platform-specific recipes (K8s Secret, ECS Task Definition,
Lambda Layer, etc.) see [08-cicd-recipes.md](./08-cicd-recipes.md).

---

## Pick the right model for your threat

A quick table to anchor the decision. Pick the row that best matches
your situation; the column tells you the recommended strategy.

| Your situation | Recommended | Rationale |
|---|---|---|
| Solo dev, single VPS, manual deploys | basic + Model A | Simplest viable. Master key never on server. |
| Small team, shared repo, low-stakes app | team + Model A | HMAC integrity + host-side decrypt. |
| Small team, small infra, can SSH from CI | team + Model A | CI runs `deploy --remote`. Server stays clean. |
| Banking / regulated data, manual deploy windows | enterprise + Model A | Highest ceiling possible from a single library. |
| Banking / regulated data, autoscaling pods | enterprise + Model B | TOTP-bound token closes the window quickly. |
| K8s rolling restart, no operator presence | enterprise + Model B | Operator supervision impractical; accept the 5-min window. |
| Lambda / Cloud Run with cold starts | enterprise + Model B | Same. Mint token at deploy time, accept the window. |

---

## Implementation reality

`sealed-env deploy --remote` is implemented in the **Node CLI**
(npm package `sealed-env`). Java users invoke the same Node CLI to
operate their sealed files; the Java side ships as a library plus a
Spring Boot starter for the application runtime. This division is
intentional: the wire format is what makes the project "cross-stack",
not the operator tooling. A Maven-distributed CLI is on the roadmap
for 0.2.0 — until then, install the Node CLI as you would `git`,
`docker`, or any other ops tool.

```sh
npm install -g sealed-env   # installs the `sealed-env` CLI
sealed-env deploy --remote user@prod -- ./up.sh
```

## Future direction

Three improvements on the roadmap close the remaining gap:

1. **Java CLI parity (0.2.0).** Maven-distributed `sealed-env-cli`
   module so JVM-only shops can operate without Node on the
   operator's machine. Mirrors the Node CLI command-for-command.

2. **Sidecar pattern (0.2.0).** Master key lives in a separate
   process with stricter capabilities; app reads plaintext via Unix
   socket. Container escape into the app process no longer yields
   the master key. Documented as a reference implementation, not a
   library feature.

3. **Hardware-backed wrap (1.0).** Master key wrapped by TPM /
   Secure Enclave / YubiKey. A complete copy of operator's `.env.local`
   plus the sealed file plus all keys is still useless without the
   physical device. Eliminates the "stolen laptop" failure mode.

None of these block 0.1.0 stable. They are non-breaking additions to
a stable wire format.

---

## Cross-references

- [01-overview.md](./01-overview.md) — what sealed-env is and isn't
- [02-threat-model.md](./02-threat-model.md) — full threat enumeration
- [05-enterprise-mode.md](./05-enterprise-mode.md) — TOTP + deploy binding
- [08-cicd-recipes.md](./08-cicd-recipes.md) — per-platform deploy configs
- [09-lifecycle.md](./09-lifecycle.md) — full project lifecycle
