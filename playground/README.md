# sealed-env playground

A hands-on walkthrough of all three modes — and what happens when an
attacker tampers with a sealed file.

Run the scripts in order. Each one is fully self-contained: it generates
its own keys, seals a sample `.env`, demonstrates the mode, and
decrypts to verify roundtrip. None of the scripts persist anything
sensitive — keys are scoped to the script's own shell.

## Prerequisites

- **Node 20 or 22** with `sealed-env` built locally (run `cd node && npm run build` from the repo root).
- **Bash** (Git Bash on Windows works fine).
- **OpenSSL** for key generation (comes with Git Bash and any Linux/macOS).
- *(optional, for cross-stack)* **Java 17+** with the `sealed-env-core` jar built (`cd java && mvn -B install -DskipTests`).

## Run order

| # | Script | What it shows |
|---|---|---|
| 0 | `00-setup.sh` | Verifies the CLI is built and creates a sample `.env` |
| 1 | `01-basic.sh` | Encrypt + decrypt with master key only |
| 2 | `02-team.sh` | Add HMAC integrity with a separate signing key |
| 3 | `03-enterprise.sh` | TOTP-bound unseal token + deploy challenge |
| 4 | `04-tampering.sh` | Modify the sealed file and watch decryption fail loud |
| 5 | `05-cross-stack.sh` | Seal in Node, decrypt with Java (requires Java jar built) |

## Run each one

```bash
cd playground
./00-setup.sh     # once
./01-basic.sh
./02-team.sh
./03-enterprise.sh
./04-tampering.sh
./05-cross-stack.sh   # optional
```

Each script prints what it's doing and what the resulting file looks
like. **Read the output** — the goal is to understand the format, not
just to see green checkmarks.

## What the scripts deliberately don't do

- **No `.env.sealed` is committed** — every run regenerates artifacts in `playground/out/`.
- **No keys are persisted to disk** — they live only in the shell variables of the running script.
- **No real production secrets** — the sample `.env` has placeholder values like `API_KEY=demo-12345`.

## When something fails

The scripts use `set -euo pipefail`. If one of them errors out:

1. Read the last 10 lines of output. The `sealed-env` CLI prints a
   single explicit error message ("file is corrupted, tampered, or
   wrong key") for any decryption failure — that's intentional, to
   avoid oracle-style information leaks. The hint is in the
   step the script was on, not in the error.
2. Re-run `00-setup.sh` to make sure the CLI is current.
3. If the issue persists, open an issue with the full transcript.
