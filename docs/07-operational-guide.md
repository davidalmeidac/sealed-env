# Operational guide — for sysadmins, managers, and founders

This page is for the people who **don't write code every day** but need
to read, change, or hand off a `.env.sealed` file. No cryptography
required.

If you're a developer integrating sealed-env into an app, see
[03-quickstart-node.md](./03-quickstart-node.md) or
[04-quickstart-java.md](./04-quickstart-java.md).

---

## What is `.env.sealed`?

It's an encrypted version of your `.env` file. Same idea as a regular
`.env` (a list of `KEY=value` pairs) but readable only to whoever has
the master key. The sealed file is **safe to commit to git**.

```
.env             ← plaintext, NEVER commit, NEVER share
.env.sealed      ← encrypted, safe in git, safe in chat, safe on disk
```

The master key lives in **one** environment variable:
`SEALED_ENV_KEY`. Whoever has that key can read the file.

---

## The five things you'll actually do

### 1. Read one variable

```sh
sealed-env get .env.sealed DATABASE_URL
```

Prints just the value. Nothing else. You can pipe it:

```sh
psql "$(sealed-env get .env.sealed DATABASE_URL)"
```

### 2. Change one variable

```sh
sealed-env set .env.sealed STRIPE_KEY "sk_live_new_value_here"
```

Re-seals the file in place. The previous file is saved as
`.env.sealed.bak` so you can roll back if something went wrong.

### 3. Edit several variables at once

```sh
sealed-env edit .env.sealed
```

Opens your editor (`$EDITOR`, defaults to `vi` on Linux/macOS,
`notepad` on Windows) with the plaintext. When you save and exit,
sealed-env re-seals the file. The plaintext is held in RAM (Linux:
`/dev/shm` tmpfs — never touches disk) and wiped on exit.

### 4. See the whole file (read-only)

```sh
sealed-env decrypt .env.sealed | less
```

Or in a Git Bash / PowerShell session:

```sh
sealed-env decrypt .env.sealed
```

**Don't redirect this to a file you might forget about.** Pipe it to
your pager, your editor's stdin, or another tool — never to disk.

### 5. Compare two versions

```sh
sealed-env diff .env.sealed.bak .env.sealed
```

Shows which keys changed, were added, or were removed. Values are
hidden by default. Add `--show-values` if you actually need to see the
secrets.

---

## Common situations

### A developer asks "what's the value of `XYZ_API_KEY` in production?"

```sh
sealed-env get prod/.env.sealed XYZ_API_KEY
```

Don't paste the answer into Slack or email. If they need to use it,
share the encrypted file and the master key separately, through
different channels.

### A new dev needs to run the project locally

Give them:

1. The repo (which already contains `.env.sealed`).
2. The **dev** master key, through a secure channel (1Password,
   Bitwarden, signed Slack message, in person).

They run:

```sh
git clone <repo>
cd <repo>
export SEALED_ENV_KEY=...           # from secure channel
sealed-env decrypt .env.sealed > .env  # one-time, into gitignored .env
npm run dev
```

…or, if your team uses sealed-env's Spring Boot starter / Node
loader, they don't need to decrypt at all — the app reads the sealed
file directly.

### You need to rotate a leaked secret

```sh
# 1. Set the new value
sealed-env set .env.sealed LEAKED_KEY "the-new-rotated-value"

# 2. Verify it took
sealed-env get .env.sealed LEAKED_KEY

# 3. Commit the change
git add .env.sealed
git commit -m "chore: rotate LEAKED_KEY"
git push
```

Then revoke the old key wherever it was issued (Stripe dashboard, AWS
console, etc.).

### You need to check what changed in a PR

```sh
git checkout <pr-branch>
git fetch origin main
sealed-env diff <(git show origin/main:.env.sealed) .env.sealed
```

(On Windows / without process substitution, save the two versions to
files first.) This tells you which secrets the PR is changing without
revealing the values.

---

## What about production?

For production deploys you can use the same `decrypt` flow with the
master key in a secure environment variable, **or** you can use
**enterprise mode** which adds a second factor: a TOTP-bound,
short-lived "unseal token" that only allows decryption on a specific
deploy.

See [05-enterprise-mode.md](./05-enterprise-mode.md). The short
version: developers can read the file with the master key alone, but
the production server needs both the master key **and** a fresh
unseal token signed at deploy time. A leaked master key alone is not
enough to decrypt production secrets.

---

## How do I include this in code?

You don't strictly have to. The CLI is enough for most workflows: a
deploy script can run `sealed-env decrypt` to populate environment
variables before starting the app.

But if you want the app itself to read the sealed file directly:

### Spring Boot

Add the starter to `pom.xml`:

```xml
<dependency>
  <groupId>io.github.davidalmeidac</groupId>
  <artifactId>sealed-env-spring-boot-starter</artifactId>
  <version>0.1.0-alpha.3</version>
</dependency>
```

Place `.env.sealed` at the project root. Set `SEALED_ENV_KEY`
in the deployment environment. That's it — every key in the sealed
file is now available via `@Value("${KEY}")` and Spring's
`Environment` like any other property.

### Node.js

```js
import { loadSealedEnv } from 'sealed-env';

// At the very top of your entry file, before any other imports
// that might read process.env:
await loadSealedEnv('.env.sealed');

// Now process.env.DATABASE_URL etc. are populated.
```

Or use the CLI in your start script:

```json
{
  "scripts": {
    "start": "sealed-env decrypt .env.sealed | xargs -I {} env {} node server.js"
  }
}
```

(On Linux / macOS. On Windows use a small wrapper script.)

---

## What it costs

- **Performance:** seal/unseal takes ~50–200 ms once at startup. Zero
  runtime overhead after that.
- **Operations:** one extra environment variable (`SEALED_ENV_KEY`)
  to manage in your deployment system.
- **Mental model:** one new file (`.env.sealed`) and one new gitignore
  entry (`.env`).

That's the whole tax. There's no server to run, no SaaS to pay for,
no key-management vault to integrate.

---

## What it does NOT do

- It does not store, sync, or rotate secrets for you. If a secret
  leaks, you still have to revoke it at the source (Stripe, AWS,
  GitHub, etc.).
- It does not replace a full secret manager (HashiCorp Vault, AWS
  Secrets Manager) for organizations that need fine-grained access
  control, audit logs, and dynamic secret generation.
- It does not protect against an attacker who has root on the running
  server — once decrypted in memory, the secrets are reachable like
  any other process memory. (Same as every other secret manager.)

For when sealed-env is the right tool and when it isn't, see the
"When to pick which" section in the main [README](../README.md).

---

## Cheatsheet

| Task                              | Command                                                 |
| --------------------------------- | ------------------------------------------------------- |
| Read one variable                 | `sealed-env get .env.sealed KEY`                        |
| Change one variable               | `sealed-env set .env.sealed KEY value`                  |
| Edit several at once              | `sealed-env edit .env.sealed`                           |
| Print the whole file              | `sealed-env decrypt .env.sealed`                        |
| Compare two versions              | `sealed-env diff old.sealed new.sealed`                 |
| Compare with values shown         | `sealed-env diff old new --show-values`                 |
| Show available commands           | `sealed-env help`                                       |

All commands need `SEALED_ENV_KEY` set in the environment. Team and
enterprise modes also need `SEALED_ENV_SIGNING_KEY` (and, for
enterprise, a TOTP secret or unseal token — see the enterprise
guide).
