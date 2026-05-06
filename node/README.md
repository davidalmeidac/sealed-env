<p align="center">
  <img src="https://raw.githubusercontent.com/davidalmeidac/sealed-env/main/assets/logo-sigillum-mono.svg" alt="sealed-env" width="160" />
</p>

# sealed-env

> Encrypted `.env` files with optional TOTP unsealing for production deploys.
> Cross-stack with the Java port. Zero runtime dependencies.

[![npm version](https://img.shields.io/npm/v/sealed-env?style=flat-square&color=1a1612&labelColor=c4471f&logo=npm&logoColor=f4ede0)](https://www.npmjs.com/package/sealed-env)
[![npm downloads](https://img.shields.io/npm/dm/sealed-env?style=flat-square&color=1a1612&labelColor=c4471f)](https://www.npmjs.com/package/sealed-env)
[![License](https://img.shields.io/badge/license-MIT-1a1612?style=flat-square&labelColor=c4471f)](LICENSE)
[![Threat model](https://img.shields.io/badge/threat--model-public-1a1612?style=flat-square&labelColor=c4471f)](https://github.com/davidalmeidac/sealed-env/blob/main/THREAT_MODEL.md)

```bash
npm install sealed-env
```

## Why

In **2025**, supply-chain attacks on the JavaScript ecosystem stole **thousands of plaintext
secrets** from CI/CD pipelines and developer machines. The Shai-Hulud worm (Nov 2025)
compromised over **25,000 repositories** by scanning `.env` files and exfiltrating their
contents to public GitHub repos. The tj-actions/changed-files attack (Mar 2025) read
secrets directly from CI Runner memory.

Plaintext `.env` is dead. And encryption-at-rest alone isn't enough — when the master
key leaks (and it does), the entire vault opens.

`sealed-env` solves both halves.

## What it does

- Encrypts your secrets with **AES-256-GCM** at rest.
- For production: requires a fresh **TOTP code from a human operator** before each deploy.
- Even if your CI key leaks, attackers cannot decrypt without the operator's phone.
- **Cross-stack:** the same `.env.sealed` file works in Node and in Java/Spring Boot.
- **Zero runtime dependencies.** Only Node's built-in `crypto` and `fs`.

## Quick start

### 1. Initialize

```bash
npx sealed-env init --mode basic
```

This generates a master key and saves it to `.env.local` (auto-gitignored).

### 2. Encrypt your existing `.env`

```bash
npx sealed-env encrypt .env
```

You now have `.env.sealed` — commit it to your repo.

### 3. Use in code (auto-load)

```ts
import 'sealed-env/config';

console.log(process.env.STRIPE_API_KEY); // resolved from .env.sealed
```

### 4. (Optional) Use the API directly

```ts
import { loadSealed } from 'sealed-env';

const env = loadSealed({ path: '.env.sealed', populate: true });
console.log(env.STRIPE_API_KEY);
```

## Three security modes

```bash
npx sealed-env init --mode basic       # personal projects
npx sealed-env init --mode team        # small teams, staging
npx sealed-env init --mode enterprise  # production with TOTP unseal
```

|  | basic | team | enterprise |
|---|:---:|:---:|:---:|
| AES-256-GCM | ✓ | ✓ | ✓ |
| HMAC integrity tag | — | ✓ | ✓ |
| TOTP unseal required | — | — | ✓ |
| Deploy-bound tokens | — | — | ✓ |

## Enterprise mode: production deploys

```bash
# In CI, the deploy job pauses waiting for an operator. Operator runs:
$ npx sealed-env unseal --deploy-id <commit-sha>
> Enter 6-digit TOTP code: 482914

✓ Unseal token (expires in 60s):
usl_eyJhbGciOiJIUzI1NiIsInR5cCI6InNlYWxlZC1lbnYtdW5zZWFsL3YxIn0...

# Operator pastes the token into CI. The deploy continues with:
SEALED_ENV_KEY=...
SEALED_ENV_SIGNING_KEY=...
SEALED_ENV_UNSEAL_TOKEN=usl_...
SEALED_ENV_DEPLOY_ID=<commit-sha>

# Application starts:
node --import sealed-env/config app.js
```

If the master key later leaks, attackers still need a fresh TOTP. If a token is captured,
it's only valid for that one deploy and expires within seconds.

## Comparison

|  | sealed-env | dotenvx | dotenv-vault | jasypt |
|---|---|---|---|---|
| Node + Java with shared format | **✓** | ✗ | ✗ | ✗ |
| Zero dependencies | **✓** | ✗ | ✗ | n/a |
| TOTP unseal for production | **✓** | ✗ | ✗ | ✗ |
| Memory wipe after ingestion | **✓** | ✗ | ✗ | ✗ |
| Public threat model | **✓** | partial | partial | ✗ |
| Vendor-neutral (no service) | **✓** | ✓ | ✗ | ✓ |

## Status

**v0.1.0-alpha** — early. API is stabilizing. The `.env.sealed` v1 format is
**frozen** and will remain readable forever.

## Documentation

- 🔐 [Threat model](https://github.com/davidalmeidac/sealed-env/blob/main/THREAT_MODEL.md)
- 📐 [File format spec](https://github.com/davidalmeidac/sealed-env/blob/main/SPEC.md)
- 🛡️ [Security policy](https://github.com/davidalmeidac/sealed-env/blob/main/SECURITY.md)
- 📚 [Full docs](https://github.com/davidalmeidac/sealed-env)

## License

[MIT](LICENSE) — David Almeida, 2026.
