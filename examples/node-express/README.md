# Node + Express example

Minimal Express server that reads its config from a sealed `.env`
file. Demonstrates the **zero-code-change** integration pattern:
swap `import 'dotenv/config'` for `import 'sealed-env/config'` and
your `process.env` is now decrypted-at-startup.

## Run it in 60 seconds

```bash
cd examples/node-express
npm install

# The library expects SEALED_ENV_KEY in the process environment.
# In production this comes from your orchestrator (K8s Secret, ECS
# task definition, systemd EnvironmentFile, …). For this demo we
# export the toy key directly:
SEALED_ENV_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  npm start
```

Or — if you have the `sealed-env` CLI installed globally (`npm i -g
sealed-env`) — use it as a wrapper, which auto-loads
`SEALED_ENV_KEY` from `.env.local`:

```bash
cp .env.local.example .env.local
sealed-env exec --file .env.sealed -- node index.js
```

Then in another terminal:

```bash
curl http://localhost:3000
```

You should see the decrypted secrets in the JSON response.

> **Heads-up:** `import 'sealed-env/config'` itself does **not**
> auto-load `.env.local` — that auto-load is a CLI-only convenience
> (in 0.1.0). Library users either set `SEALED_ENV_KEY` in their
> shell / orchestrator, or wrap their command with
> `sealed-env exec`. Library-side auto-load is on the 0.1.1 roadmap.

## What's happening

```
   ┌──────────────────┐         ┌──────────────────┐
   │ .env.local       │         │ .env.sealed      │
   │ (master key,     │         │ (ciphertext,     │
   │  gitignored)     │         │  committed)      │
   └────────┬─────────┘         └────────┬─────────┘
            │                            │
            │ auto-loaded by             │ read at startup
            │ sealed-env/config          │ by sealed-env/config
            ▼                            ▼
        ┌────────────────────────────────────┐
        │ process.env populated with:        │
        │   DATABASE_URL=postgresql://...    │
        │   STRIPE_KEY=sk_test_demo...       │
        │   JWT_SECRET=demo-jwt-secret...    │
        │   PORT=3000                        │
        └────────────────────────────────────┘
                       │
                       ▼
                Express server uses
                process.env normally
```

## The demo master key

```
SEALED_ENV_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

This key is **public on GitHub** and exists only to make the example
runnable. The decrypted values (`STRIPE_KEY=sk_test_demo...` etc.) are
intentionally fake. **Never reuse this key in a real project.**

## Try it without the helper

You can decrypt the file by hand to see what's inside:

```bash
SEALED_ENV_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  npx sealed-env decrypt .env.sealed
```

## Adapt for your project

```bash
# 1. In your own project root:
cd my-app
sealed-env init

# 2. Encrypt your existing .env:
sealed-env encrypt .env

# 3. In your entry file, replace dotenv:
# - import 'dotenv/config';
# + import 'sealed-env/config';

# 4. Commit .env.sealed but NEVER .env or .env.local.
```

## Files in this example

```
node-express/
├── .env.sealed             ← committed (encrypted, safe in git)
├── .env.local.example      ← copy to .env.local (master key)
├── index.js                ← Express server
├── package.json
└── README.md               ← this file
```

No `.env` plaintext — that would be gitignored if it existed locally.
