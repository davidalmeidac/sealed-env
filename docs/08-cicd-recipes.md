# CI/CD + cloud recipes

Copy-paste configurations for the most common deploy targets. Every
recipe boils down to the same three steps:

1. Store the **master key** (`SEALED_ENV_KEY`) in the platform's
   secret store. Never commit it.
2. At deploy time, expose it as an environment variable.
3. Either run the app with the sealed-env loader **or** decrypt to
   `.env` once at startup.

For enterprise mode, you also need `SEALED_ENV_SIGNING_KEY` and a
short-lived `SEALED_ENV_UNSEAL_TOKEN` minted at deploy time. See
[05-enterprise-mode.md](./05-enterprise-mode.md) for the security
rationale.

> 💡 In every recipe: the **plaintext** `.env` should never appear in
> CI logs, build artifacts, or container images. Decrypt at the latest
> possible moment — ideally inside the running container, not during
> the build.

---

## Table of contents

- [GitHub Actions](#github-actions)
- [GitLab CI/CD](#gitlab-cicd)
- [AWS (ECS / Lambda / EC2)](#aws)
- [Google Cloud (Cloud Run / GKE)](#google-cloud)
- [Vercel](#vercel)
- [Netlify](#netlify)
- [Fly.io](#flyio)
- [Render](#render)
- [Heroku](#heroku)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Generic SSH deploys](#generic-ssh-deploys)

---

## GitHub Actions

### 1. Store the master key

`Settings → Secrets and variables → Actions → New repository secret`

| Name                      | Value                                |
| ------------------------- | ------------------------------------ |
| `SEALED_ENV_KEY`          | hex or base64 master key             |
| `SEALED_ENV_SIGNING_KEY`  | (team / enterprise modes only)       |
| `SEALED_ENV_TOTP_SECRET`  | (enterprise — only on the *deploy* job) |

For multi-environment setups use **GitHub Environments** (`Settings →
Environments`) so `production` secrets are only available to jobs that
target the `production` environment, with required reviewers.

### 2. Basic mode — decrypt at runtime

```yaml
# .github/workflows/deploy.yml
name: deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    env:
      SEALED_ENV_KEY: ${{ secrets.SEALED_ENV_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - run: npx sealed-env decrypt .env.sealed > .env
      - run: npm run deploy   # your deploy command
      - run: shred -u .env || rm -f .env  # belt and suspenders
```

### 3. Enterprise mode — mint an unseal token in the job

```yaml
- name: Mint unseal token
  env:
    SEALED_ENV_KEY: ${{ secrets.SEALED_ENV_KEY }}
    SEALED_ENV_TOTP_SECRET: ${{ secrets.SEALED_ENV_TOTP_SECRET }}
  run: |
    TOKEN=$(npx sealed-env unseal \
      --file .env.sealed \
      --deploy-id "${GITHUB_SHA}" \
      --ttl 300)
    echo "::add-mask::$TOKEN"
    echo "SEALED_ENV_UNSEAL_TOKEN=$TOKEN" >> "$GITHUB_ENV"
    echo "SEALED_ENV_DEPLOY_ID=${GITHUB_SHA}" >> "$GITHUB_ENV"

- name: Deploy
  env:
    SEALED_ENV_KEY: ${{ secrets.SEALED_ENV_KEY }}
    SEALED_ENV_SIGNING_KEY: ${{ secrets.SEALED_ENV_SIGNING_KEY }}
    # SEALED_ENV_UNSEAL_TOKEN and SEALED_ENV_DEPLOY_ID inherited from $GITHUB_ENV
  run: ./deploy.sh
```

`::add-mask::` registers the token as a secret so it gets `***`-ed in
logs even if echoed.

---

## GitLab CI/CD

Store the master key as a **masked, protected** CI/CD variable:
`Settings → CI/CD → Variables`. Mark it `Protected` so only protected
branches/tags can use it, and `Masked` so it never appears in logs.

```yaml
# .gitlab-ci.yml
stages: [deploy]

deploy:
  stage: deploy
  image: node:20
  variables:
    SEALED_ENV_KEY: $SEALED_ENV_KEY
  only:
    - main
  script:
    - npm ci
    - npx sealed-env decrypt .env.sealed > .env
    - ./deploy.sh
  after_script:
    - rm -f .env
```

For enterprise mode, mint the unseal token in a script step (same
pattern as GitHub Actions above) and export it via `dotenv` artifacts:

```yaml
mint-token:
  stage: prepare
  script:
    - TOKEN=$(npx sealed-env unseal --file .env.sealed --deploy-id "$CI_COMMIT_SHA" --ttl 300)
    - echo "SEALED_ENV_UNSEAL_TOKEN=$TOKEN" > unseal.env
    - echo "SEALED_ENV_DEPLOY_ID=$CI_COMMIT_SHA" >> unseal.env
  artifacts:
    reports:
      dotenv: unseal.env
```

---

## AWS

The recommended pattern: keep the **master key** in **AWS Secrets
Manager** (or SSM Parameter Store), and let the running instance
fetch it via IAM. Never put the key in the AMI, the container image,
or environment definitions stored in plaintext.

### ECS (Fargate)

Store the master key as a secret:

```sh
aws secretsmanager create-secret \
  --name prod/sealed-env-key \
  --secret-string "$(cat sealed-env.key)"
```

Reference it from the task definition:

```json
{
  "containerDefinitions": [{
    "name": "app",
    "image": "...",
    "secrets": [
      { "name": "SEALED_ENV_KEY",
        "valueFrom": "arn:aws:secretsmanager:...:secret:prod/sealed-env-key" }
    ],
    "command": ["sh", "-c",
      "sealed-env decrypt /app/.env.sealed > /app/.env && exec node server.js"]
  }]
}
```

Or, with the Spring Boot starter / Node loader, skip the
`> /app/.env` step entirely and let the app read `.env.sealed`
directly.

### Lambda

Use the [Lambda extension for Secrets Manager / Parameter Store](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html)
to fetch the master key, then in your handler init:

```js
import { loadSealedEnv } from 'sealed-env';
process.env.SEALED_ENV_KEY = await fetchSecretFromExtension();
await loadSealedEnv('./.env.sealed');
```

Done **at cold start** so warm invocations skip the work.

### EC2

Attach an IAM role with `secretsmanager:GetSecretValue` on the key
ARN. In your systemd unit:

```ini
[Service]
ExecStartPre=/usr/local/bin/fetch-key.sh
EnvironmentFile=/run/sealed-env.env
ExecStart=/usr/bin/node /app/server.js
```

`fetch-key.sh` writes `SEALED_ENV_KEY=...` to `/run/sealed-env.env`
(tmpfs) and the app picks it up from there. The sealed file is
shipped with the AMI / git checkout; only the master key is fetched
at boot.

---

## Google Cloud

Same pattern using **Secret Manager**.

### Cloud Run

```sh
# Create the secret
echo -n "<hex master key>" | \
  gcloud secrets create sealed-env-key --data-file=-

# Deploy with the secret mounted as an env var
gcloud run deploy my-app \
  --image=gcr.io/.../my-app \
  --update-secrets=SEALED_ENV_KEY=sealed-env-key:latest \
  --command="sealed-env" \
  --args="decrypt,/app/.env.sealed"
```

In practice you'll wrap the start command:

```dockerfile
CMD ["sh", "-c", "sealed-env decrypt .env.sealed > .env && exec node server.js"]
```

### GKE (Kubernetes on GCP)

Use [External Secrets Operator](https://external-secrets.io/) or
[GKE Workload Identity + Secret Manager CSI](https://cloud.google.com/secret-manager/docs/secret-manager-managed-csi-component)
to pull `SEALED_ENV_KEY` into the pod, then see the
[Kubernetes section](#kubernetes) below.

---

## Vercel

Vercel supports environment variables per environment (Production /
Preview / Development) in `Settings → Environment Variables`.

1. Add `SEALED_ENV_KEY` (and `SEALED_ENV_SIGNING_KEY` for team mode)
   for each environment.
2. Commit `.env.sealed` to the repo (`vercel.json` doesn't ignore it).
3. Load it in your Next.js / Node server at startup:

```js
// instrumentation.ts (Next.js 14+) or top of server.js
import { loadSealedEnv } from 'sealed-env';
await loadSealedEnv('./.env.sealed');
```

For **build-time** secrets (used during `next build`), Vercel injects
the env vars before the build step runs, so `loadSealedEnv` works
there too if you call it from a `prebuild` script.

> ⚠️ Enterprise mode (TOTP-bound unseal tokens) is hard to do on
> Vercel because there's no separate "deploy" step you control —
> minting a token requires running a command after the deploy
> infrastructure has settled on a deploy ID. Stick to **basic** or
> **team** mode on serverless platforms unless you're orchestrating
> deploys from your own CI.

---

## Netlify

Same idea as Vercel: add `SEALED_ENV_KEY` in `Site settings →
Environment variables`. For Netlify Functions, load the sealed file
inside the handler:

```js
import { loadSealedEnv } from 'sealed-env';
let loaded = false;
export const handler = async (event) => {
  if (!loaded) { await loadSealedEnv('./.env.sealed'); loaded = true; }
  // ... handler code
};
```

---

## Fly.io

```sh
fly secrets set SEALED_ENV_KEY="$(cat sealed-env.key)"
fly secrets set SEALED_ENV_SIGNING_KEY="$(cat sealed-env-signing.key)"
```

In your `Dockerfile`:

```dockerfile
CMD ["sh", "-c", "sealed-env decrypt .env.sealed > .env && exec node server.js"]
```

Or use the Node/Java loader directly without writing a `.env` file.

---

## Render

`Dashboard → your service → Environment → Add Environment Variable`
for `SEALED_ENV_KEY`. Render injects env vars before your start
command runs, so:

```yaml
# render.yaml
services:
  - type: web
    name: my-app
    env: node
    buildCommand: npm ci && npm run build
    startCommand: sealed-env decrypt .env.sealed > .env && node server.js
```

---

## Heroku

```sh
heroku config:set SEALED_ENV_KEY="$(cat sealed-env.key)" -a my-app
```

In your `Procfile`:

```
web: sealed-env decrypt .env.sealed > .env && node server.js
```

---

## Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
# .env.sealed IS shipped with the image; the master key is NOT.
ENTRYPOINT ["sh", "-c"]
CMD ["sealed-env decrypt .env.sealed > .env && exec node server.js"]
```

Pass the key at run time:

```sh
docker run --rm \
  -e SEALED_ENV_KEY="$SEALED_ENV_KEY" \
  -p 3000:3000 \
  my-app
```

> 🚨 **Never** bake the master key into the image with `ENV
> SEALED_ENV_KEY=...` or by `COPY`-ing a key file. Anyone who pulls
> the image can read it.

For multi-stage builds the same rule applies: pass the key as a
runtime variable, never as a build arg.

---

## Kubernetes

Store the master key as a `Secret`, mount it as an env var in the
pod spec.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sealed-env-keys
type: Opaque
stringData:
  SEALED_ENV_KEY:         "<hex master key>"
  SEALED_ENV_SIGNING_KEY: "<hex signing key>"
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: my-app }
spec:
  replicas: 2
  selector: { matchLabels: { app: my-app } }
  template:
    metadata: { labels: { app: my-app } }
    spec:
      containers:
        - name: app
          image: my-app:latest
          envFrom:
            - secretRef:
                name: sealed-env-keys
          # The .env.sealed file is baked into the image. The keys
          # are mounted from the Secret. The two never live in the
          # same artifact.
```

For production-grade setups, use [External Secrets Operator](https://external-secrets.io/)
to source `SEALED_ENV_KEY` from AWS Secrets Manager / GCP Secret
Manager / HashiCorp Vault instead of a static `Secret` object.

---

## Generic SSH deploys

For a plain VPS where you `ssh user@host` and `git pull`:

```sh
# On the server, in /etc/systemd/system/my-app.service.d/override.conf:
[Service]
Environment="SEALED_ENV_KEY=<hex master key>"

# .env.sealed lives in the git checkout. App reads it directly via
# the Node loader / Spring Boot starter. No plaintext .env on disk.
```

`systemd` env files (`EnvironmentFile=`) are world-unreadable when
mode is `0600`. That's the closest a VPS gets to a managed secret
store; if you outgrow it, move to AWS Secrets Manager / GCP Secret
Manager.

---

## Audit checklist

Before you sign off on any of the above, verify:

- [ ] The master key is **not** in the repo, the build artifact, or
      the container image.
- [ ] CI logs are scrubbed (`::add-mask::`, GitLab `Masked` flag,
      etc.).
- [ ] The plaintext `.env` (if you decrypt to a file) is on tmpfs or
      gets `rm`'d after the process starts.
- [ ] The IAM role / service account that fetches the master key has
      the **minimum** scope: read on one secret, nothing else.
- [ ] Rotation is documented: someone else on the team knows how to
      rotate `SEALED_ENV_KEY` if you're hit by a bus.

For the rotation playbook, see the "Rotation" section in
[05-enterprise-mode.md](./05-enterprise-mode.md).
