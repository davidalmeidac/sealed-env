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

> ⚠️ **Choice of decrypt strategy matters.** Most recipes below show
> Model B (the app on the server reads `.env.sealed` and decrypts at
> startup). Model A (decrypt on the operator/CI host, ship only
> plaintext through SSH) has a strictly higher security ceiling at
> rest on the server but requires a supervised deploy. See
> [10-decrypt-strategies.md](./10-decrypt-strategies.md) for the
> trade-off and how to pick.

---

## Table of contents

- [GitHub Actions](#github-actions)
- [GitLab CI/CD](#gitlab-cicd)
- [Bitbucket Pipelines](#bitbucket-pipelines)
- [CircleCI](#circleci)
- [Jenkins](#jenkins)
- [Azure (Container Apps / App Service / Functions / Pipelines)](#azure)
- [AWS (ECS / Lambda / EC2)](#aws)
- [Google Cloud (Cloud Run / GKE)](#google-cloud)
- [Vercel](#vercel)
- [Netlify](#netlify)
- [Fly.io](#flyio)
- [Render](#render)
- [Railway](#railway)
- [Heroku](#heroku)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Generic SSH deploys](#generic-ssh-deploys)
- [OIDC federation (advanced)](#oidc-federation-advanced--ci-never-holds-the-master-key)

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

## Bitbucket Pipelines

Store the master key as a **secured** repository variable: `Repository
settings → Repository variables → Add variable` and tick the **Secured**
checkbox so it's masked in logs.

```yaml
# bitbucket-pipelines.yml
image: node:20

pipelines:
  branches:
    main:
      - step:
          name: Deploy
          deployment: production
          script:
            - npm ci
            - npx sealed-env decrypt .env.sealed > .env
            - ./deploy.sh
          after-script:
            - rm -f .env
```

For multi-environment setups use **Deployments** (`Repository settings →
Deployments`) with environment-scoped variables. Production-scoped
variables only become available to steps with `deployment: production`.

For enterprise mode, mint the unseal token in the same step and pass it
forward via an artifact or environment file:

```yaml
- step:
    name: Mint and deploy
    deployment: production
    script:
      - export TOKEN=$(npx sealed-env unseal \
          --file .env.sealed \
          --deploy-id "$BITBUCKET_COMMIT" \
          --ttl 300)
      - export SEALED_ENV_UNSEAL_TOKEN="$TOKEN"
      - export SEALED_ENV_DEPLOY_ID="$BITBUCKET_COMMIT"
      - ./deploy.sh
```

---

## CircleCI

Add the master key in `Project Settings → Environment Variables`. For
team-shared keys, use a **Context** (`Organization Settings → Contexts`)
so multiple projects can share secrets without duplicating them.

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  deploy:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run: npm ci
      - run:
          name: Decrypt sealed env
          command: npx sealed-env decrypt .env.sealed > .env
      - run:
          name: Deploy
          command: ./deploy.sh
      - run:
          name: Cleanup
          command: rm -f .env
          when: always

workflows:
  deploy:
    jobs:
      - deploy:
          context: production-secrets   # injects SEALED_ENV_KEY
          filters:
            branches: { only: main }
```

Enterprise mode — mint the token in a dedicated step, persist it via
`BASH_ENV` so subsequent steps inherit it:

```yaml
- run:
    name: Mint unseal token
    command: |
      TOKEN=$(npx sealed-env unseal \
        --file .env.sealed \
        --deploy-id "$CIRCLE_SHA1" \
        --ttl 300)
      echo "export SEALED_ENV_UNSEAL_TOKEN=$TOKEN" >> $BASH_ENV
      echo "export SEALED_ENV_DEPLOY_ID=$CIRCLE_SHA1" >> $BASH_ENV
```

---

## Jenkins

Most enterprise / banking pipelines run here. Store the master key as a
**Secret text** credential (`Manage Jenkins → Credentials → System →
Global → Add Credentials`) with ID `sealed-env-key`.

### Declarative pipeline

```groovy
// Jenkinsfile
pipeline {
  agent any

  environment {
    SEALED_ENV_KEY = credentials('sealed-env-key')
  }

  stages {
    stage('Deploy') {
      when { branch 'main' }
      steps {
        sh 'npm ci'
        sh 'npx sealed-env decrypt .env.sealed > .env'
        sh './deploy.sh'
      }
      post {
        always { sh 'rm -f .env' }
      }
    }
  }
}
```

`credentials('sealed-env-key')` automatically masks the value in console
output. Never `echo $SEALED_ENV_KEY` — even though Jenkins masks it,
it's a habit worth not building.

### Scripted pipeline (legacy)

```groovy
node {
  withCredentials([string(credentialsId: 'sealed-env-key',
                          variable: 'SEALED_ENV_KEY')]) {
    sh 'npm ci'
    sh 'npx sealed-env decrypt .env.sealed > .env'
    sh './deploy.sh'
  }
}
```

### Enterprise mode

```groovy
stage('Mint unseal token') {
  environment {
    SEALED_ENV_KEY        = credentials('sealed-env-key')
    SEALED_ENV_TOTP_SECRET = credentials('sealed-env-totp')
  }
  steps {
    script {
      env.SEALED_ENV_UNSEAL_TOKEN = sh(
        script: """npx sealed-env unseal \\
                     --file .env.sealed \\
                     --deploy-id "${env.GIT_COMMIT}" \\
                     --ttl 300""",
        returnStdout: true
      ).trim()
      env.SEALED_ENV_DEPLOY_ID = env.GIT_COMMIT
    }
  }
}
```

> 💡 If your Jenkins controller is shared across teams, prefer
> **HashiCorp Vault** + the Jenkins Vault plugin over storing the
> master key in the Jenkins credentials store. The controller's
> `secrets/` directory is high-value loot if compromised.

---

## Azure

The recommended pattern: keep the **master key** in **Azure Key Vault**
and grant access via **managed identity**. Same principle as AWS Secrets
Manager and GCP Secret Manager.

### Container Apps

```sh
# Store the master key
az keyvault secret set \
  --vault-name my-vault \
  --name sealed-env-key \
  --value "$(cat sealed-env.key)"

# Reference it from the container app
az containerapp create \
  --name my-app \
  --resource-group my-rg \
  --image myregistry.azurecr.io/my-app:latest \
  --secrets "sealed-env-key=keyvaultref:https://my-vault.vault.azure.net/secrets/sealed-env-key,identityref:/subscriptions/.../identities/my-identity" \
  --env-vars "SEALED_ENV_KEY=secretref:sealed-env-key" \
  --command "/bin/sh" \
  --args "-c" "sealed-env decrypt /app/.env.sealed > /app/.env && exec node server.js"
```

The managed identity needs `Key Vault Secrets User` role on the vault.

### App Service

```sh
# Reference Key Vault from app settings — Azure resolves it at runtime
az webapp config appsettings set \
  --name my-app \
  --resource-group my-rg \
  --settings "SEALED_ENV_KEY=@Microsoft.KeyVault(VaultName=my-vault;SecretName=sealed-env-key)"
```

In your startup command (`Configuration → General settings → Startup
Command`):

```
sh -c 'sealed-env decrypt .env.sealed > .env && node server.js'
```

Or use the Node loader / Spring Boot starter and skip writing `.env`.

### Functions

For Azure Functions with the Node runtime, fetch the key once at cold
start using the `@azure/identity` + `@azure/keyvault-secrets` SDKs:

```js
import { DefaultAzureCredential } from '@azure/identity';
import { SecretClient } from '@azure/keyvault-secrets';
import { loadSealedEnv } from 'sealed-env';

const vault = new SecretClient(
  'https://my-vault.vault.azure.net',
  new DefaultAzureCredential()
);

let loaded = false;
export default async function (context, req) {
  if (!loaded) {
    const secret = await vault.getSecret('sealed-env-key');
    process.env.SEALED_ENV_KEY = secret.value;
    await loadSealedEnv('./.env.sealed');
    loaded = true;
  }
  // ... handler code
}
```

### Azure Pipelines

Store the master key in an **Azure DevOps variable group** linked to
Key Vault, or as a **secret variable** directly on the pipeline.

```yaml
# azure-pipelines.yml
trigger:
  branches: { include: [main] }

pool:
  vmImage: ubuntu-latest

variables:
  - group: production-secrets   # contains SEALED_ENV_KEY

steps:
  - task: NodeTool@0
    inputs: { versionSpec: '20.x' }

  - script: npm ci
    displayName: Install

  - script: npx sealed-env decrypt .env.sealed > .env
    env:
      SEALED_ENV_KEY: $(SEALED_ENV_KEY)
    displayName: Decrypt sealed env

  - script: ./deploy.sh
    displayName: Deploy

  - script: rm -f .env
    condition: always()
    displayName: Cleanup
```

Secret variables surface as masked `***` in logs. For enterprise mode,
mint the unseal token in a script step and use `##vso[task.setvariable]`
to expose it to subsequent steps:

```yaml
- script: |
    TOKEN=$(npx sealed-env unseal \
      --file .env.sealed \
      --deploy-id "$(Build.SourceVersion)" \
      --ttl 300)
    echo "##vso[task.setvariable variable=SEALED_ENV_UNSEAL_TOKEN;issecret=true]$TOKEN"
    echo "##vso[task.setvariable variable=SEALED_ENV_DEPLOY_ID]$(Build.SourceVersion)"
  env:
    SEALED_ENV_KEY: $(SEALED_ENV_KEY)
    SEALED_ENV_TOTP_SECRET: $(SEALED_ENV_TOTP_SECRET)
  displayName: Mint unseal token
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
directly. Both flows are **Model B** — the server holds the
master key plus the sealed file simultaneously.
[See doc 10 for the trade-off vs Model A](./10-decrypt-strategies.md).

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

## Railway

Add the master key in `Project → Variables`. Railway injects variables
into both the build and the runtime.

```sh
# Or set it via the CLI
railway variables set SEALED_ENV_KEY="$(cat sealed-env.key)"
```

In your `railway.toml` (or service settings), set the start command:

```toml
# railway.toml
[deploy]
startCommand = "sealed-env decrypt .env.sealed > .env && node server.js"
```

For multi-environment setups (dev / staging / prod), use Railway
**Environments** — each one has its own variable scope, so a leaked
dev key cannot decrypt prod's `.env.sealed`.

> 💡 If you use Railway's **shared variables** across services, scope
> `SEALED_ENV_KEY` per service rather than globally — only the services
> that actually need to decrypt should see it.

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

There are two shapes of SSH deploy depending on which decrypt model
you pick. See [10-decrypt-strategies.md](./10-decrypt-strategies.md)
for the trade-off.

### Model A — host-side decrypt with `deploy --remote`

The recommended path for operator-supervised deploys. The master key
**never leaves your machine**: only plaintext env vars cross the
network through an SSH tunnel.

```sh
# Operator's machine:
sealed-env deploy --remote ops@prod.example.com -- ./up.sh

# With explicit port, identity file, health check:
sealed-env deploy \
  --remote ops@prod.example.com \
  --ssh-port 2222 \
  --ssh-key ~/.ssh/deploy_ed25519 \
  --health-url https://prod.example.com/health \
  --health-timeout 60 \
  -- docker compose up -d --build
```

What the server sees:
- The operator's SSH connection (authenticated via the operator's
  key in your `authorized_keys`).
- A `/bin/sh` invocation that receives `export VAR='value'` lines on
  stdin (never argv — invisible to `ps aux` on the remote).
- The deploy command (`./up.sh`, `docker compose ...`) running with
  those env vars in process memory only.

What the server does **not** see:
- The master key.
- The signing key.
- The TOTP secret.
- The `.env.sealed` file (unless your repo checkout happens to have
  it, which is harmless).

Requirements on the remote:
- An OpenSSH server (any modern Linux distro is fine).
- `/bin/sh` on `$PATH`.
- The user in `--remote` has the right to run `<command>`.

### Model B — sealed file lives on the server

The convenient path when deploys must run unattended (autoscaling
pods, K8s rolling restarts, serverless cold starts). The server
holds both the master key and the sealed file.

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

> ⚠️ Pair Model B with **enterprise mode** (TOTP-bound unseal token)
> if the data on the server is high-value. The token's 5-minute TTL
> closes the window in which a stolen master key + sealed file pair
> can be decrypted offline. See
> [05-enterprise-mode.md](./05-enterprise-mode.md).

---

## OIDC federation (advanced — CI never holds the master key)

Every recipe above stores `SEALED_ENV_KEY` as a long-lived secret
inside the CI/CD platform. That works, but it's still a secret with
a perimeter — Shai-Hulud, tj-actions, and similar 2025 attacks all
exploited exactly this kind of persistent CI credential.

A stronger pattern: **the CI runner has no master key at all.** It
authenticates to your cloud's KMS via a short-lived OIDC token,
fetches `SEALED_ENV_KEY` just-in-time, uses it for the deploy, and
the value is gone the moment the job ends.

### GitHub Actions → AWS Secrets Manager

One-time AWS setup:

```sh
# 1. Trust GitHub's OIDC provider in your AWS account.
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# 2. Create a role that GH Actions can assume (trust policy below).
aws iam create-role \
  --role-name sealed-env-deploy \
  --assume-role-policy-document file://trust.json

# 3. Grant ONLY GetSecretValue on ONE secret to that role.
aws iam put-role-policy \
  --role-name sealed-env-deploy \
  --policy-name read-sealed-env-key \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/sealed-env-key-*"
    }]
  }'
```

`trust.json` (constrains which workflows on which repo can assume):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:youruser/yourrepo:ref:refs/heads/main"
      }
    }
  }]
}
```

The workflow:

```yaml
# .github/workflows/deploy.yml
name: deploy
on:
  push: { branches: [main] }

permissions:
  id-token: write     # required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/sealed-env-deploy
          aws-region: us-east-1

      - name: Fetch master key just-in-time
        run: |
          KEY=$(aws secretsmanager get-secret-value \
            --secret-id prod/sealed-env-key \
            --query SecretString --output text)
          echo "::add-mask::$KEY"
          echo "SEALED_ENV_KEY=$KEY" >> "$GITHUB_ENV"

      - uses: actions/setup-node@v4
        with: { node-version: 20 }

      - run: npm ci
      - run: npx sealed-env decrypt .env.sealed > .env
      - run: ./deploy.sh
      - run: shred -u .env || rm -f .env
        if: always()
```

What this changes versus the basic GitHub Actions recipe:

| Property | With static `SEALED_ENV_KEY` secret | With OIDC federation |
|---|---|---|
| GitHub holds the master key | ✅ Yes (forever) | ❌ No |
| Compromise of GH Actions runner = master key leak | ✅ Yes | ⚠️ Only if leaked DURING the job |
| Audit trail of who fetched the key when | (GitHub Actions log) | (CloudTrail — outside the CI vendor's surface) |
| Rotation requires updating GH | ✅ Yes | ❌ Just rotate in AWS Secrets Manager |

The same pattern works for **GCP Cloud Build** (Workload Identity
Federation → Secret Manager), **Azure Pipelines** (Workload Identity
→ Key Vault), and **GitLab CI/CD** (`id_tokens:` → AWS / GCP / Azure).
The mechanics differ; the principle is the same: **CI authenticates,
KMS authorizes, master key never persists in CI**.

### When this is overkill

For solo developers, private repos, and low-stakes deploys, the
static-secret recipes earlier in this document are fine. OIDC
federation pays off when:

- You have multiple repos that should each have least-privileged
  access to a shared secret store.
- You operate under a compliance regime (SOC2, ISO 27001, PCI) that
  audits who has access to production credentials.
- The CI vendor itself is part of your threat model (rare but
  legitimate at large scale).

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
- [ ] (For high-stakes deploys) you considered whether OIDC
      federation makes sense — if so, you implemented it.

For the rotation playbook, see the "Rotation" section in
[05-enterprise-mode.md](./05-enterprise-mode.md).
