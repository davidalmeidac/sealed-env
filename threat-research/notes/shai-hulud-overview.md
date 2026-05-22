# Shai-Hulud / Mini Shai-Hulud — overview

> Compiled from public research (Datadog Security Labs, StepSecurity, Mondoo,
> Akamai, The Register, SC Media, OX Security, Security Boulevard). Last
> updated 2026-05-22.

This document is the **starting point** for any deeper analysis. It captures
the architecture and the attack chain at a high level. For specific
indicators, see `analysis/ioc-table.md`. For per-module deep dives, see
the other files in this directory.

---

## Timeline

| Date | Event |
|---|---|
| 2025 | Original Shai-Hulud worm observed in the wild (closed-source). |
| 2026-03-19 | `voicproducoes` GitHub account created. |
| 2026-05-12 | TeamPCP open-sources the Shai-Hulud framework on GitHub under MIT. Headline: *"Shai-Hulud: Open Sourcing The Carnage"*. |
| 2026-05-12 | Mini Shai-Hulud campaign begins compromising @tanstack packages. 84 malicious versions across 42+ packages. |
| 2026-05-13 | GitHub takes down the original repos; forks proliferate. Datadog and StepSecurity publish technical analyses. |
| 2026-05-14+ | First clones appear (`chalk-tempalte` typosquat with DDoS payloads + wallet stealers). |
| 2026-05-22 | sealed-env begins defensive analysis (this document). |

---

## Architecture: a credential-harvesting + supply-chain-poisoning pipeline

The leaked framework is **modular** — discrete TypeScript modules wired
into a pipeline. This matters because it's not one giant blob; each
module can be ported, replaced, or combined independently by clones.

```
                ┌────────────────────────┐
                │  Loaders               │
                │  BASH_LOADER.sh        │ Stage-1 droppers. Download
                │  PYTHON_LOADER.py      │ Bun runtime, launch payload.
                │  config.mjs            │
                └───────────┬────────────┘
                            │
                            ▼
   ┌────────────────────────────────────────────┐
   │  Providers — credential collectors          │
   │  ┌─────────────────┐  ┌─────────────────┐  │ Each provider implements
   │  │ FileSystem      │  │ Shell           │  │ a specific harvest:
   │  │ (100+ paths)    │  │ (gh, process.env)│ │  - files on disk
   │  ├─────────────────┤  ├─────────────────┤  │  - shell context
   │  │ GitHubRunner    │  │ AwsProvider     │  │  - GH runner memory
   │  │ (/proc/pid/mem) │  │ (17 regions)    │  │  - cloud APIs
   │  ├─────────────────┤  ├─────────────────┤  │  - k8s API
   │  │ KubernetesP.    │  │ VaultProvider   │  │  - Vault
   │  └─────────────────┘  └─────────────────┘  │
   └────────────────────┬───────────────────────┘
                        │
                        ▼
              ┌──────────────────┐ Buffers harvested data
              │  Collector       │ until flush threshold
              │  (100KB flush)   │ (default 100 KB).
              └────────┬─────────┘
                       │
                       ▼
            ┌────────────────────┐ Hybrid crypto:
            │  Dispatcher        │  AES-256-GCM payload
            │  (encrypt + send)  │  + RSA-4096-OAEP key
            └────────┬───────────┘  (public key hardcoded).
                     │
            ┌────────┴───────────┐
            ▼                    ▼
   ┌─────────────────┐  ┌─────────────────┐
   │ DomainSender    │  │ GitHubSender    │
   │ HTTPS POST C2   │  │ Dune-themed     │
   │ (api.masscan)   │  │ dead-drop repos │
   └─────────────────┘  └─────────────────┘
                     │
                     ▼
            ┌────────────────────┐ Propagation:
            │  Mutators          │  - GitHub repo poisoning
            │                    │    (ReadmeUpdater)
            │  Read these AFTER  │  - npm package poisoning
            │  exfil succeeds.   │    (NpmClient)
            │                    │  - npm OIDC abuse
            │                    │    (NPMOidcClient)
            └────────────────────┘
```

---

## The propagation we need to understand

Two mechanisms keep this worm alive without a botnet:

### 1. NPM_TOKEN-based propagation (developer machine)
1. FileSystemService reads `~/.npmrc`
2. Token extracted, validated against `https://registry.npmjs.org/-/v1/login` (or similar)
3. NpmClient enumerates packages the token can publish (including org-scoped)
4. For each writable package:
   - Download latest tarball
   - Modify `package.json` → add `"preinstall": "node setup.mjs"`
   - Inject `config.mjs` as `setup.mjs`
   - Inject compiled malware (`router_init.js`, ~2.3 MB)
   - Bump patch version
   - Re-publish

The worm specifically looks for tokens flagged `bypass_2fa: true`. **2FA on
npm is not enough** if your token is exfiltrated and the token itself has
2FA-bypass set.

### 2. OIDC-based propagation (GitHub Actions runner)
1. Detect `GITHUB_ACTIONS=true` and target a specific workflow
2. Request OIDC token: audience = `npm:registry.npmjs.org`
3. Exchange OIDC → short-lived npm publish token via npm's exchange endpoint
4. Download target package
5. Inject `optionalDependencies` pointing to attacker-controlled GitHub commit ref
6. **Generate a fake-but-valid Sigstore bundle**:
   - Request signing cert from Fulcio
   - Sign DSSE envelope with ephemeral ECDSA key
   - Record in Rekor transparency log
7. Publish with attached provenance

The forged provenance shows up as **SLSA Build Level 3 compliant** in dashboards.
This is the part that broke a lot of defensive assumptions.

---

## What this means for sealed-env users

### Worst-case path (operator on a workstation, no hardening)

```
1. Operator npm-installs an infected package           (could be any popular dep)
2. preinstall hook runs node setup.mjs
3. setup.mjs daemonizes, drops persistence, starts collector
4. FileSystemService reads:
   - ~/.npmrc              → NPM_TOKEN  → worm propagates
   - **/.env recursive     → SEALED_ENV_KEY in plain text ❌
   - ~/.aws/credentials    → cloud takeover
5. Encrypted exfil to git-tanstack.com:443
6. Within minutes, attacker has:
   - Full read of all .env.sealed files (master key in hand)
   - GitHub PAT, AWS, K8s, Vault, Slack, Discord, browser passwords
   - The ability to publish a poisoned sealed-env@0.2.2 themselves
```

This is the path we're defending against. sealed-env can't prevent the
package install (out of scope) but **MUST** make step 4's harvest fail.

### Step 4 mitigated path (operator with `keychain push`)

```
4'. FileSystemService reads **/.env recursive
    → finds .env.local with DATABASE_URL but NOT SEALED_ENV_KEY
    → master key is in OS keychain (Windows Credential Manager / macOS / libsecret)
    → harvest fails for this credential
4''. ShellService captures process.env
    → SEALED_ENV_KEY not in env unless `sealed-env exec` is actively running
    → if `exec` runs WHILE worm is active, key is in env of child for the
      duration of the child. Still vulnerable but window is shorter.
```

So `keychain push` is the **single most impactful hardening** for an
sealed-env user against this threat. It deserves to be much more prominent
in the README and SETUP docs.

---

## Open questions to resolve in the deep-dive

These are what motivate the deeper static analysis:

1. **Does FileSystemService open files passively or also chmod/chown them?**
   If it modifies metadata, we can detect retroactively via `find -newer`.

2. **What's the exact glob pattern for `**/.env`?** Does it follow symlinks?
   Does it descend into `node_modules`? If not, putting the keychain wrapper
   inside `node_modules/.sealed-env-state/` could literally hide it.

3. **How does ShellService capture `process.env`?** Snapshot at startup?
   Polling? If snapshot, then `sealed-env exec` started AFTER worm activation
   gets caught; started BEFORE is safe.

4. **Does the Vault provider try to exchange tokens, or just read raw?**
   sealed-env doesn't talk to Vault today but a future Capa 3 might.

5. **What's the per-file size limit for FS read?** Datadog says 5MB. We can
   confirm and ensure no future sealed-env state file exceeds something
   sneaky (though file size alone won't stop the read).

6. **Are there any sealed-env-specific paths in the harvest list?**
   (`SEALED_ENV_*`, `sealed-env-state.json`, etc.)? Highly unlikely today but
   worth checking — if the worm explicitly targets us, we know we hit a nerve.

---

## Next step

Move to per-module deep-dive in `notes/` once a sample is acquired and
verified by hash in the sandbox. See `README.md` "Workflow" section.
