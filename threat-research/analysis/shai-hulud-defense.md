# Shai-Hulud Framework — Defensive Analysis for sealed-env

**Scope.** Module-by-module mapping of the TeamPCP Shai-Hulud framework
(open-sourced 2026-05-12) to sealed-env's existing and missing defenses.
Honest about gaps; no marketing.

**Sources.**
- Datadog Security Labs, *"Shai-Hulud Goes Open Source"*, 2026-05-13 — static analysis of the leaked framework.
- StepSecurity, *"Mini Shai-Hulud Is Back"*, 2026-05-19 — TanStack campaign forensics.
- Mondoo, *"When Worm Source Code Goes Open Source"*, 2026-05-15 — clone ecosystem.
- Akamai, The Register, SC Media, OX Security — corroborating sources for specific claims.

**Method.** No malware was executed. No source samples were downloaded.
Findings derive entirely from the cited researcher publications, cross-
checked across at least two independent sources where possible.

**Disclaimer.** Defense claims here apply to sealed-env at version 0.2.1
(May 2026). Future versions may close gaps marked 🔴 today. The framework
itself will likely evolve in clones; new variants may require re-analysis.

---

## Legend

- 🟢 **Defends** — sealed-env defaults block this technique
- 🟡 **Defends with config** — operator must opt-in to a hardening step
- 🔴 **Does not defend** — outside what sealed-env was designed to stop; operator must use other tools
- ⚪ **Out of scope** — sealed-env's surface area doesn't touch this

---

## Module 1 — `FileSystemService` (credential harvest via disk scan)

### What it does
Recursively scans known credential paths on the host and reads up to 5 MB
per file. Path list includes (non-exhaustive):

- `**/.env` glob (recursive from cwd)
- `~/.aws/credentials`, `~/.azure/accessTokens.json`, `~/.config/gcloud/credentials.db`
- `~/.npmrc`, `~/.pypirc`, `~/.yarnrc`
- `~/.ssh/id_*`, `~/.ssh/config`, `~/.ssh/known_hosts`
- `~/.kube/config`, `/var/run/secrets/kubernetes.io/serviceaccount/token`
- `~/.docker/config.json`, `~/.gitconfig`, `.git-credentials`
- Shell histories: `.bash_history`, `.zsh_history`, `.python_history`
- AI tools: `.claude.json`, `.claude/mcp.json`, `.kiro/settings/mcp.json`
- 30+ wallet config paths (Bitcoin, Ethereum, etc.)
- Messaging app configs (Slack, Discord, Telegram, Signal)

### Direct impact on sealed-env users

The `**/.env` glob is the killshot. If your `.env.local` contains
`SEALED_ENV_KEY=<64 hex>`, this module exfiltrates it.

### Defense matrix

| Sub-vector | Status | Detail |
|---|---|---|
| Master key in `.env.local` plaintext | 🔴 | Default install puts the key here; vulnerable |
| Master key in OS keychain (`sealed-env keychain push`) | 🟢 | Not on disk; FileSystemService can't read what isn't there |
| Signing key in `.env.local` plaintext | 🔴 | Same problem as master key |
| TOTP secret in `.env.local` plaintext | 🔴 | Worst case: combined with master key, defeats enterprise mode 2FA |
| `.env.sealed` ciphertext itself committed to repo | 🟢 | Useless without the keys; this is the designed behavior |

### Recommendation for operators

1. **Run `sealed-env keychain push`** immediately after first init. This is
   the single most impactful step.
2. Treat `.env.local` as a development convenience only. In CI/prod, the
   key MUST come from the platform's secret store, never from a file.
3. If you can't use the OS keychain (containers without GUI/keyring), use
   a hardware-backed store: AWS KMS, HashiCorp Vault, sops with KMS, etc.
   sealed-env doesn't ship this integration yet (roadmap), but reading the
   key from `$(aws ssm get-parameter ...)` at runtime is a viable wrapper.

### Recommendation for sealed-env itself

- `init` should print a much more prominent warning that the default
  `.env.local` is vulnerable to disk scanners and recommend `keychain push`
  as the next step. Today's docs underplay this.
- `doctor` should detect plain-hex `SEALED_ENV_KEY` in `.env.local` and
  raise a finding (proposed in task #3).
- The proposed `sealed-env scan` (shipped in 0.2.1) catches the operator
  about to commit `.env.local`. Pair it with a `pre-commit` hook in the
  README quickstart.

---

## Module 2 — `ShellService` (process.env capture)

### What it does
- Executes `gh auth token` to extract the GitHub CLI's cached token.
- Captures the entire `process.env` object of the shell that spawned the malware.

### Direct impact on sealed-env users

When you run `sealed-env exec -- <command>`, the master key is in
`process.env.SEALED_ENV_KEY` for the duration of the child process. If
the malware is already daemonized on the host, it sees this env on spawn.

### Defense matrix

| Sub-vector | Status | Detail |
|---|---|---|
| Long-lived `SEALED_ENV_KEY` in shell env | 🔴 | If you `export SEALED_ENV_KEY=...` in `.bashrc`, every shell has it |
| Key only during `sealed-env exec` execution | 🟡 | Window is short, but worm running concurrently still wins |
| `gh` token theft | ⚪ | Out of scope; mitigate with `gh auth status` + token rotation |

### Recommendation for operators

1. **Never `export SEALED_ENV_KEY=...`** in your shell rc files. Read it
   just-in-time from the keychain via `sealed-env exec`.
2. Use **enterprise mode + short-TTL unseal tokens** so that even if the
   master key is captured, an attacker also needs a fresh TOTP code within
   the TTL window.
3. Rotate `gh` tokens on a schedule. This is hygiene that sealed-env
   doesn't enforce but every operator should follow.

### Recommendation for sealed-env itself

- Investigate **just-in-time key loading + post-fork wipe**: spawn the
  child, read the key into the child's env only at fork-time, then zero
  the key in the parent's `process.env` immediately. Tradeoff: complicates
  re-exec semantics for tools that fork their own children.
- Document the `process.env` exposure window explicitly in
  `docs/threat-model-runtime.md` (new file).

---

## Module 3 — `GitHubRunner` (/proc memory scrape)

### What it does
On GitHub Actions runners:
1. Scans `/proc/*/cmdline` to find the `Runner.Worker` process.
2. Reads `/proc/<pid>/maps` and `/proc/<pid>/mem` via Python (piped through
   stdin with `sudo` if available).
3. Greps for JSON matching `{"value":"...","isSecret":true}` — the runner's
   internal representation of a workflow secret.

### Direct impact on sealed-env users

If sealed-env's unseal tokens or master key are passed as workflow secrets
in CI, they appear in the runner's memory in this exact format and get
scraped. This bypasses GitHub Actions' log masking entirely.

### Defense matrix

| Sub-vector | Status | Detail |
|---|---|---|
| Unseal token passed via `secrets.SEALED_ENV_UNSEAL_TOKEN` | 🔴 → 🟡 | If token TTL is ≤ 30s, scraped token may have expired before exfil completes |
| Token TTL > 120s | 🔴 | Plenty of time for exfil and reuse |
| Master key passed via `secrets.SEALED_ENV_KEY` in workflow | 🔴 | Same scrape, no mitigation from sealed-env side |
| Unseal token bound to `ops_id` (replay cache) | 🟢 | Even if scraped & sent to C2 within TTL, a second use fails |

### Recommendation for operators

1. **Set unseal TTL ≤ 30s** for CI deploys. Default is 60s; tune down for
   production.
2. **One-shot unseal**: the replay cache ensures a single use, then dead.
3. **Restrict CI runner privileges**: do not run with `sudo` access where
   `/proc/*/mem` is readable. Use ephemeral runners with no persistent
   state and no extra capabilities.
4. **Network egress allowlist on runners** (e.g., StepSecurity's
   Harden-Runner) — even if the token is scraped, it can't leave.

### Recommendation for sealed-env itself

- The replay cache + TTL combo is the right answer here. Defaults should
  be 30s for CI use cases. Today's 60s default leans dev-friendly; a
  `--ci` flag could tighten the defaults.
- Document explicitly that **sealed-env tokens DO leak through `/proc` on
  compromised runners** and the only mitigations are short TTLs +
  ephemeral runners + egress controls. Don't pretend we stop the scrape.

---

## Module 4 — `AwsProvider` / `KubernetesProvider` / `VaultProvider`

### What they do
- AWS: enumerate Secrets Manager + SSM Parameter Store across 17 regions
  using whatever credentials are in scope.
- K8s: list all namespaces, base64-decode every secret via the API.
- Vault: 4 auth methods, enumerate KV mounts, read up to 100 secrets/mount.

### Direct impact on sealed-env users

These modules target the *underlying* secret stores that an operator might
use as the source of `SEALED_ENV_KEY`. They don't target sealed-env's
artifacts directly, but they steal the upstream keys.

### Defense matrix

⚪ Out of scope for sealed-env. The defenses here belong to the secret
stores themselves (IAM scoping, K8s RBAC, Vault policies). sealed-env
neither helps nor hurts.

### Recommendation for operators

If you store `SEALED_ENV_KEY` in AWS SSM / Vault / K8s secrets and the
compromised machine has read access to that store, you lose the master
key by transitive compromise. Two mitigations:

1. **Least-privilege**: the runtime IAM role that decrypts `.env.sealed`
   should be able to read **only** that one parameter, not the entire
   Parameter Store.
2. **Decouple the dev key from the prod key**: never use the same
   `SEALED_ENV_KEY` for development and production. A compromised dev
   keychain shouldn't unseal prod files.

---

## Module 5 — `NpmClient` (token-based npm propagation)

### What it does
1. Validates a captured npm token (from `.npmrc`) against the registry
   for `package:write` permission.
2. Enumerates all packages the token can publish.
3. For each writable package:
   - Downloads latest tarball
   - Modifies `package.json` → adds `"preinstall": "node setup.mjs"`
   - Injects the malware as `setup.mjs` + `router_init.js`
   - Bumps patch version
   - Re-publishes to npmjs.org

### Direct impact on sealed-env users (who are also publishers)

If you, the operator, are a publisher (e.g., you maintain a Java/Node
library yourself) and your `~/.npmrc` token is compromised, the worm
publishes a poisoned version of YOUR packages. Your downstream users get
infected when they next install.

### Direct impact on sealed-env itself

If David's (the maintainer's) `~/.npmrc` is compromised, `sealed-env@0.2.2`
could be published with a `preinstall` hook that steals secrets from every
sealed-env user. **This is sealed-env's worst-case existential threat.**

### Defense matrix

| Sub-vector | Status | Detail |
|---|---|---|
| Worm-published `sealed-env@x.y.z+1` reaches users | 🔴 | sealed-env can't unpublish itself once compromised |
| Provenance attestation verifies on install | 🟡 | npm shows provenance, but tools rarely *enforce* it |
| Operator pins to digest, not version | 🟡 | If the operator pins `sealed-env@sha512-...`, a re-publish doesn't help the worm |
| Operator uses pnpm 11 `minimumReleaseAge: 24h` | 🟢 | Cooldown lets the community report before the bad version is installed |

### Recommendation for operators

1. **Pin sealed-env to a specific version range**, ideally with `pnpm`'s
   `minimumReleaseAge` cooldown (24h) or Yarn Berry's `npmMinimalAgeGate`
   (3 days). This is the single best ecosystem-level defense.
2. **Verify provenance**: `npm install --provenance` if available.
3. **Subscribe to GitHub Advisory Database alerts** for `sealed-env` and
   for every package in your dep tree. The CVE-2026-45091 advisory for
   sealed-env itself shows the system works when used.

### Recommendation for sealed-env itself

- David's npm publishing should be done with **OIDC trusted publishing**
  from a single dedicated GitHub repo + protected branch + 2FA-required,
  not from a local laptop. This is the same defense that broke for the
  TanStack maintainers (compromised maintainer machine → npm token).
- Every release should ship with **Sigstore provenance**. The worm can
  forge provenance, but only with `id-token: write` and a stolen workflow
  context. Pinning the publishing workflow to a SHA + restricting `id-token`
  grants raises the bar.
- **Document the operator pinning recipe** prominently in README. "How to
  install sealed-env safely" should be a top-level section, not a footnote.

---

## Module 6 — `NPMOidcClient` (OIDC + Sigstore provenance forgery)

### What it does
1. In a GitHub Actions context, requests an OIDC token scoped to
   `npm:registry.npmjs.org`.
2. Exchanges that token for an npm publish token.
3. Generates a complete Sigstore bundle: requests cert from Fulcio, signs
   DSSE envelope with ephemeral ECDSA key, records in Rekor.
4. Publishes target package with attached provenance — appearing as
   legitimate SLSA Build Level 3.

### Direct impact on sealed-env users

The worm specifically targeted `release-drafter.yml` in `opensearch-js`.
sealed-env's release workflow has not been audited for this specific
vector yet.

### Defense matrix

| Sub-vector | Status | Detail |
|---|---|---|
| Workflow uses `id-token: write` permission broadly | 🔴 | The token can be misused for any audience |
| Workflow restricts `id-token` to specific job | 🟡 | Reduces blast radius |
| npm trusted publisher restricts publisher GitHub identity + workflow file | 🟢 | npm refuses publish if the publishing identity doesn't match the registered configuration |

### Recommendation for sealed-env itself

This is the single most important defensive action for the project right
now:

1. **Audit `.github/workflows/release.yml`** (or whatever publishes to npm
   and Maven Central) and verify:
   - `id-token: write` is only on the publish job, not job-wide
   - The workflow file is pinned in npm's trusted publisher config
   - The publishing job runs only on a protected branch (`main`)
2. **Register sealed-env with npm trusted publishing** (if not already).
   Once configured, npm will reject any publish from an identity that
   doesn't match the registered workflow.
3. **Maven Central equivalent**: Sonatype's verification gates the
   publishing identity; verify it's tied to a single source.

### Recommendation for operators

Same as Module 5 — pin to version + use release-age cooldowns. Provenance
forgery is harder to detect at install time; cooldowns are the best
generic defense.

---

## Module 7 — `ReadmeUpdater` (GitHub repo poisoning)

### What it does
Commits malicious files (`.github/workflows/codeql_analysis.yml`,
`.claude/setup.mjs`, `.vscode/tasks.json`) across all branches of a
repo the attacker has push access to. The fake workflow uses
`toJSON(secrets)` to serialize every repository secret and POST it
out (or upload as artifact).

### Direct impact

If an operator's GitHub PAT is in the compromised credential pool, all
their repos can have these files committed. Downstream collaborators who
clone or `npm install` will execute the IDE hooks on open.

### Defense matrix

⚪ Out of scope for sealed-env directly. But the proposed
`sealed-env doctor --check-ide-hooks` (task #3) can detect the injected
files locally.

### Recommendation for operators

1. **`gh auth status` + `gh auth token` should be revocable**. Don't reuse
   long-lived PATs.
2. **Branch protection**: require PR review for `main` (and any branch
   that builds/releases). A poisoned commit needs to land via PR, which
   gives a human chance to catch it.
3. **GitHub Actions secrets** should use environment-scoped permissions
   so a workflow on a feature branch can't see prod secrets.

### Recommendation for sealed-env itself

Ship the `doctor --check-ide-hooks` heuristic. Detect:
- `.vscode/tasks.json` with `runOn: folderOpen`
- `.claude/settings.json` with `SessionStart` hook
- `.claude/setup.mjs` / `.vscode/setup.mjs` files

If any are found, raise a finding with the IOC link to this doc.

---

## Module 8 — Persistence (LaunchAgent / systemd + deadman switch)

### What it does
On a workstation, the framework installs:
- **macOS**: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
  with `RunAtLoad` + `KeepAlive`
- **Linux**: `~/.config/systemd/user/gh-token-monitor.service` with
  `loginctl enable-linger`

A daemon polls GitHub every minute. If the operator revokes their GitHub
token (because they detected the compromise), the daemon's default
handler executes **`rm -rf ~/`**. Self-terminates after 24 hours regardless.

### Direct impact

This is the most operationally dangerous module. It transforms compromise
into a hostage situation: revoking your token wipes your home directory.

### Defense matrix

⚪ Out of scope for sealed-env. But this module changes the playbook for
*responding* to a compromise.

### Recommendation for operators (incident response)

If you suspect compromise:

1. **Do not revoke tokens before isolating the machine.**
2. **Power off the machine.** Boot from external media. Mount the disk
   read-only.
3. **Image the disk** before any cleanup, in case forensics matter.
4. **Check for the persistence files first**:
   - `ls ~/Library/LaunchAgents/ | grep gh-token`
   - `systemctl --user list-unit-files | grep gh-token`
5. **Remove the daemons** *before* revoking any GitHub credentials.
6. *Then* rotate every credential.

### Recommendation for sealed-env itself

Add this incident-response playbook to `docs/incident-response.md` and
link it from the README + `sealed-env doctor` output when a finding is
reported. Operators reaching for `sealed-env doctor` are exactly the
audience that needs this warning.

---

## Cross-cutting recommendations (don't fit any single module)

### For operators

1. **Use pnpm 11 or Yarn Berry** with default release-age cooldowns
   enabled. This is the cheapest, most impactful supply-chain defense
   for the entire JS ecosystem. sealed-env benefits transitively.

2. **Audit your dependency tree's `preinstall` / `postinstall` scripts**:
   ```bash
   npm explore <pkg> -- node -e 'console.log(require("./package.json").scripts)'
   ```
   Or use `npm-audit-resolver` to maintain an allowlist.

3. **Air-gap your TOTP secret** physically. The Datadog analysis is clear:
   if both `SEALED_ENV_KEY` and `SEALED_ENV_TOTP_SECRET` live on the same
   compromised machine, enterprise mode reduces to basic mode. Use a
   separate device (phone authenticator) and never paste the secret into
   `.env.local`.

4. **Rotate after any suspected exposure**: `sealed-env rotate <file>`
   re-seals with a fresh salt. Existing tokens are invalidated. The
   replay cache + new epoch make stolen tokens worthless even before TTL.

### For the sealed-env project

1. **Ship the proposed `doctor --check-ide-hooks` + plaintext-key
   detection** (task #3).

2. **Make `keychain push` the default `init` recommendation**, not an
   afterthought. Update README quickstart accordingly.

3. **Tighten unseal token TTL defaults for CI**: 30s default when
   `GITHUB_ACTIONS=true` is detected.

4. **Audit and document the release workflow** for OIDC + Sigstore
   trusted-publishing configuration (Module 6 recommendation).

5. **Add a one-line in `sealed-env doctor` output**: "For Shai-Hulud
   defense status, see https://github.com/davidalmeidac/sealed-env/blob/
   main/threat-research/analysis/shai-hulud-defense.md"

---

## Honest gap analysis

After this exercise, sealed-env defends — with appropriate operator
configuration — against the **credential storage** and **token replay**
parts of Shai-Hulud's attack chain. It does **not** defend against:

- Initial compromise via malicious dependency install (ecosystem problem)
- Memory scraping of the operator's machine (OS / kernel problem)
- Persistence daemons / IDE hooks installed by the worm (host hygiene problem)
- Re-publishing of sealed-env itself by a worm with the maintainer's
  npm token (npm trusted publishing problem)

Marketing claims of the form "sealed-env defends against Shai-Hulud"
should be replaced with:

> sealed-env reduces the impact of Shai-Hulud-class supply-chain attacks
> by keeping master keys out of disk and process.env when configured with
> `keychain push` and enterprise mode + short-TTL unseal tokens. It does
> not prevent compromise; it limits what a compromised host can steal
> from sealed files.

That's honest, defensible, and still a real selling point.

---

## Version history

| Date | Version | Change |
|---|---|---|
| 2026-05-22 | 0.1 | Initial draft based on Datadog + StepSecurity + Mondoo public analyses. |
