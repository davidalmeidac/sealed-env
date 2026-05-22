# Shai-Hulud / Mini Shai-Hulud — Indicators of Compromise

**Compiled from**: Datadog Security Labs (2026-05-13), StepSecurity (2026-05-19),
Akamai (2026-05-14), The Register (2026-05-13).
**Last updated**: 2026-05-22.

This table is for **defensive use only** — feed it to your SIEM, your
network blocklists, your secret-scanning detectors. Do not use any of
these artifacts to contact the C2 or to verify malware functionality.

---

## Network IOCs

| Indicator | Type | Context | Source |
|---|---|---|---|
| `git-tanstack.com:443` | Domain | Primary C2 exfiltration (HTTPS) | Datadog |
| `83.142.209.194` | IPv4 | Associated C2 infrastructure | Datadog |
| `filev2.getsession.org` | Domain | Session-protocol CDN exfil endpoint | StepSecurity |
| `seed1.getsession.org` | Domain | Pinned-cert (Oxen Privacy Tech, exp 2033) | StepSecurity |
| `api.masscan.cloud` | Domain | Secondary direct C2 | StepSecurity |

## GitHub identities

| Indicator | Type | Notes | Source |
|---|---|---|---|
| `voicproducoes` | GitHub login | Account ID 269549300, created 2026-03-19 | StepSecurity |
| `voicproducoes@gmail.com` | Email | Listed on GitHub account | StepSecurity |
| `claude@users.noreply.github.com` | Git author | Used on poisoned-branch commits | StepSecurity |
| `voicproducoes/router` | Repo | Fork used to host the malicious payload | StepSecurity |
| `79ac49eedf774dd4b0cfa308722bc463cfe5885c` | Commit SHA | Malicious payload commit | StepSecurity |

## Commit & branch signatures

| Indicator | Where | Source |
|---|---|---|
| `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` | npm token description / commit message | Datadog |
| `thebeautifulmarchoftime` | Commit search string for signed fallback C2 | Datadog |
| `Shai-Hulud: Here We Go Again` | Repo description on exfil dead-drops | Datadog |
| `chore: update dependencies` | Commit message for poisoned-branch commits | Datadog |
| `dependabot/github_actions/format/*` | Branch name patterns (Dune terminology) | Datadog |
| `fremen`, `sandworm`, `harkonnen` | Dead-drop branch name fragments | StepSecurity |

## Filesystem artifacts (host-side)

| Path | OS | Purpose | Source |
|---|---|---|---|
| `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | macOS | Persistence daemon (deadman switch) | Datadog |
| `~/.config/systemd/user/gh-token-monitor.service` | Linux | Persistence daemon (deadman switch) | Datadog |
| `~/.claude/settings.json` (with `SessionStart` hook) | All | Claude Code session-init backdoor | Datadog |
| `.vscode/tasks.json` (with `runOn: folderOpen`) | All | VSCode folder-open execution | Datadog |
| `.claude/setup.mjs` | All | Loader injected into repos | Datadog |
| `.vscode/setup.mjs` | All | Loader injected into repos | Datadog |
| `/tmp/tmp.ts018051808.lock` | Linux/macOS | Singleton lock file | Datadog |

## Source-code hashes (stable, pre-build)

| File | SHA-256 | Source |
|---|---|---|
| `src/index.ts` | `f2157f1cecbf3995aafad750e6e805c472cec466a53d17c2063f266ad2b3d625` | Datadog |
| `src/assets/config.mjs` | `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d` | Datadog |
| `src/assets/DEADMAN_SWITCH.sh` | `619c56acf572df75b6004a6fc013c80900316a76099b241d64312da3a44f10b4` | Datadog |
| `src/assets/python_util.py` | `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7` | Datadog |
| `src/assets/enc_key.pub` | `f7a1e56b6dbd42778fe349b8412ab9749c78fa2bf41ea90b1165615ddfee52e4` | Datadog |
| `src/assets/verify_key.pub` | `c55a10759f6f415a536940a75f42aa372878a51f8eb97468551eabf6d88ae492` | Datadog |
| `src/assets/workflow.yml` | `3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7` | Datadog |

## Compiled-payload hashes (in-the-wild)

> ⚠️ Per-build random passphrase makes compiled hashes non-reproducible.
> A hash *change* doesn't mean it's not Shai-Hulud — could just be a fresh build.

| File | SHA-256 | Campaign | Source |
|---|---|---|---|
| `router_init.js` | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` | TanStack | Datadog |
| `tanstack_runner.js` | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` | TanStack | StepSecurity |
| `setup.mjs` | `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df` | — | Datadog |

## Obfuscation parameters (deobfuscation aid)

For anyone trying to deobfuscate a captured sample to verify it's
Shai-Hulud (NOT to run it):

| Parameter | Value | Source |
|---|---|---|
| Algorithm | Fisher-Yates cipher seeded by SHA-256 RNG | StepSecurity |
| PBKDF2 hash | SHA-256 | StepSecurity |
| PBKDF2 iterations | 200,000 | StepSecurity |
| Master passphrase | `0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa` | StepSecurity |
| Salt | `svksjrhjkcejg` | StepSecurity |
| String count (router_init) | 11,516 base64 strings | StepSecurity |

> ⚠️ The master passphrase listed here is for a specific build. Other
> samples will have different passphrases generated per-build. Use this
> to confirm a specific sample matches the TanStack campaign; new
> campaigns will need their own keys extracted.

## Affected npm packages (TanStack campaign, partial)

| Package | Malicious version(s) | Source |
|---|---|---|
| `@tanstack/react-router` | 1.169.5, 1.169.8 | StepSecurity |
| `@tanstack/router-core` | 1.169.5, 1.169.8 | StepSecurity |
| `@opensearch-project/opensearch` | 3.6.2 | StepSecurity |
| `@mistralai/mistralai` | 2.2.3, 2.2.4 | StepSecurity |
| (42 total @tanstack packages, 84 versions; 60+ others) | — | StepSecurity |

## Behavioral detection signatures

For SIEM / EDR rules — high-fidelity, low-FP signals:

| Pattern | Why it's suspicious |
|---|---|
| `python3` process reading `/proc/<other-pid>/mem` in CI | Memory scrape of runner |
| `optionalDependencies` field referencing `github:` URL with commit SHA | Payload-staging fork reference |
| `router_init.js`, `*_init.js`, or `setup.mjs` at npm package root | Outside expected `dist/`/`src/` layout |
| Sudden ~5× growth in published npm tarball size | Compiled `router_init.js` ~2.3 MB added |
| New `LaunchAgent` or `systemd user service` named `*gh-token*` | Persistence install |
| New `.claude/settings.json` with `SessionStart` hook | IDE backdoor |
| New `.vscode/tasks.json` with `runOn: folderOpen` | IDE backdoor |
| GitHub Actions workflow that invokes `toJSON(secrets)` | Bulk-secret exfil pattern |
| GitHub OIDC token exchange for `npm:registry.npmjs.org` audience | npm trusted-publishing abuse |
| HTTPS POST to `*.getsession.org` from a CI runner | Session-protocol C2 |
| Hex-encoded JSON in commit search across the org | C2 token-recovery channel |
