# sealed-env — Defense Improvement Roadmap

**Generated**: 2026-05-22 (post-0.2.1 release)
**Scope**: Concrete, prioritized improvements to harden sealed-env against
the documented Shai-Hulud framework, its variants, and future iterations.

> ⚠️ This document focuses on what to **change in sealed-env itself**.
> For the per-module attack analysis, see `shai-hulud-defense.md`.
> For IOCs, see `ioc-table.md`.

---

## Method

1. **Pass 1**: Inventoried newly documented public research from
   Snyk, Socket, StepSecurity, Upwind, Phoenix Security, TanStack
   post-mortem, Tenable CVE-2026-45321 FAQ, The Register, Aikido,
   OX Security, ThreatLocker, Rescana, BleepingComputer.

2. **Pass 2**: Read the actual source code at `node/src/` and verified
   each claim in `shai-hulud-defense.md` against the code that's
   actually shipped. **Several "claimed defenses" hold up; several
   gaps are real.**

3. **Pass 3**: Identified concrete code/doc/process changes, each
   with file path, effort estimate, risk, and verification path.

4. **Pass 4**: Forward-looking architectural improvements.

No malware executed. No source samples downloaded. All findings derive
from public researcher publications + reading our own code.

---

## Newly documented techniques (post-2026-05-22)

### Updated facts about the campaign

| Fact | Source | Was in `shai-hulud-defense.md`? |
|---|---|---|
| **CVE-2026-45321 (CVSS 9.6)** assigned to Mini Shai-Hulud / TanStack chain | Tenable | ❌ no |
| 84 malicious versions across 42 @tanstack packages, published in **<6 minutes** | TanStack postmortem, Snyk | partial |
| **518M cumulative weekly downloads** affected | OX Security, ThreatLocker | ❌ no |
| **PyPI also affected** (not just npm) — 170+ packages spanning both | OX Security, Corgea | ❌ no |
| **OpenAI: 2 employee devices compromised**, internal source repos accessed, code-signing certs rotated for iOS/macOS/Windows | Rescana | ❌ no |
| AntV campaign: **639 malicious versions across 323 packages in a 22-minute automated burst** on May 19 | Socket, Aikido, safedep | ❌ no (we had 300+) |
| Compromised maintainer account `atool` maintained 547 packages | Aikido | ❌ no |
| Affected packages with massive downstream: `echarts-for-react`, `size-sensor`, `@antv/scale`, `timeago.js` | Aikido | ❌ no |

### Newly understood attack mechanism

The earlier analysis treated "OIDC abuse" as a single technique. Researchers
have since broken down **CVE-2026-45321** into a **chained exploit**:

1. Attacker **forks** the target repo and opens a PR triggering
   `pull_request_target` workflow.
2. Workflow runs **in the base repo's trusted context**, executing
   attacker-controlled code from the fork.
3. Attacker code **poisons the GitHub Actions cache** with a malicious
   pnpm store.
4. On the next release run (triggered by maintainer), the poisoned
   cache hydrates the build.
5. Build-time code **extracts the OIDC token** from `/proc/<runner-pid>/mem`.
6. Token is exchanged via npm's federation endpoint for a publish token
   bound to the legitimate publisher identity.
7. Packages are published with **valid SLSA Build Level 3 provenance**
   (this is the first documented case of malicious npm packages with
   legitimate Sigstore provenance).

**Implications for sealed-env**:
- Module 6 of our analysis already said "audit `.github/workflows/release.yml`".
  Now we know the audit must specifically catch `pull_request_target`
  usage AND cache scoping AND `id-token: write` scope.
- We need to be honest with users: **provenance attestation is not
  sufficient proof of safety** when the publisher's CI is compromised.
  Pin to digests, use release-age cooldowns.

### IDE persistence: now confirmed durable across uninstall

Multiple researchers (Snyk, Socket, Aikido) now confirm that the
`.claude/settings.json` + `.vscode/tasks.json` payload **persists even
after `npm uninstall`** of the compromised package. The IDE files
themselves are the persistence vector; the original npm package is
disposable infrastructure.

**Implications for sealed-env**:
- Our `doctor --check-ide-hooks` (shipped in 0.2.1) detects this.
- Should add a `--remediate` flag that offers to remove the files
  after user confirmation.

---

## Verified gaps in sealed-env's current defenses

Read the source. These are the gaps **after** verifying each claim.

### Gap 1 — `doctor`'s persistence check misses Linux `pgsql-monitor.service`

Upwind documented a new persistence vector specifically for Linux:
fake PostgreSQL monitoring service installed at
`/usr/bin/pgmonitor.py` + `/etc/systemd/system/pgsql-monitor.service`.
This is **in addition to** the `~/.config/systemd/user/gh-token-monitor.service`
we already documented.

Our current `doctor` only checks `.vscode/tasks.json` and
`.claude/settings.json` — it does not look at systemd units at all.

**File**: `node/src/cli/commands/doctor.ts` lines 230-280
**Fix**: extend `checkIdeBackdoorHooks` (rename to `checkPersistenceMarkers`)
to also enumerate user systemd units containing suspicious names.

### Gap 2 — No detection of workflow-level dangerous patterns

If a sealed-env user's project has `pull_request_target` in
`.github/workflows/*.yml`, they're vulnerable to the same chain that
hit TanStack. We don't surface this anywhere.

**File**: new — `node/src/cli/commands/audit_workflow.ts`
**Idea**: `sealed-env audit-workflow` scans `.github/workflows/*` for:
- `pull_request_target` triggers (warn — context-dependent)
- `id-token: write` at workflow level (should be job level)
- Unpinned action versions (`@v4` instead of `@<SHA>`)
- `checkout` of attacker-controllable refs (head.ref under PRT)

### Gap 3 — `init` doesn't lead with `keychain push` recommendation

Our analysis says `keychain push` is "the single most impactful step"
against FileSystemService. But `init` today prints all the generated
keys to stdout and writes them to `.env.local` without prominently
warning about disk exposure.

**File**: `node/src/cli/commands/init.ts`
**Fix**: end of `init` should print a clearly-formatted callout:

```
⚠ Your master key is now in .env.local.
  RECOMMENDED: move it to the OS keychain immediately:
    sealed-env keychain push
  Without this, any process that scans .env files (including
  malicious npm postinstall scripts) can read your master key.
```

### Gap 4 — No documentation of post-compromise incident response

Datadog's analysis describes a deadman switch that executes `rm -rf ~/`
when the GitHub token is revoked. We mention this in `shai-hulud-defense.md`
but provide no playbook.

**File**: new — `docs/incident-response.md`
**Content**: ordered steps for compromised host (power off, image disk,
remove persistence files BEFORE revoking tokens, rotate credentials).

### Gap 5 — Release workflow uses long-lived NPM_TOKEN

Our `.github/workflows/node-release.yml` still uses `NODE_AUTH_TOKEN`
from a stored secret. This is exactly the credential the Shai-Hulud
framework wants to steal. Trusted publishing with OIDC was added by npm
in 2023 and is recommended for security-conscious libraries.

**File**: `.github/workflows/node-release.yml` + npmjs config
**Fix**: configure trusted publishing on npmjs.com, remove
`NODE_AUTH_TOKEN`, rely on OIDC.

### Gap 6 — No CHANGELOG / SECURITY.md reference to CVE-2026-45321

Our own CVE-2026-45321 reference in `THREAT_MODEL.md` only references
the original Shai-Hulud campaigns. The Tenable-assigned CVE for the
Mini variant has CVSS 9.6 and is the primary technical citation
researchers will look for.

**File**: `THREAT_MODEL.md` + `SECURITY.md` + `CHANGELOG.md` for 0.2.2
**Fix**: add explicit CVE-2026-45321 reference where we discuss the
TanStack incident.

### Gap 7 — Provenance verification not documented for consumers

We just shipped 0.2.1 with SLSA provenance. But our README does not
tell consumers how to verify it on install.

**File**: `README.md`
**Fix**: add a "Verify install" section:

```bash
# Verify the provenance attestation matches our release pipeline
npm audit signatures sealed-env
```

### Gap 8 — Worm's `+3 version bump` fingerprint not used as detection signal

Researchers documented that the worm propagation pattern is
distinctive: it bumps the patch version by exactly +3 every time it
republishes. Our `scan` and `doctor` could surface this as an upstream
detection signal — "your `.npmrc` has access to packages where the
last 3 versions all jumped patch by +3, that's a Shai-Hulud signature".

**File**: this is more of an idea for an external tool, not
sealed-env per se. Document in `shai-hulud-defense.md`.

### Gap 9 — No `.pypirc` detection in doctor

Mini Shai-Hulud now affects PyPI too. Our doctor only scans `.env` /
`.env.local` for master keys. If we extend it to also flag `.pypirc`
plaintext tokens, we help Python operators who use sealed-env's
cross-stack patterns. (Currently sealed-env doesn't have a Python
port, but operators who use Node + Python together still benefit.)

**File**: `node/src/cli/commands/doctor.ts`
**Fix**: add a check for plaintext credentials in `~/.pypirc` and
warn if found. Low effort, signals defense-in-depth posture.

---

## Prioritized improvement list

### Priority 1 — ship in 0.2.2 (≤1 month)

#### P1.1 — Extend `doctor` persistence check to Linux systemd units

- **Type**: code change
- **File**: `node/src/cli/commands/doctor.ts` (the `checkIdeBackdoorHooks` function)
- **Description**: Rename to `checkPersistenceMarkers`. Add detection
  for systemd user units in `~/.config/systemd/user/` whose names match
  known persistence patterns: `*gh-token*`, `*pgsql-monitor*`,
  `*pg-monitor*`. Also check LaunchAgent paths on macOS for the same
  patterns. Report findings as warnings with link to incident-response doc.
- **Defensive value**: Catches Upwind-documented Linux persistence
  + Datadog-documented macOS persistence. Closes Gap 1.
- **Effort**: S (1-2h including tests)
- **Risk**: low — read-only file checks, no destructive ops
- **Dependencies**: none
- **Verification**: integration test creates a fake `pgsql-monitor.service` in tmpdir, runs doctor, asserts warning

#### P1.2 — `init` prints `keychain push` recommendation prominently

- **Type**: code change
- **File**: `node/src/cli/commands/init.ts`
- **Description**: After generating keys, print a clearly visible
  callout (Unicode boxes, color if TTY) recommending `keychain push`.
  Don't auto-execute — operator should make the choice consciously.
- **Defensive value**: Closes Gap 3. The single most impactful step
  for FileSystemService defense, now surfaced at the moment it matters most.
- **Effort**: S (30 min)
- **Risk**: low — purely additive output
- **Dependencies**: none
- **Verification**: snapshot test of `init` output in basic/team/enterprise modes

#### P1.3 — `docs/incident-response.md` playbook

- **Type**: doc change
- **File**: new — `docs/incident-response.md`
- **Description**: Step-by-step playbook for compromised host. Order
  matters: power off, image disk, remove persistence files (with exact
  paths from IOCs), THEN rotate credentials. Specifically warn about
  the deadman switch that executes `rm -rf ~/` on token revocation —
  this is the kind of warning that has saved researchers' home
  directories in real incidents.
- **Defensive value**: Closes Gap 4. Even without code changes, this
  doc could be the most important deliverable in this list — operators
  in panic mode need a checklist, not narrative.
- **Effort**: M (2-3h)
- **Risk**: low — documentation
- **Dependencies**: none
- **Verification**: peer review by someone else who hasn't read our threat model

#### P1.4 — `--remediate` flag on `doctor`

- **Type**: code change
- **File**: `node/src/cli/commands/doctor.ts`
- **Description**: When `doctor --remediate` is passed and persistence
  markers are found, offer to **remove** them after y/N confirmation.
  Only remove files matching strict allowlist of known-malicious patterns.
  Backup to `.sealed-env-quarantine/` before delete.
- **Defensive value**: Closes the "even after npm uninstall the
  backdoor remains" gap. One-command cleanup for an operator who
  knows what doctor is telling them.
- **Effort**: M (2-4h with tests)
- **Risk**: medium — destructive operation; needs careful confirmation
  UX and quarantine path; needs tests against accidentally deleting
  legitimate `.vscode/tasks.json` files
- **Dependencies**: P1.1
- **Verification**: integration tests for happy path, refuse-on-no path,
  unknown-pattern path

#### P1.5 — Document CVE-2026-45321 in THREAT_MODEL.md

- **Type**: doc change
- **File**: `THREAT_MODEL.md` (Section 1, Shai-Hulud subsection)
- **Description**: Add explicit reference to CVE-2026-45321 (CVSS 9.6)
  as the official MITRE classification of the Mini Shai-Hulud /
  TanStack chain. Note: this is the externally-assigned CVE for the
  Mini variant; our own CVE-2026-45091 is unrelated (it's our
  self-disclosure for the token-payload exposure bug).
- **Defensive value**: Closes Gap 6. Provides a citation researchers
  expect to see.
- **Effort**: S (15 min)
- **Risk**: low
- **Dependencies**: none

#### P1.6 — Document provenance verification in README

- **Type**: doc change
- **File**: `README.md`
- **Description**: Add a small section under installation showing
  `npm audit signatures sealed-env` to verify the provenance we ship.
  Explain why this matters in 2-3 sentences.
- **Defensive value**: Closes Gap 7. Makes our provenance investment
  legible to users.
- **Effort**: S (15 min)
- **Risk**: low

#### P1.7 — Extend `scan` patterns to `.pypirc`

- **Type**: code change + spec
- **File**: `SECRET-PATTERNS.md` + `node/src/cli/scan/patterns.ts` +
  `node/src/cli/commands/doctor.ts`
- **Description**: Add pattern `SE-K4: pypi-token` to detect plaintext
  PyPI tokens (`pypi-AgEIcHlwaS5vcmcC...`). Even though sealed-env
  doesn't yet manage Python projects, operators frequently have both,
  and detecting leaked PyPI tokens is high-value at low cost.
- **Defensive value**: Closes Gap 9. Cross-ecosystem hygiene for the
  operator audience.
- **Effort**: M (1-2h with tests)
- **Risk**: low — additive pattern, tested with corpus
- **Dependencies**: none
- **Verification**: positive + negative fixtures added to test corpus

---

### Priority 2 — ship in 0.3.0 ("Simplicitas" — credential modernization)

#### P2.1 — Trusted publishing migration

- **Type**: process change + workflow change
- **File**: `.github/workflows/node-release.yml` + npm settings
- **Description**: Configure trusted publisher on npmjs.com pointing
  to our release workflow. Remove `NPM_TOKEN` from GitHub secrets.
  Rely entirely on OIDC. This is exactly Module 6 of our defense doc.
- **Defensive value**: Closes Gap 5. Eliminates the most attractive
  credential for a Shai-Hulud-class compromise of David's machine.
  If the laptop is compromised, the worm cannot publish a malicious
  `sealed-env@0.2.2` because there's no token to steal.
- **Effort**: L (4-6h including testing in a dry-run release)
- **Risk**: medium — one bad workflow run can break the release pipeline;
  we should validate against a `node-v0.2.2-test.1` prerelease before
  going hot
- **Dependencies**: npm trusted publisher application + approval
  (timing: usually instant, but verify)
- **Verification**: publish a test version with the new flow, confirm
  attestation appears + no `NPM_TOKEN` was used

#### P2.2 — `sealed-env audit-workflow` CLI subcommand

- **Type**: new feature
- **File**: new — `node/src/cli/commands/audit_workflow.ts`
- **Description**: Scan `.github/workflows/*.yml` for known dangerous
  patterns: `pull_request_target` with checkout of head.ref,
  `id-token: write` at workflow level, unpinned action versions,
  `npm publish` without provenance flag, environment-less publish jobs.
  Output in same JSON schema as `scan` for CI integration.
- **Defensive value**: Closes Gap 2. Gives every sealed-env user a
  one-command audit of their CI hygiene, not just their secrets.
- **Effort**: L (6-10h with reasonable rule set + tests)
- **Risk**: medium — false positives if rule set is too aggressive;
  benchmark against zizmor's rule set for parity
- **Dependencies**: none, but should reference our threat model

#### P2.3 — Rotation cadence recommendation

- **Type**: doc + UX change
- **File**: `docs/key-rotation.md` (new) + `sealed-env doctor` output
- **Description**: Recommend rotating the master key every 90 days.
  `doctor` reads the sealed file's `kdf_params.salt` creation date
  (proxy via `last_modified` of `.env.sealed`) and warns if >90 days.
  Suggest `sealed-env rotate`.
- **Defensive value**: Limits the value of a stolen master key. Even
  if a Shai-Hulud variant captures the master key in May, rotating
  in August means the captured key opens nothing by then.
- **Effort**: M (2-3h)
- **Risk**: low — warning only, doesn't force rotation

#### P2.4 — Hardware-backed key storage research

- **Type**: research / spec
- **File**: `SPEC.md` addendum + design doc
- **Description**: Investigate TPM 2.0 / Apple Secure Enclave / YubiKey
  PIV slots as alternatives to OS keychain for master key storage.
  The keychain is already harder to scrape than `.env.local`, but
  hardware-backed storage is the gold standard. Output: design doc
  for `keychain --backend=tpm`.
- **Defensive value**: Future-proofs sealed-env against hypothetical
  variants that learn to scrape OS keychains.
- **Effort**: XL (10-20h research + design only; implementation later)
- **Risk**: low — doc only at this stage

---

### Priority 3 — research / spec / community

#### P3.1 — OpenSSF Scorecard adoption

- **Type**: process change
- **File**: `.github/workflows/scorecard.yml` (new) + badge in README
- **Description**: Adopt the OpenSSF Scorecard action for objective
  scoring of our security practices. We probably already pass most
  checks (provenance, pinned actions, branch protection if we set it).
- **Defensive value**: External attestation of practices, not a defense
  per se. Useful for credibility.
- **Effort**: S (1-2h)
- **Risk**: low

#### P3.2 — Branch protection + signed tags

- **Type**: process change
- **File**: GitHub repo settings + `git config`
- **Description**: Require PR review on `main`, require signed commits,
  sign tags with GPG. The TanStack postmortem specifically calls out
  unprotected main branches as a fundamental enabler of supply-chain
  attacks.
- **Defensive value**: Closes the door on a worm pushing a tampered
  commit to `main` even with stolen GitHub credentials.
- **Effort**: S (30 min)
- **Risk**: low — slight friction for solo development

#### P3.3 — Public threat model exercise: PyPI port

- **Type**: research
- **File**: `THREAT_MODEL/python.md` (new)
- **Description**: Threat-model what a Python port of sealed-env would
  defend against, given the PyPI ecosystem also being affected by Mini
  Shai-Hulud. Not committing to building it — just researching whether
  the Java port + Node port story should expand.
- **Effort**: M (3-4h)
- **Risk**: low — doc only

---

## Architectural changes for unknown future variants

These don't fit a release timeline but inform direction.

### A1 — Move toward credential delivery via Unix socket / named pipe

The current `exec` model passes credentials via `process.env` to the
child. `exec.ts` correctly **strips** master keys from the child env,
but the **parent process** has them in env during the spawn window.

A future variant that scrapes process env across the entire host
(rather than only the runner.worker process) gets us during that window.

A more isolated mechanism would be: parent passes credentials via a
short-lived Unix socket or named pipe that the child opens and reads
in one shot. Tradeoffs: complicates the API (apps need to opt in),
but eliminates the env-var window entirely.

This is a 0.4.x+ idea; we'd need a real API design and community input.

### A2 — Workflow integrity verification on `npm install` time

Crazy idea: `sealed-env` postinstall verifies the workflow file in
the consuming project AGAINST our recommended baseline. If it finds
dangerous patterns, refuses to install (`npm install --ignore-scripts`
bypasses, of course).

Why crazy: postinstall scripts are exactly the vector Shai-Hulud
uses. Adding our own postinstall undermines our own threat model.

Reject. But interesting to note explicitly so future contributors
don't propose it.

### A3 — Multi-party signature on releases (Shamir-style)

For high-value releases (0.x.y where x is a major), require N-of-M
maintainers to sign. We have one maintainer today (David), so this
is purely forward-looking for if/when sealed-env grows.

This is on the existing 0.4.0 roadmap (Shamir threshold sharing).

---

## Honest non-findings

Areas I reviewed carefully and found **nothing worth changing**:

### `exec.ts` env hygiene is correctly implemented

The strip list (lines 123-130 of `node/src/cli/commands/exec.ts`) is
complete and correct. The plaintext buffer wipe with `.fill(0)` is
correct. The `shell: false` + signal forwarding is correct. For the
threat model sealed-env claims (server doesn't see master keys), this
is well-done.

The parent-process env-var-window concern is real but **on-spec**: the
threat model explicitly says we don't defend against host compromise.

### `unsealToken.ts` TTL clamping is correct

`Math.min(input.ttlSeconds ?? 60, MAX_UNSEAL_TOKEN_AGE_SECONDS)` on
line 68 of `node/src/totp/unsealToken.ts` prevents an operator from
accidentally minting a long-lived token. The min-TTL check (line 70)
prevents pathological short windows. Good.

### Replay cache + `ops_id` single-use is sound

Reviewed `node/src/core/api.ts` integration of the replay cache. The
LRU semantics + opsId binding + TTL respect are all correct. This is
exactly the defense that limits a scraped unseal token to a single
use within its TTL.

### Cross-stack byte-identical wire format is the right design choice

Verified by reading test-vectors under `test-vectors/v1/`. The fact
that a sealed file written from Node decrypts byte-identically from
Java (and presumably Rust when the port lands) is the kind of
property that AUDITORS love. Future researchers will be able to
cross-check our work easily.

### Release workflow is mostly already hardened

`.github/workflows/node-release.yml` already:
- Pins all action versions to commit SHAs (not tags) ✓
- Restricts `id-token: write` to the publish job only ✓
- Does NOT use `pull_request_target` ✓
- Uses an `environment: npm-publish` (which CAN have required reviewers
  if we configure it) ✓
- Uses `npm ci` (frozen lockfile) ✓
- Tests before publish ✓

The remaining hardening is just the trusted publisher migration (P2.1).

---

## Closing thought

The Mini Shai-Hulud campaign was successful against TanStack — a
reputable project — primarily because of a chained workflow vulnerability,
not because secret-management was poor. The defensive lesson is humbling:
**sealed-env can't save users whose CI is compromised**. What sealed-env
CAN do, well, is limit the BLAST RADIUS of a compromise:

- With `keychain push`: master key not on disk to be scraped
- With short-TTL unseal tokens: scraped tokens expire before exfil completes
- With replay cache: scraped tokens are one-shot
- With provenance + trusted publishing: malicious republish of
  `sealed-env` itself becomes much harder
- With workflow audit: catches the precursor conditions before
  attackers do

Each P1 item closes a gap that researchers DOCUMENTED but our shipped
code doesn't address. Each P2 item raises the bar for future
contributors. Together they represent a **second wave** of hardening
beyond the 0.2.1 marketing claim.

The framing in our README — "reduces the impact, does not prevent
the compromise" — remains correct. This roadmap just makes the
"reduces the impact" claim deeper.

---

## Sources

- TanStack postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Snyk — TanStack analysis: https://snyk.io/blog/tanstack-npm-packages-compromised/
- Snyk — AntV campaign: https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/
- Socket — AntV burst analysis: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- Tenable — CVE-2026-45321 FAQ: https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
- Upwind — TanStack analysis: https://www.upwind.io/feed/shai-hulud-tanstack-supply-chain-worm
- Aikido — AntV strikes again: https://www.aikido.dev/blog/mini-shai-hulud-antv-npm-supply-chain-attack
- Phoenix Security — TeamPCP TanStack: https://phoenix.security/mini-shai-hulud-teampcp-tanstack/
- Rescana — OpenAI macOS impact: https://www.rescana.com/post/openai-macos-products-impacted-by-tanstack-supply-chain-attack-via-mini-shai-hulud-malware-in-teampcp-campaign/
- OX Security — AntV ecosystem: https://www.ox.security/blog/the-antv-ecosystem-was-compromised-with-shai-hulud-malware-300-packages-affected/
- ThreatLocker — TeamPCP attack: https://www.threatlocker.com/blog/teampcp-supply-chain-attack-hits-tanstack
- BleepingComputer — signed malicious packages: https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/
- Corgea — 170+ packages compromised: https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud
- safedep — 317 packages: https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
- The Register — TanStack invitation-only PRs: https://www.theregister.com/security/2026/05/18/tanstack-weighs-invitation-only-pull-requests-after-supply-chain-attack/5241899
- The Hacker News — Mistral + Guardrails: https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html
