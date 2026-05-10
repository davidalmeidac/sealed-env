# Changelog

All notable changes to `sealed-env` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The wire format (`SEALED-ENV-V1`) follows its own stability commitment:
files written today will remain readable forever. See [SPEC.md](./SPEC.md).

---

## [Unreleased]

### Security

- **SEC-006 (Node): Replay cache wired into `loadSealed`/`unseal` by default.**
  Re-using a token within its TTL is now rejected with `TOKEN_INVALID` (cause: `replay`).
  A shared module-level `InProcessReplayCache` (10k-entry LRU) is provided automatically —
  no caller configuration required. Inject a custom `ReplayCache` implementation
  (e.g. Redis-backed) via `LoadSealedOptions.replayCache` / `UnsealOptions.replayCache`
  to share replay state across processes. Opt out via `replayCache: null` (emits a
  one-time stderr warning containing `replay-cache-disabled`).
  Java parallel implementation coming in PR-B1b.

<!-- SEC-009 section added by PR-B2 -->

---

## [0.1.1] — 2026-05-10

### Security

- **SEC-002 — scrypt cost-floor enforced.** `DEFAULT_SCRYPT_PARAMS.N` raised
  from `32768` to `131072` (OWASP 2024 login-authentication floor for scrypt).
  New seals write `KDF-PARAMS=N=131072,r=8,p=1`. Files written by 0.1.0 with
  `N=32768` continue to decrypt correctly — the parser reads stored params from
  the file header without override. Java side is Argon2id-only for writes and
  already above the cost floor; no Java source change required.

- **SEC-003 — sealed-file writes are now mode 0600 on POSIX.** The CLI
  commands `encrypt`, `set`, `edit`, and `rotate` all use a shared
  `writeSealedFile` helper. On POSIX, written files and `.bak` backups are
  created with mode `0o600` (was `0o644` in 0.1.0). Windows mode semantics
  are unchanged (NTFS ACLs, not POSIX bits).

- **SEC-005 — `unseal` now requires an explicit salt source.** Running
  `sealed-env unseal` without `--file` or `--salt` now exits with
  `CONFIG_ERROR` instead of silently using a zero-salt sentinel. To opt
  into the legacy zero-salt path (not for production), pass
  `--unsafe-zero-salt`. All existing demos and CI recipes already pass
  `--file`; no user-visible breakage expected.

- **SEC-007 — token epoch field strictly validated before base64 decode.**
  `verifyUnsealToken` now validates that `payload.epoch` matches
  `/^[A-Za-z0-9+/]+={0,2}$/` before calling `Buffer.from`. Characters
  outside the standard base64 alphabet (e.g. whitespace injected by
  a proxy) cause an immediate `TOKEN_INVALID`. Java's `Base64.getDecoder()`
  was already strict; this aligns Node behavior. A cross-stack test vector
  (`test-vectors/v1/enterprise-token-malformed-epoch.json`) documents the
  expected rejection across all stacks.

- **SEC-021 — all GitHub Actions `uses:` lines pinned to 40-char commit
  SHAs.** A lint script (`node/scripts/lint-workflows.mjs`) enforces pinning
  in CI. Dependabot is configured to open grouped weekly PRs to update
  pinned SHAs. *(Shipped in PR-A1, merged before this release.)*

### Internal

- Sealed-file writes (`encrypt`/`set`/`edit`/`rotate`) are now atomic via
  temp-write + fsync + rename (SEC-019). A crash mid-write no longer corrupts
  the destination file; the previous content is preserved until the rename
  completes.

---

## [Unreleased]

### Security

- **CVE-2026-45091 has been reserved by a CNA** for the JWS-payload
  TOTP-secret leak that affected `0.1.0-alpha.{1,2,3}` and was
  patched in alpha.4 on 2026-05-07. The record is currently in the
  RESERVED state at
  [cve.org/CVERecord?id=CVE-2026-45091](https://www.cve.org/CVERecord?id=CVE-2026-45091)
  pending publication of the full description by the assigning CNA;
  it will appear in NVD shortly thereafter. No code change in this
  entry — references throughout the repository (README, THREAT_MODEL,
  Java regression tests, CHANGELOG) updated to cite the official
  identifier alongside the existing GitHub Security Advisory
  ([GHSA-x3r2-fj3r-g5mv](https://github.com/davidalmeidac/sealed-env/security/advisories/GHSA-x3r2-fj3r-g5mv)).

---

## [0.1.0] — 2026-05-07

**First stable release.** The wire format (`SEALED-ENV-V1`) is frozen
and will remain readable forever. The public API is stable. Bug-fix
and non-breaking feature releases land as `0.1.x`; breaking changes
wait for `0.2.0`.

What 0.1.0 represents:

- A wire-format-compatible **cross-stack** library: Node (npm) and
  Java (Maven Central) read and write the same `.env.sealed` files,
  validated by cryptographic test vectors in CI.
- A complete operator toolchain in the Node CLI: `init`, `encrypt`,
  `decrypt`, `get` / `set` / `edit` / `diff`, `exec`, `deploy`,
  `keychain`. The Java side ships as library + Spring Boot starter;
  a Java-native CLI is on the 0.2.0 roadmap.
- Three modes — **basic**, **team**, **enterprise** — with
  progressive defense: basic gives encryption-at-rest, team adds
  HMAC integrity for shared repos, enterprise adds TOTP-bound
  per-deploy authorization.
- Two decrypt strategies — **Model A (host-side)** via
  `deploy --remote` and **Model B (in-process)** via the Spring
  starter / Node loader — explicitly documented with the trade-off.
- 17 platform CI/CD recipes (GitHub Actions, GitLab, Bitbucket,
  CircleCI, Jenkins, Azure, AWS, GCP, Vercel, Netlify, Fly.io,
  Render, Railway, Heroku, Docker, Kubernetes, generic SSH) plus an
  OIDC-federation pattern for shops that want zero persistent
  master-key storage in CI.
- A public threat model (T1-T13) and a track record of CVE response.
  alpha.4 closed [CVE-2026-45091](https://www.cve.org/CVERecord?id=CVE-2026-45091)
  (JWS-payload TOTP-secret leak) in under four hours with cross-stack
  vectors and a migration playbook.

### Added

- **`sealed-env deploy --remote <user@host>`** (Node CLI) — Model A
  host-side decrypt deploy. Decryption happens on the operator's
  machine; only the resulting plaintext env vars cross the network
  through an SSH tunnel. The remote server never holds the master
  key, the signing key, or the sealed file. Significantly raises the
  defense ceiling at rest on the production server (see
  [docs/10-decrypt-strategies.md](./docs/10-decrypt-strategies.md)).

  Implementation notes:
  - Plaintext env vars travel via stdin to a remote `/bin/sh` — never
    in argv, never visible in remote `ps aux`.
  - Pre-flight SSH validation runs **before** decryption, so a
    misconfigured target fails fast without ever holding plaintext
    in memory.
  - Bash-safe single-quote escaping on every value (including
    embedded quotes, `$`, backticks, newlines, unicode).
  - Deterministic, sorted output of the remote shell script — useful
    for reproducible deploys and future cross-stack vector tests.
  - Reuses the existing TOTP-bound `unseal_token` mint flow when the
    sealed file is in enterprise mode.
  - New flags: `--remote <user@host>`, `--ssh-port`, `--ssh-key`.
  - Existing local-deploy behaviour is unchanged when `--remote` is
    not passed.

- **New utility modules `node/src/cli/utils/ssh.ts` and
  `node/src/cli/utils/health-check.ts`** — small, focused helpers
  that keep `deploy.ts` readable. The `ssh` module shells out to the
  system `ssh` binary instead of bringing in a library, honoring the
  zero-deps promise of the core.

- **18 new unit tests** covering SSH target parsing, shell escaping
  edge cases (single quotes, `$`, backticks, newlines, unicode,
  injection attempts), remote-script generation determinism, and
  health-check polling behaviour (timeout, network errors, retries).

### Documentation

- **New `docs/10-decrypt-strategies.md`** — explicit treatment of the
  Model A (host-side decrypt) vs Model B (in-process decrypt)
  trade-off, including:
  - Side-by-side attacker-yield comparison for each model.
  - How enterprise mode mitigates Model B by tightening the window
    in which a stolen key is useful.
  - Decision tree mapping a deployment scenario to a recommended
    strategy.
  - **Forward spec for `sealed-env deploy --remote`** — the CLI flag
    that promotes Model A from "concept buried in docs" to a
    first-class command. Includes flag surface, behaviour, artefact
    placement, and the failure modes the wrapper handles vs the
    operator's residual responsibilities.
- **`docs/08-cicd-recipes.md` and `docs/09-lifecycle.md` updated**
  to cross-reference doc 10 wherever they previously presented the
  Spring Boot starter / Node loader as the default. The text now
  acknowledges that the convenient path is Model B and links to the
  trade-off discussion so readers make an informed choice.

- **New `docs/09-lifecycle.md`** — end-to-end narrative covering the
  three phases of a sealed-env project: **init** (greenfield setup
  with key generation, gitignore management, and the QR enrollment for
  enterprise mode), **onboarding** (how a new teammate clones the repo
  and receives the master key out-of-band, with the optional keychain
  flow), and **deploy** (basic vs enterprise modes, the `sealed-env
  deploy` wrapper, and where each platform recipe plugs in). Cross-links
  every existing doc so new readers have a single map to the surface
  area instead of having to assemble it from quickstarts and reference
  pages.

- **Expanded `docs/08-cicd-recipes.md`** — five new platform recipes
  added, all following the same pattern (master key in native secret
  store + decrypt at runtime + cleanup):
  - **Bitbucket Pipelines** with secured variables and Deployments
    scope, plus enterprise unseal-token minting.
  - **CircleCI** with shared Contexts and `BASH_ENV` token persistence
    for enterprise mode.
  - **Jenkins** with both declarative and scripted pipeline syntax,
    a tip about Vault-backed credentials for shared controllers, and
    enterprise mode via `withCredentials` blocks.
  - **Azure** — four sub-sections: Container Apps (Key Vault refs),
    App Service (`@Microsoft.KeyVault(...)` settings), Functions
    (managed-identity SDK fetch at cold start), and Azure Pipelines
    (variable groups + `##vso[task.setvariable]`).
  - **Railway** with CLI / `railway.toml` configuration and
    per-service variable scoping guidance.
  - Top-level READMEs updated to list all 17 supported platforms.

---

## [0.1.0-alpha.8] — 2026-05-07

UX hot-fix on top of alpha.7. **No wire-format changes.**

### Changed

- **Keychain backend is now strictly opt-in.** alpha.7 always tried to
  read from the OS keychain on every CLI invocation, even for users
  who had never run `sealed-env keychain push` — that meant ~300 ms of
  PowerShell/security/secret-tool spawn overhead per command. Not OK.

  alpha.8 only checks the keychain when the project has explicitly
  opted in:

  - `sealed-env keychain push` now writes `.sealed-env.json` (a small
    JSON marker file with `{ "storage": "keychain", ... }`) to the
    project root. Safe to commit — contains no secrets.
  - The auto-loader checks for that marker file BEFORE even loading
    the keychain backend module. If the marker is absent, the
    keychain code path is fully bypassed.
  - `SEALED_ENV_USE_KEYCHAIN=1` is honored as an alternative opt-in
    for one-off / CI scenarios.

  `sealed-env keychain clear` and `pull` remove the marker.
  `sealed-env keychain status` now reports whether the marker is
  present so users can audit their setup.

  Measured impact: `sealed-env doctor` overhead dropped from ~1.7 s
  to ~250 ms when the project hasn't opted in. The keychain feature
  remains exactly as functional as in alpha.7 for projects that have
  opted in.

---

## [0.1.0-alpha.7] — 2026-05-07

Operator ergonomics + hardened key storage. **No wire-format changes** —
files sealed by previous `0.1.0-alpha.x` releases (≥ alpha.4) decrypt
cleanly on `0.1.0-alpha.7`.

### Added

- **`sealed-env exec` now handles enterprise mode end-to-end.** When the
  file is enterprise, exec mints the unseal token IN MEMORY (prompting
  for the TOTP code if `--totp` not given), uses it to decrypt, and
  injects the resulting `KEY=value` pairs into the child process. The
  raw token never appears in stdout/stderr/disk. Master/signing/TOTP
  credentials are also stripped from the child's environment, so the
  application sees only `DATABASE_URL` etc., never `SEALED_ENV_KEY`.

  ```sh
  # Single-line replacement for a 130-line deploy.sh:
  sealed-env exec --file .env.sealed --deploy-id $(git rev-parse HEAD) \
    -- docker compose up -d --build status
  ```

- **`sealed-env deploy [-- <command>]`** — production deploy wrapper
  around `exec` that auto-detects `deploy_id` from `git rev-parse HEAD`,
  refuses to run with a dirty working tree (uncommitted changes would
  silently NOT be in the build), and optionally polls a health URL after
  the command finishes. Replaces the standard hand-rolled deploy.sh
  pattern with a single command.

  ```sh
  sealed-env deploy \
    --health-url http://127.0.0.1:8090/actuator/health \
    -- docker compose up -d --build status
  ```

- **`sealed-env keychain push|pull|status|clear`** — store
  `SEALED_ENV_*` secrets in the OS-native encrypted keychain instead of
  `.env.local` plaintext. Cross-platform via shell-out (no native deps):
    - Windows: DPAPI (`%LOCALAPPDATA%\sealed-env\*.bin`, encrypted with
      the user login key, inaccessible to other users on the machine).
    - macOS: `security` CLI (system Keychain).
    - Linux: `secret-tool` (libsecret / GNOME Keyring / KWallet).

  After `keychain push`, the auto-loader prefers the keychain over
  `.env.local`. The `status` subcommand prints a SHA-256 fingerprint
  per entry (no values), safe for logs and support threads.

- **`sealed-env unseal --token-only`** — emit just the token, no
  surrounding human-readable text. Designed for shell scripts:
  `TOKEN=$(sealed-env unseal --token-only --file ... --totp ...)`.
  No more parsing through `grep -oE 'usl_...'`.

### Changed

- **Auto-load priority** is now: `process.env` → OS keychain →
  `.env.local`. CI/explicit env vars still win. The startup hint
  on stderr now reads `(loaded N SEALED_ENV_* vars from OS keychain)`
  or `(... from .env.local)` so users know where their keys came from.

- **`init` no longer writes inline comments** in `.env.local`. The
  TOTP-secret-is-base32 hint moved to its own comment line above. The
  old inline form (`SECRET=value  # base32`) confused the auto-load
  parser, treating the comment as part of the value.

### Architecture note: host-side decrypt

This release enables a meaningful security upgrade for production
deploys. With `sealed-env exec` / `sealed-env deploy`, the operator's
machine does the full unseal (master key + signing key + TOTP secret +
mint token) and only injects the resulting plaintext env vars into the
container. The container — and the deploy host, if you deploy from
laptop via `DOCKER_HOST=ssh://...` — never sees the master key,
signing key, TOTP secret, or unseal token.

In contrast, the Spring Boot starter approach (which still works, no
breaking change) requires those credentials on the deploy host. For
single-instance deploys that's fine; for multi-container fleets the
starter is still the right call. Both are documented.

---

## [0.1.0-alpha.6] — 2026-05-07

UX release. **No wire-format changes** — files sealed by previous
`0.1.0-alpha.x` releases (≥ alpha.4) decrypt cleanly on `0.1.0-alpha.6`
and vice versa.

### Added

- **Auto-loading of `SEALED_ENV_*` from `.env.local`.** Every CLI
  command (except `init`, `version`, and `help`) now reads `.env.local`
  in the current directory at startup and injects any `SEALED_ENV_*`
  keys it finds into `process.env` — but only for keys that aren't
  already set. This means:

  - **Dev machines:** the user never has to run `set` / `export` /
    `$env:`. After `sealed-env init`, every subsequent command in that
    project directory just works.
  - **CI / production:** explicit env vars always win. A stray
    `.env.local` (which shouldn't exist there anyway) cannot
    accidentally override platform secrets.
  - **Other dotenv vars:** ignored. The auto-loader is intentionally
    NOT a generic dotenv loader — only `SEALED_ENV_*` keys are touched,
    so it never collides with `dotenv` or framework-level env loading.

  Set `SEALED_ENV_NO_AUTOLOAD=1` to disable. The CLI prints a one-line
  hint to stderr (`(loaded N SEALED_ENV_* vars from .env.local)`) so
  users know auto-loading happened.

### Changed

- **`init` output** now tells the user explicitly that they don't need
  to export anything — `.env.local` is auto-loaded — and points to the
  opt-out flag.

- **Operational guide** (`docs/07-operational-guide.md`) updated with
  the simplified onboarding flow for new developers: clone → write
  `.env.local` → run `sealed-env exec`. No more `export` step.

### Migration

None. This is a pure UX addition — `.env.local` was already being
created by `init` since `0.1.0-alpha.1`. We just read from it now.

---

## [0.1.0-alpha.5] — 2026-05-07

Polish + ops ergonomics on top of the alpha.4 security fix. **No wire-format
changes** — files sealed by `0.1.0-alpha.4` decrypt cleanly on `0.1.0-alpha.5`
and vice versa.

### Added

- **`sealed-env exec [--file <path>] [--override] -- <command> [args...]`** —
  decrypt the sealed file in memory and run a command with each `KEY=value`
  injected into its environment. The plaintext never lands on disk. Host env
  wins over sealed values by default; pass `--override` to flip that. Forwards
  SIGINT/SIGTERM to the child and propagates its exit code. Replaces the
  fragile `sealed-env decrypt > .env && command && rm .env` recipe.

  ```sh
  sealed-env exec --file .env.sealed -- node server.js
  sealed-env exec --file .env.sealed -- npm start
  ```

- **`sealed-env rotate <file>`** — re-seal in place with a fresh salt and
  nonce without changing any value. Invalidates any unseal token previously
  minted for this file. Use after a suspected token leak, on a regular
  rotation cadence, or after offboarding an operator. Backs up to `<file>.bak`
  same as `set`/`edit`.

- **`sealed-env doctor [<file>]`** — non-destructive diagnostic that validates
  env vars + sealed file + decrypt roundtrip WITHOUT printing any secret
  values. Each env var reports byte length and a short SHA-256 fingerprint
  (4 + 4 hex chars) — enough to tell two machines have the same key, useless
  to anyone observing the log. Safe to paste into CI logs and support threads.

- **Shell-aware `MISSING_KEY` error messages** — when an env var is missing,
  the error now includes the correct syntax for the user's shell. On Windows
  it shows PowerShell + cmd.exe + Git Bash side by side, with a note about
  the classic footgun: `set X=Y` in PowerShell creates a PowerShell variable,
  NOT an env var, so child processes can't see it. Propagated to all six
  call sites (`encrypt`, `decrypt`, `unseal`, `set`, `edit`, `doctor`,
  `exec`, `rotate`, `get`, `diff`).

### Changed

- **`qrcode-terminal` is now lazy-loaded.** It's pulled in via `createRequire`
  only when `init --mode enterprise` actually renders a QR. Restores the
  "core has zero third-party imports" property for `seal`/`unseal`/`decrypt`
  and all the operational commands. If the module ever becomes unavailable,
  the QR step falls back to plain URI output instead of crashing.

- **CI: `npm audit --audit-level=high --omit=dev`** runs on a single matrix
  cell (Linux + Node 22). Fails CI if any production dep has a high-severity
  advisory. Catches CVEs faster than waiting for the next Dependabot scan.

- **Workflow `permissions:` blocks** added explicitly to `node-ci.yml` and
  `node-release.yml` (CodeQL: "Workflow does not contain permissions"). All
  five workflows now scope `GITHUB_TOKEN` to the minimum needed.

### Fixed

- **CodeQL: incomplete regex escaping** in `.gitignore` membership check
  (`init` command). The previous code only escaped `.` in user-provided
  entries; replaced with a Set lookup over trimmed lines. Zero regex
  surface, simpler, correct for any future entry.

### Documentation

- **THREAT_MODEL.md** gained section 6 ("Token-payload exposure — lesson
  from sealed-env's own CVE") and matrix entry T13 documenting the
  `0.1.0-alpha.{1,2,3}` JWS-payload TOTP-secret leak. Captures three
  takeaways for future contributors:
  - JWT/JWS payloads are public — signature attests to integrity, not
    confidentiality.
  - Carry derived material in tokens, never raw secrets.
  - Use negative regression assertions ("the token MUST NOT contain X")
    to surface design regressions.

### Dependencies

- `bouncycastle` 1.78.1 → **1.84** — patches CVE-2026-5598 (Frodo timing
  channel) and CVE-2026-0636 (LDAP injection). sealed-env uses BC only
  for Argon2id and never touches Frodo or LDAP code paths; bumping is
  hygiene for downstream Dependabot status.
- `assertj-core` 3.26.3 → **3.27.7** — patches CVE-2026-24400 (XXE in
  `isXmlEqualTo`). Test-scope only and we don't process XML in tests.

---

## [0.1.0-alpha.4] — 2026-05-07

> **🚨 SECURITY: [CVE-2026-45091](https://www.cve.org/CVERecord?id=CVE-2026-45091)
> (RESERVED, full record pending CNA publication; advisory:
> [GHSA-x3r2-fj3r-g5mv](https://github.com/davidalmeidac/sealed-env/security/advisories/GHSA-x3r2-fj3r-g5mv)).
> This release fixes a critical issue in `enterprise` mode. Prior versions
> (alpha.1, alpha.2, alpha.3) embedded the operator's TOTP secret in the JWS
> payload of every unseal token. JWS payload is base64-encoded JSON, NOT
> encrypted — anyone observing a token (CI logs, container env dumps, stack
> traces) could extract the secret and use it (with the master key) to mint
> unseal tokens for FUTURE deploys indefinitely.**
>
> **All `0.1.0-alpha.{1,2,3}` releases are deprecated on npm and Maven
> Central. If you adopted enterprise mode in any of those versions:**
>
> 1. **Rotate your TOTP secret.** Re-run `sealed-env init --mode enterprise`.
> 2. **Re-seal all `.env.sealed` files.** Old files use the deprecated wire
>    field (`TOTP-VERIFIER`) and won't decrypt with `0.1.0-alpha.4`.
> 3. **Update CI / production env to use the new package version.**
>
> The wire format intentionally breaks compatibility — files sealed before
> alpha.4 are NOT readable by alpha.4. Since the package was not yet adopted
> in the wild (only the author's own dogfooding), this seemed safer than a
> backward-compatible code path that would silently keep reading the
> insecure field on old files.

### Security

- **CRITICAL: TOTP secret no longer appears in unseal tokens.** The token
  payload now carries an `enterprise_epoch`:
  ```
  enterprise_epoch = HMAC-SHA256(totp_secret, salt || "epoch-v1")
  ```
  This is a salt-bound HMAC derivative — knowing it does NOT let an
  attacker recompute it for files with a different salt. The blast radius
  of a leaked token is reduced from "permanent compromise of all current
  and future enterprise files" to "compromise of one specific file
  generation, until re-seal".

- **Wire format field renamed:** `TOTP-VERIFIER` → `EPOCH-COMMIT`. The new
  field commits to the salt-bound epoch instead of the raw TOTP secret:
  ```
  epoch_commit = HMAC-SHA256(derived_key, enterprise_epoch || "epoch-commit-v1")
  ```

- **Token payload field renamed:** `totp_secret` → `epoch`. Old field is
  rejected. Any code or test that referenced the old field will fail at
  parse time, surfacing the upgrade as a hard error rather than silent
  insecurity.

- **Regression tests added** that fail if either:
  - The serialized file contains `TOTP-VERIFIER`, or
  - A minted token contains the literal TOTP secret in any common encoding
    (hex or base64), or the field name `totp_secret`.

### Migration

This release is **incompatible with files sealed by `0.1.0-alpha.{1,2,3}`**.
To migrate:

```sh
# 1. Decrypt with the old version
npx sealed-env@0.1.0-alpha.3 decrypt .env.sealed > /tmp/.env.plaintext

# 2. Upgrade
npm i -D sealed-env@0.1.0-alpha.4

# 3. Re-init keys (TOTP secret rotation is mandatory)
sealed-env init --mode enterprise

# 4. Re-seal with the new keys
sealed-env encrypt /tmp/.env.plaintext --mode enterprise

# 5. Securely wipe the plaintext
shred -u /tmp/.env.plaintext   # or: rm -P on macOS
```

### Credit

This issue was identified by an external reviewer comparing the actual JWS
payload of a minted token against the operator's `.env.local` TOTP secret
and confirming bit-for-bit equality. Thank you for the careful eyes.

---

## [0.1.0-alpha.3] — 2026-05-06

Operational ergonomics release — adds the day-to-day commands that
were missing for sysadmins and operators. No wire-format changes;
files sealed by previous `0.1.0-alpha.x` versions decrypt cleanly on
`0.1.0-alpha.3` and vice versa.

### Added

- **`sealed-env get <file> <KEY>`** — print one variable's value to
  stdout. Composable: `STRIPE_KEY=$(sealed-env get .env.sealed STRIPE_KEY)`.
  Exits 1 if the key is not found, with the available key list in the
  error message.
- **`sealed-env set <file> <KEY> <VALUE>`** — update or add a single
  variable and re-seal in place. Comments and key order in the
  underlying `.env` are preserved. The previous sealed file is backed
  up to `<file>.bak` before overwriting.
- **`sealed-env edit <file>`** — opens `$EDITOR` (defaults to `vi` on
  Linux/macOS, `notepad` on Windows) with the plaintext for in-place
  editing. The temp file lives in `/dev/shm` (tmpfs, RAM-backed) on
  Linux when available, falls back to the OS temp dir elsewhere. Mode
  `0600`, zeroed and unlinked on exit including SIGINT/SIGTERM. Re-seals
  with the same mode/keys as the source on save.
- **`sealed-env diff <old.sealed> <new.sealed>`** — show which keys
  were added, removed, or changed between two sealed files. Values
  are hidden by default to avoid leaking secrets in CI logs and PR
  comments. Pass `--show-values` to reveal them. Long values are
  truncated at 60 characters. Exit code 0 if identical, 1 if different.
- **`init --mode enterprise` now renders a scannable QR code**
  directly in the terminal for the TOTP `otpauth://` URI. Point Google
  Authenticator / Authy / 1Password / Bitwarden at the screen and it
  pairs in under a second. The URI is still printed below the QR as a
  fallback for terminals that don't render Unicode half-block
  characters correctly.

### Refactored

- Internal: shared `decrypt → parse → reseal` helpers in
  `src/cli/utils/io.ts`. All five operational commands (decrypt, get,
  set, edit, diff) now go through one set of well-tested primitives,
  removing roughly 200 lines of duplication and ensuring consistent
  error handling across commands.

### Fixed

- **Smoke test `tampered HMAC is rejected`** had a ~1/64 chance of
  silently passing without actually tampering the HMAC, when the
  original first base64 character of the HMAC happened to be `'A'`
  and the test replaced it with the same character. The test now
  picks a guaranteed-different replacement.

### Documentation

- **New `docs/07-operational-guide.md`** — walks non-developers
  (sysadmins, managers, founders) through the five common workflows
  with no cryptography background required. Covers reading secrets,
  rotating leaked keys, comparing PR changes, onboarding a new
  developer, and how to integrate sealed-env into application code
  via the Spring Boot starter or the Node loader.
- **New `docs/08-cicd-recipes.md`** — copy-paste configurations for
  GitHub Actions (basic + enterprise mode with token minting and
  `::add-mask::`), GitLab CI (Protected + Masked variables, dotenv
  artifacts), AWS (ECS/Fargate, Lambda extension, EC2 with IAM +
  systemd), Google Cloud (Cloud Run, GKE with External Secrets
  Operator), Vercel, Netlify, Fly.io, Render, Heroku, Docker (with
  the rule that the master key must never be baked into the image),
  Kubernetes (`Secret` + `envFrom` + ESO), and bare-metal SSH.
  Includes a 5-point audit checklist.

### Dependencies

- **New runtime dependency: `qrcode-terminal@0.12.0`** — pure JS,
  zero transitive dependencies, MIT licensed, ~80 KB. Used only by
  the `init --mode enterprise` flow to render the TOTP QR code. Core
  cryptography and the `decrypt` / `get` / `set` / `edit` / `diff`
  paths remain dependency-free.

---

## [0.1.0-alpha.2] — 2026-05-06

Iteration on usability and onboarding. No wire-format changes; files
sealed by `0.1.0-alpha.1` decrypt cleanly on `0.1.0-alpha.2` and vice
versa.

### Fixed

- **CLI: `encrypt --out`** no longer auto-suffixes the user-provided
  path with `.sealed`. Previously, `--out file.sealed.basic` produced
  `file.sealed.basic.sealed` (double suffix). Now `--out` is respected
  exactly as given. The default (when `--out` is omitted) is still
  `<input>.sealed`.
- **CLI: `unseal`** now accepts `--file <.env.sealed>` and extracts the
  salt and KDF parameters automatically. Previously an operator had to
  decode the salt manually from the file and pass it via `--salt <hex>`,
  which was the documented but practically unusable path for
  `enterprise` mode. The `--salt` flag is kept for backward
  compatibility, and a stderr warning is emitted when neither flag is
  used (the zero-salt sentinel only works in single-process flows).

### Added — Open Source

- **Hands-on demo scripts** under `/playground/` for all three modes
  plus tampering and cross-stack interop. Self-contained bash scripts
  that generate ephemeral keys, seal a sample `.env`, demonstrate each
  mode end-to-end, and verify the roundtrip. Cross-platform: Git Bash
  on Windows, native bash elsewhere.
- **Cross-stack test vector for `enterprise` mode**
  (`test-vectors/v1/node-enterprise.json`) plus a Java interop test
  that builds its own unseal token from the file's salt + the master
  key + the TOTP secret committed in the vector. Cross-stack
  conformance suite now covers all three modes.
- **Open-source repository hygiene**:
  - `CONTRIBUTING.md` — local setup for both Node and Java sides,
    commit convention, crypto change policy, spec change policy,
    adapter contribution guide.
  - `CODE_OF_CONDUCT.md` — adopts Contributor Covenant 2.1 verbatim
    by canonical link.
  - GitHub issue templates: structured bug report, feature request,
    and `config.yml` that disables blank issues and routes security
    disclosures to the GitHub Security Advisory flow.
  - GitHub pull request template with a security review checklist
    required when crypto code is touched.
- **GitHub Discussions** enabled for design questions.

### Documentation

- **Expanded comparison table** in the root README. Adds HashiCorp
  Vault, Doppler, AWS Secrets Manager, and `dotenv` proper to the
  comparison. Includes a "when to pick which" decision section and an
  explicit "what `sealed-env` is not" callout to set expectations
  against centralized vault tooling.
- **Bilingual public landing site** at
  [davidalmeidac.github.io/sealed-env](https://davidalmeidac.github.io/sealed-env/)
  (English + Spanish) deployed via GitHub Pages. Plain HTML/CSS,
  single small i18n script, no runtime dependencies.
- **ASCII-art diagrams** replacing the previous Mermaid diagrams
  across all docs. Renders correctly in GitHub, any terminal,
  `cat`/`less`, and inside `git diff` — no JavaScript renderer
  required, which matters for a security tool whose docs should
  remain legible even when the rendering layer is unavailable or
  untrusted.
- **Cross-stack architecture diagram**, three-modes side-by-side
  comparison, and a visual mode-decision flowchart added to the root
  README.
- **Six numbered docs guides** under `/docs/` (overview, threat
  model, Node quickstart, Java/Spring Boot quickstart, enterprise
  mode walkthrough, format anatomy).
- **README documentation links repaired** — the previous version
  pointed to files that did not exist in `/docs/`.

### Sponsorship

- `FUNDING.yml` configured with GitHub Sponsors and Ko-fi.
- Sponsorship section on the landing page with three explicit tiers
  and honest framing about what the funds enable (security research,
  new language adapters, maintainer time).

---

## [0.1.0-alpha.1] — 2026-05-06

First public release. Both the Node and Java implementations are
published to their respective registries on this version.

> **⚠️ Alpha designation**: the public API is stable but minor breaking
> changes are still possible until v1.0.0. The wire format
> (`SEALED-ENV-V1`) is **frozen** and will remain readable forever.

### Added

#### Node implementation — `sealed-env` on npm

- AES-256-GCM authenticated encryption with HKDF-SHA256 subkey derivation.
- scrypt key derivation (RFC 7914) with `N=32768, r=8, p=1` defaults
  (Node 22 stdlib does not ship Argon2id).
- HMAC-SHA256 integrity tag for `team` and `enterprise` modes with
  domain-separated signing key.
- TOTP unseal token (RFC 6238) for `enterprise` mode, signed with the
  file's derived key (master + salt) and bound to a deploy challenge.
- High-level API: `seal()`, `unseal()`, `loadSealed()`.
- CLI: `npx sealed-env seal/unseal/init`.
- Zero runtime dependencies. Works on Node 20 and 22 (Linux, macOS,
  Windows).
- Memory wiping (`wipe(buf)`) of derived keys after use.

#### Java implementation — `io.github.davidalmeidac:sealed-env-core` + `sealed-env-spring-boot-starter` on Maven Central

- Pure Java 17, single auditable crypto module
  (`CryptoPrimitives.java`) using JDK stdlib for AES-GCM, HKDF, HMAC,
  scrypt, and SecureRandom; Bouncy Castle only for Argon2id.
- Reads both `KDF=scrypt` (Node-written files) and `KDF=argon2id`
  (Java-written files) for cross-stack interop.
- Java writer defaults to `KDF=argon2id` (`t=3, m=65536, p=4`).
- Spring Boot 3 starter with autoconfiguration:
  - `EnvironmentPostProcessor` runs before property binding so `@Value`
    and `@ConfigurationProperties` see decrypted values.
  - Driven by `application.yml` properties under the `sealed-env`
    prefix (path, fail-fast, override, env-var name customization).
- High-level API mirrors the Node side: `SealedEnv.seal()`, `unseal()`,
  `loadSealed()`.
- Single error type (`SealedEnvException`) with a stable `Code` enum.
- Constant-time equality (`MessageDigest.isEqual`) for all
  secret comparisons; defensive memory wiping on derived keys.

#### Cross-stack interoperability

- Single canonical wire format (`SEALED-ENV-V1`) consumed by both
  implementations.
- Node-generated test vectors under `test-vectors/v1/` (`node-basic.json`,
  `node-team.json`) read by automated Java tests on every commit.
- Byte-for-byte spec compliance verified by the Java test suite.

#### CI/CD

- `Node CI` workflow: matrix Linux/macOS/Windows × Node 20/22.
- `Java CI` workflow: matrix Linux/macOS/Windows × JDK 17/21,
  regenerates Node test vectors on each run before invoking
  `mvn -B verify`.
- `Node Release` workflow: publishes to npm with provenance attestation
  and OIDC.
- `Java Release` workflow: GPG-signs artifacts and publishes to Maven
  Central via the Sonatype Central Portal.

### Security

- **Public threat model** (`THREAT_MODEL.md`) mapping each defense to a
  real 2024-2025 supply-chain incident: Shai-Hulud npm worm,
  tj-actions/changed-files compromise, GhostAction campaign, Spring
  Boot heap-dump CVEs, backup leaks, and TOTP AitM phishing.
- AAD construction includes the magic line and all metadata except
  the `AAD-DIGEST` and `HMAC` fields themselves; mode-binding is part
  of the AAD so a `basic` file cannot be silently parsed as
  `enterprise` to bypass TOTP.
- Mandatory failure mode: all decryption errors collapse to a single
  generic message (`"sealed-env: file is corrupted, tampered, or wrong key"`)
  to avoid oracle-style information leaks.
- Allowed primitives: AES-256-GCM, Argon2id, scrypt, HKDF-SHA256,
  HMAC-SHA256, RFC 6238 TOTP (SHA-1 used **only** inside RFC 6238 as
  the standard mandates).
- Forbidden primitives: AES-CBC, PBKDF2, MD5, SHA-1 (outside TOTP),
  PKCS#1 v1.5 padding, custom RNGs.

### Wire format

- `SEALED-ENV-V1` specification published in [SPEC.md](./SPEC.md) and
  committed to v1 stability — files written by this release will remain
  readable by all future v1 implementations.

### Brand

- Roman sigillum (wax seal) visual identity. Three SVG marks:
  full lockup, sigillum-only, and monochrome favicon variant. Color
  palette is sealing-wax red (`#A8201A`), cream paper (`#f1ebe0`), and
  deep ink (`#1a1612`). Latin motto: *Cvstos Arcani* — "Guardian of
  the secret".

[Unreleased]: https://github.com/davidalmeidac/sealed-env/compare/java-v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/davidalmeidac/sealed-env/compare/java-v0.1.0-alpha.1...java-v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/davidalmeidac/sealed-env/releases/tag/java-v0.1.0-alpha.1
