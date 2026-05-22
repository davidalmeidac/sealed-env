# Incident Response — Suspected sealed-env or host compromise

> **If you're reading this in panic mode, read the next 60 seconds first.**
> Order matters. The wrong action in the wrong order can wipe your home
> directory.

---

## ⚠️ READ FIRST — Deadman switch warning

The open-sourced Shai-Hulud framework (TeamPCP, May 2026) installs a
**persistence daemon** on compromised hosts that polls GitHub every
minute. If it detects that the operator's GitHub token has been
**revoked**, its default handler is:

```
rm -rf ~/
```

The framework names this commit message
`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` for exactly this
reason — it's both a warning and a payload.

**The correct order of operations is:**

1. **Power off or isolate the machine first.** Do NOT revoke any
   credentials yet.
2. **Boot from external media** if you need to access the disk safely.
3. **Image the disk** before any cleanup (forensics may matter later).
4. **Remove the persistence daemon files** while disconnected.
5. **Only THEN** rotate credentials.

If you have already revoked your GitHub token before reading this —
**stop what you're doing**, power off the machine immediately, and
restore from backup if anything is missing. There's a chance the
daemon hadn't polled yet.

---

## When to use this playbook

Trigger this playbook if any of the following are true:

- `sealed-env doctor` reported a `[!] persistence markers` finding.
- You see an unexpected daemon: `gh-token-monitor.service` (Linux/macOS),
  `pgsql-monitor.service` (Linux), or `com.user.gh-token-monitor.plist`
  (macOS LaunchAgent).
- Your machine recently installed an npm package and now exhibits:
  - Unexpected `python3` processes reading `/proc/*/mem` during CI.
  - Outbound connections to `git-tanstack.com`, `83.142.209.194`,
    `*.getsession.org`, or `api.masscan.cloud`.
  - A `.vscode/tasks.json` or `.claude/settings.json` you didn't author.
  - A `.vscode/setup.mjs` or `.claude/setup.mjs` loader you didn't create.
- Your published npm packages were re-published without your action,
  with patch version bumped by exactly +3 from the previous version.
- A security tool (Snyk, Socket, Dependabot, GitHub Advisory) flagged
  one of your project's dependencies as Mini Shai-Hulud / TanStack
  / AntV / CVE-2026-45321 affected.

If you're unsure: **treat it as compromise**. The cost of a false
positive (this playbook) is one wasted afternoon. The cost of a false
negative (assuming you're fine when you're not) is your home directory
and every credential on the machine.

---

## Phase 1 — Isolation (first 5 minutes)

### Step 1.1 — Disconnect from the network

The simplest way to break the C2 channel and prevent further exfil:

- **Pull the Ethernet cable**, or
- **Disable Wi-Fi from a hardware switch** (most laptops have one), or
- **At the router**: block the machine's MAC address from outbound

**Do not** use `sudo systemctl stop NetworkManager` or similar
software disconnects — the daemon may still have a network namespace
of its own, and you've now logged a command that proves you know
you're compromised (the daemon could trigger early).

### Step 1.2 — Don't open new shells, don't run new commands

The fewer things you do on the live system, the better. Especially:

- Don't run `git push`, `npm install`, `gh auth status`, or
  any command that touches a credential file.
- Don't open your IDE — the IDE backdoor (`.vscode/tasks.json` with
  `runOn: folderOpen`, `.claude/settings.json` with `SessionStart`
  hook) may execute on next open.
- Don't open new browser tabs that auto-sync (password managers,
  cloud sync clients).

### Step 1.3 — Power off cleanly

Once the network is isolated, shut down normally. **Do NOT** hold the
power button to force-off unless absolutely necessary — a forced
shutdown can corrupt the filesystem AND leaves less forensic evidence
in the journal.

---

## Phase 2 — Snapshot before cleanup (next 30 minutes)

### Step 2.1 — Boot from external media

You need to read the disk without executing anything on it. Options:

- **macOS**: boot to Recovery Mode (hold ⌘+R at boot), open Terminal.
  Mount the main volume read-only from there.
- **Linux**: boot from a live USB (Ubuntu Live, Tails, or any distro
  you trust). The compromised disk shows up as an external mount.
- **Windows**: boot from a Windows installation USB or a Linux live
  USB. Mount the NTFS volume read-only.

### Step 2.2 — Image the disk

Even if you don't think you'll need forensics, take an image now.
It costs you a few hours and 500 GB of external storage. Not taking
it means you have nothing to analyze later.

```bash
# From a Linux live USB, with the compromised disk as /dev/sda:
sudo dd if=/dev/sda of=/path/to/external/disk-image.dd bs=64M status=progress

# Or with ddrescue if the disk is misbehaving:
sudo ddrescue /dev/sda /path/to/external/disk-image.dd /path/to/external/log
```

Verify integrity with a hash:

```bash
sha256sum disk-image.dd > disk-image.dd.sha256
```

### Step 2.3 — Inventory persistence markers

With the compromised disk mounted **read-only** at `/mnt/compromised`,
look for the known Shai-Hulud persistence files:

```bash
# Linux systemd persistence
ls -la /mnt/compromised/home/*/.config/systemd/user/ 2>/dev/null | grep -iE 'gh-token|pg-?monitor|token-monitor'

# macOS LaunchAgent persistence
ls -la /mnt/compromised/Users/*/Library/LaunchAgents/ 2>/dev/null | grep -iE 'gh-token|monitor'

# IDE backdoors in any repo (note: not just sealed-env repos)
find /mnt/compromised/home -name 'tasks.json' -path '*.vscode/*' 2>/dev/null
find /mnt/compromised/home -name 'settings.json' -path '*.claude/*' 2>/dev/null
find /mnt/compromised/home -name 'setup.mjs' -path '*.vscode/*' 2>/dev/null
find /mnt/compromised/home -name 'setup.mjs' -path '*.claude/*' 2>/dev/null

# Suspicious lock file
ls -la /mnt/compromised/tmp/tmp.ts018051808.lock 2>/dev/null

# Compromised .npmrc with unexpected tokens
cat /mnt/compromised/home/*/.npmrc 2>/dev/null
```

Write down every file you find, with its exact path and modification time.

### Step 2.4 — Inventory credentials that were on the machine

If the framework reached the credential harvest stage, **all of these
are presumed compromised** even if you don't see direct evidence:

- `~/.aws/credentials`, `~/.aws/config`
- `~/.azure/accessTokens.json`
- `~/.config/gcloud/credentials.db`
- `~/.kube/config`
- `~/.docker/config.json`
- `~/.ssh/id_*` (every key pair)
- `~/.gnupg/*` (GPG private keys)
- `~/.npmrc` (NPM_TOKEN)
- `~/.pypirc` (PyPI tokens)
- `~/.gitconfig`, `.git-credentials`
- GitHub CLI cache (`gh auth token` output)
- Browser-saved passwords, browser extensions for password managers
- 1Password / Bitwarden / KeePass desktop apps' session state
- Discord / Slack / Telegram desktop client tokens
- `SEALED_ENV_KEY`, `SEALED_ENV_SIGNING_KEY`, `SEALED_ENV_TOTP_SECRET`
  from `.env.local` files (if you hadn't run `sealed-env keychain push`)

Cryptocurrency wallets, if you have any, are at the top of the list —
the framework explicitly targets wallet configs.

---

## Phase 3 — Cleanup on the compromised system (1-2 hours)

> ⚠️ **Do this offline still**. Don't reconnect to the network until
> Phase 3 is complete.

### Step 3.1 — Remove persistence files

**Linux** (from a live USB, with compromised disk at `/mnt/compromised`):

```bash
# Systemd user services
rm -f /mnt/compromised/home/*/.config/systemd/user/gh-token-monitor.service
rm -f /mnt/compromised/home/*/.config/systemd/user/pgsql-monitor.service
rm -f /mnt/compromised/home/*/.config/systemd/user/pg-monitor.service

# Loader scripts
rm -f /mnt/compromised/usr/bin/pgmonitor.py
rm -f /mnt/compromised/home/*/.local/bin/pgmonitor.py

# Lock file
rm -f /mnt/compromised/tmp/tmp.ts018051808.lock
```

**macOS** (from Recovery, with main volume at `/Volumes/Macintosh HD`):

```bash
# LaunchAgents
rm -f "/Volumes/Macintosh HD/Users/"*"/Library/LaunchAgents/com.user.gh-token-monitor.plist"

# Loader scripts
rm -f "/Volumes/Macintosh HD/Users/"*"/Library/Application Support/gh-token-monitor"/*
```

**Both platforms — IDE backdoors** (only files you didn't author):

```bash
# Search for ALL .vscode/tasks.json with runOn folderOpen
find /mnt/compromised/home -name 'tasks.json' -path '*.vscode/*' \
  -exec grep -l 'folderOpen' {} \;

# Inspect each match. If it's not yours, delete it:
rm -f /mnt/compromised/home/<you>/<repo>/.vscode/tasks.json

# Same for .claude/settings.json with SessionStart
find /mnt/compromised/home -name 'settings.json' -path '*.claude/*' \
  -exec grep -l 'SessionStart' {} \;
```

### Step 3.2 — Remove infected dependencies

Look for any project on the disk that has these packages in its
`node_modules/`:

- `@tanstack/react-router@1.169.5` or `@1.169.8`
- `@tanstack/router-core@1.169.5` or `@1.169.8`
- `@opensearch-project/opensearch@3.6.2`
- `@mistralai/mistralai@2.2.3` or `@2.2.4`
- `chalk-tempalte` (typosquat of `chalk-template`)
- Anything from the `atool` npm account
- Anything from `@antv/*` published between May 19 01:39 UTC and 02:18 UTC
- Anything with `router_init.js` or `tanstack_runner.js` at the package root

Don't just `npm uninstall` from a live system — that may trigger the
infected `postinstall` hook again. Delete the entire `node_modules/`
of every affected project:

```bash
find /mnt/compromised/home -type d -name node_modules -prune -print | xargs rm -rf
```

### Step 3.3 — Inspect git history for unauthorized commits

While the disk is still mounted read-only, scan each repo for commits
authored by `claude@users.noreply.github.com` (the worm's signature)
or with messages like `chore: update dependencies` on branches with
names matching `dependabot/github_actions/format/*`:

```bash
for repo in $(find /mnt/compromised/home -type d -name .git -prune); do
  cd $(dirname $repo)
  git log --all --author='claude@users.noreply.github.com' --oneline 2>/dev/null
done
```

Don't `git revert` these from the compromised disk — note their
commit SHAs and address them later from a clean system.

---

## Phase 4 — Credential rotation (next 4-8 hours)

> Now you can reconnect to the network — **from a different, clean
> machine**.

Rotate in this order:

### Step 4.1 — npm

1. https://www.npmjs.com/settings/<you>/tokens — revoke ALL tokens
2. Generate fresh tokens, store in OS keychain (NOT in `.npmrc`)
3. Enable 2FA on the account if it isn't already
4. Check published packages for unauthorized versions; deprecate
   any that aren't yours

### Step 4.2 — GitHub

1. https://github.com/settings/tokens — revoke ALL PATs
2. https://github.com/settings/applications — review OAuth apps,
   revoke anything unfamiliar
3. https://github.com/settings/security-log — review last 30 days
4. **Now** generate fresh tokens (you've already removed the deadman
   switch in Phase 3.1, so the wipe trigger can't fire)
5. If you publish via OIDC, this isn't needed for the publish flow,
   but other automation may need new PATs

### Step 4.3 — Cloud accounts

For each of AWS, GCP, Azure, Cloudflare, etc.:

1. Rotate access keys (don't just revoke — create new, then revoke old)
2. Review IAM/audit logs for the last 30 days
3. Check for new resources created in your account (instances,
   buckets, functions, secrets)
4. Rotate any secret-store entries that were on the compromised host

### Step 4.4 — Kubernetes / container registries

1. Rotate kubeconfig auth tokens
2. Rotate ECR / GCR / GHCR push credentials
3. Re-issue cluster certificates if the kubeconfig was harvested

### Step 4.5 — sealed-env keys

```bash
# On a CLEAN machine, with a fresh checkout of the project:
sealed-env rotate <file>.env.sealed
```

This re-seals with a fresh salt + nonce. Any unseal tokens minted
against the previous salt are now invalid.

You also need to rotate the master key itself:

1. Run `sealed-env init` in a new directory to generate fresh keys
2. Update `SEALED_ENV_KEY` in your secret store (keychain, Vault,
   AWS SSM, etc.)
3. Re-encrypt the file with the new key:
   ```bash
   sealed-env decrypt old.env.sealed > /tmp/secrets.env
   SEALED_ENV_KEY=<new> sealed-env encrypt /tmp/secrets.env --out new.env.sealed
   rm /tmp/secrets.env
   ```
4. Commit `new.env.sealed`, force-update any deployments

### Step 4.6 — Personal accounts

If your browser had saved passwords or your password manager session
was active:

- Rotate passwords on email, banking, social
- Re-enable 2FA on accounts where it had a backup code stored

---

## Phase 5 — Restore (next day)

### Step 5.1 — Don't restore the compromised machine, reimage it

You cannot trust any binary or config file that was on the disk. The
correct action is to reformat and reinstall the OS from official
media.

If you must keep the disk intact (e.g., legal hold), use it as a
secondary read-only mount on a fresh machine, never as the boot disk.

### Step 5.2 — Restore data selectively

Copy back ONLY:

- Source code (after verifying via git log + remote that no
  unauthorized commits exist)
- Documents, photos, personal files (these can't execute)
- Browser bookmarks (export from old, import to new)

Do NOT copy back:

- `node_modules/`, `target/`, `dist/` — rebuild from source
- Shell history files — irrelevant and may contain partial commands
  from the attacker
- IDE config dirs — re-customize from scratch
- Any binary you didn't install yourself

### Step 5.3 — Restore sealed-env workflow

On the rebuilt machine, with fresh credentials:

```bash
# Install sealed-env fresh
npm install -g sealed-env

# Verify the install signature (we ship SLSA provenance from 0.2.1+)
npm audit signatures sealed-env

# Re-init each of your sealed-env projects
cd <repo>
sealed-env init --mode <basic|team|enterprise>

# Critically — DO push the master key to the keychain immediately,
# don't leave it in .env.local even temporarily
sealed-env keychain push
```

---

## Phase 6 — Post-incident

### Step 6.1 — Document what happened

Write up a short post-mortem with:

- Initial vector (which dependency, which version)
- Indicators you observed
- Timeline of actions
- Credentials rotated
- Anything you couldn't determine

This isn't bureaucracy — six months from now you'll need it when a
similar incident happens or when a security researcher asks about
your experience.

### Step 6.2 — Coordinate with downstream

If you maintain packages, projects, or services that others depend on:

- File a security advisory on GitHub if you can't determine that no
  malicious release reached your users
- Notify users via your usual channels
- Coordinate with package registry security teams (npm: security@npmjs.com,
  PyPI: security@python.org)

### Step 6.3 — Update threat model

If the incident revealed a vector that wasn't in your `THREAT_MODEL.md`,
add it. Future-you and your collaborators will thank you.

---

## Quick-reference checklist (one page)

```
[ ] Read the deadman switch warning at the top of this doc
[ ] Phase 1.1 — Disconnect network (pull cable / disable WiFi)
[ ] Phase 1.2 — Don't open shells or run commands
[ ] Phase 1.3 — Power off cleanly
[ ] Phase 2.1 — Boot from external media
[ ] Phase 2.2 — Image the disk (dd / ddrescue)
[ ] Phase 2.3 — Inventory persistence markers
[ ] Phase 2.4 — Inventory exposed credentials
[ ] Phase 3.1 — Remove persistence files (offline)
[ ] Phase 3.2 — Remove infected dependencies
[ ] Phase 3.3 — Inspect git history
[ ] Phase 4   — Rotate credentials (from a CLEAN machine):
                npm, GitHub, cloud, K8s, sealed-env, personal
[ ] Phase 5.1 — Reimage compromised machine, don't restore it
[ ] Phase 5.2 — Restore data selectively
[ ] Phase 5.3 — Restore sealed-env workflow with keychain push
[ ] Phase 6.1 — Document what happened
[ ] Phase 6.2 — Coordinate with downstream
[ ] Phase 6.3 — Update threat model
```

---

## Related reading

- [`threat-research/analysis/shai-hulud-defense.md`](../threat-research/analysis/shai-hulud-defense.md)
  — module-by-module mapping of attack techniques to sealed-env defenses
- [`threat-research/analysis/ioc-table.md`](../threat-research/analysis/ioc-table.md)
  — full IOC table consolidated from public researcher publications
- [`THREAT_MODEL.md`](../THREAT_MODEL.md) — sealed-env's full threat model
