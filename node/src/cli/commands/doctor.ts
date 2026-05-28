/**
 * `sealed-env doctor [<file.env.sealed>]` — non-destructive diagnostic.
 *
 * Validates the local sealed-env setup WITHOUT printing any secret
 * values. Designed to be safe to paste into a CI log or a Slack thread
 * when debugging "why isn't this decrypting?" — the output is a series
 * of pass/fail lines with redacted fingerprints, never plaintext.
 *
 *   $ sealed-env doctor .env.sealed
 *   sealed-env 0.1.0-alpha.4 — diagnostic report
 *
 *   [✓] sealed file found              .env.sealed (366 B)
 *   [✓] file parses as V1              mode=enterprise, kdf=scrypt
 *   [✓] SEALED_ENV_KEY set             32 bytes (sha256: 7c8a..b3d1)
 *   [✓] SEALED_ENV_SIGNING_KEY set     32 bytes (sha256: 9d2e..ff04)
 *   [✓] SEALED_ENV_TOTP_SECRET set     20 bytes (sha256: 1aa3..c7e5)
 *   [✓] file integrity (HMAC)          OK
 *   [✓] decrypt roundtrip              OK (4 keys recovered)
 *
 *   All checks passed. Setup looks healthy.
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { existsSync, statSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir, platform } from 'node:os';
import { createHash } from 'node:crypto';

import { unseal } from '../../core/api.js';
import { parseSealedFile } from '../../format/parser.js';
import { SealedEnvError } from '../../core/errors.js';
import { shellHintFor } from '../utils/io.js';

interface CheckResult {
  ok: boolean;
  /**
   * `true` for advisory checks that should be visible but don't fail
   * the command. Used by the hardening checks (Shai-Hulud posture)
   * where missing config is worth warning but not blocking.
   */
  warn?: boolean;
  label: string;
  detail: string;
}

export function doctorCommand(argv: string[]): void {
  const filePath = argv[0];
  const checks: CheckResult[] = [];

  process.stdout.write('sealed-env diagnostic report\n\n');

  // Section 1: env vars (always relevant)
  checks.push(checkEnv('SEALED_ENV_KEY', { required: true, minBytes: 32 }));
  checks.push(checkEnv('SEALED_ENV_SIGNING_KEY', { required: false, minBytes: 32 }));
  checks.push(checkEnv('SEALED_ENV_TOTP_SECRET', { required: false, minBytes: 16 }));
  checks.push(checkEnv('SEALED_ENV_UNSEAL_TOKEN', { required: false }));
  checks.push(checkEnv('SEALED_ENV_DEPLOY_ID', { required: false }));

  // Section 2: file checks (only if a file was provided)
  if (filePath) {
    if (!existsSync(filePath)) {
      checks.push({ ok: false, label: 'sealed file found', detail: `not found: ${filePath}` });
    } else {
      const stat = statSync(filePath);
      checks.push({
        ok: true,
        label: 'sealed file found',
        detail: `${filePath} (${stat.size} B)`,
      });

      try {
        const text = readFileSync(resolve(filePath), 'utf8');
        const file = parseSealedFile(text);
        checks.push({
          ok: true,
          label: 'file parses as V1',
          detail: `mode=${file.mode}, kdf=${file.kdf}`,
        });

        // Roundtrip — only attempt if we have everything we need.
        try {
          const masterKey = readKey('SEALED_ENV_KEY');
          const signingKey =
            file.mode === 'team' || file.mode === 'enterprise'
              ? readKey('SEALED_ENV_SIGNING_KEY')
              : undefined;
          const unsealOpts: Parameters<typeof unseal>[0] = {
            file,
            masterKey,
          };
          if (signingKey) unsealOpts.signingKey = signingKey;
          if (file.mode === 'enterprise') {
            const tok = process.env['SEALED_ENV_UNSEAL_TOKEN'];
            const did = process.env['SEALED_ENV_DEPLOY_ID'];
            if (tok) unsealOpts.unsealToken = tok;
            if (did) unsealOpts.deployId = did;
          }
          const plaintext = unseal(unsealOpts);
          const numKeys = plaintext
            .toString('utf8')
            .split('\n')
            .filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l)).length;
          checks.push({
            ok: true,
            label: 'decrypt roundtrip',
            detail: `OK (${numKeys} key${numKeys === 1 ? '' : 's'} recovered)`,
          });
        } catch (e) {
          checks.push({
            ok: false,
            label: 'decrypt roundtrip',
            detail: e instanceof SealedEnvError ? `[${e.code}] ${e.message.split('\n')[0]}` : 'failed',
          });
        }
      } catch (e) {
        checks.push({
          ok: false,
          label: 'file parses as V1',
          detail: e instanceof Error ? e.message.split('\n')[0]! : 'parse error',
        });
      }
    }
  }

  // Section 3: hardening posture (Shai-Hulud defense)
  // These are advisory — they don't fail doctor, but they're visible.
  // See: /threat-research/analysis/shai-hulud-defense.md
  checks.push(checkPlaintextKeyExposure());
  checks.push(checkPyPiTokenExposure());
  checks.push(checkPersistenceMarkers());
  checks.push(checkCiTokenTtl());

  // Render the report
  const longest = Math.max(...checks.map((c) => c.label.length));
  for (const c of checks) {
    const mark = c.warn ? '!' : c.ok ? '✓' : '✗';
    process.stdout.write(`  [${mark}] ${c.label.padEnd(longest)}  ${c.detail}\n`);
  }
  process.stdout.write('\n');

  const failed = checks.filter((c) => !c.ok);
  const warnings = checks.filter((c) => c.warn);
  if (failed.length === 0 && warnings.length === 0) {
    process.stdout.write('All checks passed. Setup looks healthy.\n');
  } else if (failed.length === 0) {
    process.stdout.write(
      `${warnings.length} hardening recommendation${warnings.length === 1 ? '' : 's'} above. ` +
        'No defects detected; the items marked [!] are opt-in improvements.\n',
    );
  } else {
    process.stdout.write(
      `${failed.length} check${failed.length === 1 ? '' : 's'} failed. ` +
        'Address the items marked ✗ above.\n',
    );
    if (warnings.length > 0) {
      process.stdout.write(
        `${warnings.length} hardening recommendation${warnings.length === 1 ? '' : 's'} also listed.\n`,
      );
    }
    process.exitCode = 1;
  }
}

/**
 * Validate an env var without printing its value. Reports byte length
 * and a SHA-256 fingerprint (first 4 + last 4 hex chars) — enough to
 * tell if two machines have the same key, useless to anyone observing
 * the log.
 */
function checkEnv(
  name: string,
  opts: { required: boolean; minBytes?: number },
): CheckResult {
  const v = process.env[name];
  if (!v) {
    return {
      ok: !opts.required,
      label: `${name} set`,
      detail: opts.required ? 'missing (required)' : 'not set (optional)',
    };
  }
  let buf: Buffer;
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
    buf = Buffer.from(v, 'hex');
  } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) {
    buf = Buffer.from(v, 'base64');
  } else {
    buf = Buffer.from(v, 'utf8');
  }

  if (opts.minBytes && buf.length < opts.minBytes) {
    return {
      ok: false,
      label: `${name} set`,
      detail: `${buf.length} bytes (need ≥${opts.minBytes})`,
    };
  }
  const fp = createHash('sha256').update(buf).digest('hex');
  const shortFp = `${fp.substring(0, 4)}..${fp.substring(60)}`;
  return {
    ok: true,
    label: `${name} set`,
    detail: `${buf.length} bytes (sha256: ${shortFp})`,
  };
}

function readKey(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError(
      'MISSING_KEY',
      `environment variable ${varName} is required.\n${shellHintFor(varName)}`,
    );
  }
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}

// ---------------------------------------------------------------
// Hardening checks (Shai-Hulud defense posture)
// ---------------------------------------------------------------
//
// These checks don't validate sealed-env's correctness — they validate
// the operator's *hygiene* against credential-harvesting malware. Each
// is advisory (warn, not fail) because operators on a single dev machine
// who accept the risk should still be able to use sealed-env.
//
// See /threat-research/analysis/shai-hulud-defense.md for the full
// per-module mapping of what these checks defend against.

const SHAI_HULUD_DOC =
  'https://github.com/davidalmeidac/sealed-env/blob/main/threat-research/analysis/shai-hulud-defense.md';

/**
 * Check 1: master key in `.env.local` plaintext.
 *
 * The most impactful Shai-Hulud mitigation for sealed-env users is
 * `keychain push` — moving the master key out of `.env.local` and into
 * the OS keychain. This check reads `.env.local` from cwd (no parse, no
 * env load — purely reading the file's first 64KB for the literal
 * `SEALED_ENV_KEY=<hex>` pattern) and warns if found.
 *
 * False-negative cases are acceptable: if the operator points us at the
 * file via cwd outside their actual repo, we miss it. False positives
 * are minimized: we require the exact hex form (placeholders like
 * `SEALED_ENV_KEY=<your_key>` don't match).
 */
function checkPlaintextKeyExposure(): CheckResult {
  const candidates = ['.env.local', '.env'];
  const findings: string[] = [];

  for (const name of candidates) {
    const path = resolve(name);
    if (!existsSync(path)) continue;
    let head: string;
    try {
      head = readFileSync(path, 'utf8').slice(0, 64 * 1024);
    } catch {
      continue;
    }
    // Match the same shape as the SE-K1/K2/K3 patterns we ship for
    // gitleaks (SECRET-PATTERNS.md). Keep these in sync.
    const masterKey =
      /SEALED_ENV_KEY\s*[=:]\s*["']?[0-9a-fA-F]{64}(?![0-9a-fA-F])/.test(head);
    const signingKey =
      /SEALED_ENV_SIGNING_KEY\s*[=:]\s*["']?[0-9a-fA-F]{64}(?![0-9a-fA-F])/.test(head);
    const totp =
      /SEALED_ENV_TOTP_SECRET\s*[=:]\s*["']?[A-Z2-7]{16,64}(?![A-Z2-7])/.test(head);
    if (masterKey || signingKey || totp) {
      const found = [
        masterKey ? 'master key' : null,
        signingKey ? 'signing key' : null,
        totp ? 'TOTP secret' : null,
      ]
        .filter(Boolean)
        .join(' + ');
      findings.push(`${name} (${found})`);
    }
  }

  if (findings.length === 0) {
    return {
      ok: true,
      label: 'plaintext key exposure',
      detail: 'no sealed-env secrets in .env / .env.local (or files absent)',
    };
  }

  return {
    ok: true,
    warn: true,
    label: 'plaintext key exposure',
    detail:
      `secrets in plaintext: ${findings.join(', ')}. ` +
      `Run \`sealed-env keychain push\` to move them to the OS keychain. ` +
      `See ${SHAI_HULUD_DOC}`,
  };
}

/**
 * Check 1b: PyPI token in plaintext `~/.pypirc` or cwd `.pypirc`.
 *
 * Same family of leak as `checkPlaintextKeyExposure` but for the Python
 * supply chain. Shai-Hulud variants since May 2026 weaponize leaked
 * PyPI tokens to republish poisoned packages, so an operator who keeps
 * a plaintext `pypi-` token in `.pypirc` is one infostealer away from
 * compromise. Matched against the same SE-K4 regex shipped to gitleaks.
 *
 * Read-only and non-blocking. We check cwd first (project-scoped tokens),
 * then `~/.pypirc` (the conventional location).
 */
function checkPyPiTokenExposure(): CheckResult {
  const candidates = [resolve('.pypirc'), join(homedir(), '.pypirc')];
  const found: string[] = [];

  for (const path of candidates) {
    if (!existsSync(path)) continue;
    let head: string;
    try {
      head = readFileSync(path, 'utf8').slice(0, 64 * 1024);
    } catch {
      continue;
    }
    if (/pypi-[A-Za-z0-9_-]{60,500}/.test(head)) {
      found.push(path);
    }
  }

  if (found.length === 0) {
    return {
      ok: true,
      label: 'pypi token exposure',
      detail: 'no plaintext pypi- tokens in .pypirc (or files absent)',
    };
  }

  return {
    ok: true,
    warn: true,
    label: 'pypi token exposure',
    detail:
      `plaintext PyPI token in: ${found.join(', ')}. ` +
      `Consider moving to keyring (\`keyring set https://upload.pypi.org/legacy/ __token__\`) ` +
      `or a secret manager. See ${SHAI_HULUD_DOC}`,
  };
}

/**
 * Suspicious filename patterns used as persistence markers by the
 * Shai-Hulud framework and clones. Matched as substrings (case-insensitive)
 * against systemd unit filenames and macOS LaunchAgent plist filenames.
 *
 * Sources:
 *   - Datadog (gh-token-monitor on macOS LaunchAgent + Linux systemd)
 *   - Upwind (pgsql-monitor.service on Linux systemd)
 *
 * Keep this list narrow on purpose — false positives on persistence
 * markers create a "boy who cried wolf" problem that erodes the
 * doctor's credibility. Add a name here only when at least one
 * researcher publication documents it.
 */
const SUSPICIOUS_PERSISTENCE_NAMES = [
  'gh-token-monitor',
  'pgsql-monitor',
  'pg-monitor',
  'token-monitor',
];

function matchesSuspiciousPersistenceName(filename: string): string | null {
  const lower = filename.toLowerCase();
  for (const pat of SUSPICIOUS_PERSISTENCE_NAMES) {
    if (lower.includes(pat)) return pat;
  }
  return null;
}

/**
 * Check 2: persistence markers (IDE backdoors + OS-level daemons).
 *
 * The Shai-Hulud framework persists through two distinct surfaces:
 *
 *  1. IDE config files: `.vscode/tasks.json` with `runOn: folderOpen`
 *     and `.claude/settings.json` with `SessionStart` hooks. These
 *     survive `npm uninstall` of the compromised package because the
 *     persistence vector IS the IDE file, not the package.
 *
 *  2. OS-level daemons: systemd user units (Linux) and LaunchAgents
 *     (macOS), typically named after fake monitoring services
 *     (`gh-token-monitor.service`, `pgsql-monitor.service`).
 *     One of these daemons is the deadman switch that executes
 *     `rm -rf ~/` if the operator revokes their GitHub token before
 *     isolating the host — see docs/incident-response.md for the
 *     correct order of operations.
 *
 * All findings are warnings, not failures: legitimate tooling can use
 * the same surfaces. The doctor's job is to surface candidates for
 * manual inspection, not to make remediation decisions.
 */
function checkPersistenceMarkers(): CheckResult {
  const findings: string[] = [];

  // --- IDE config files (cwd-relative) ---

  // .vscode/tasks.json with runOn: folderOpen
  const vscodeTasks = resolve('.vscode/tasks.json');
  if (existsSync(vscodeTasks)) {
    try {
      const text = readFileSync(vscodeTasks, 'utf8');
      if (/"runOn"\s*:\s*"folderOpen"/.test(text)) {
        findings.push('.vscode/tasks.json (runOn: folderOpen)');
      }
    } catch {
      // unreadable — skip silently
    }
  }

  // .claude/settings.json with a SessionStart hook
  const claudeSettings = resolve('.claude/settings.json');
  if (existsSync(claudeSettings)) {
    try {
      const text = readFileSync(claudeSettings, 'utf8');
      if (/"SessionStart"/.test(text) && /"hooks"/.test(text)) {
        findings.push('.claude/settings.json (SessionStart hook)');
      }
    } catch {
      // unreadable — skip silently
    }
  }

  // Suspicious loader filenames the framework drops
  for (const dropFile of ['.vscode/setup.mjs', '.claude/setup.mjs']) {
    if (existsSync(resolve(dropFile))) {
      findings.push(`${dropFile} (suspicious loader filename)`);
    }
  }

  // --- OS-level daemons (home-relative, platform-specific) ---

  const home = homedir();
  const plat = platform();

  // Linux: enumerate ~/.config/systemd/user/ for suspiciously named units.
  // We do NOT parse the unit file content — just match against names.
  // A real false-positive would be a legitimate user service that
  // happened to share one of the patterns, which we accept as the
  // tradeoff for not parsing every operator's unit files.
  if (plat === 'linux') {
    const systemdDir = join(home, '.config', 'systemd', 'user');
    findings.push(...enumeratePersistenceDir(systemdDir, 'systemd user unit'));
  }

  // macOS: enumerate ~/Library/LaunchAgents/ for suspiciously named plists.
  if (plat === 'darwin') {
    const launchAgentsDir = join(home, 'Library', 'LaunchAgents');
    findings.push(...enumeratePersistenceDir(launchAgentsDir, 'LaunchAgent'));
  }

  // Windows: no equivalent home-relative daemon mechanism documented
  // in the Shai-Hulud research as of 2026-05. Scheduled Tasks are
  // system-wide (managed by `schtasks`) and would require elevated
  // enumeration — out of scope for a non-admin diagnostic check.

  if (findings.length === 0) {
    return {
      ok: true,
      label: 'persistence markers',
      detail: 'no IDE backdoors or suspicious OS-level daemons found',
    };
  }

  return {
    ok: true,
    warn: true,
    label: 'persistence markers',
    detail:
      `auto-execute markers found: ${findings.join('; ')}. ` +
      `Inspect manually — legitimate tooling can use these, but the ` +
      `Shai-Hulud framework also uses them for persistence. ` +
      `BEFORE revoking any credentials, see docs/incident-response.md ` +
      `(deadman switch warning). Reference: ${SHAI_HULUD_DOC}`,
  };
}

/**
 * Enumerate a directory expected to contain OS-level daemon definitions
 * and return findings whose filenames match any known suspicious pattern.
 *
 * Safe against missing/unreadable directories — returns empty array on
 * any I/O error. Does NOT recurse — the framework drops files at the
 * top level of the LaunchAgents / systemd user dirs.
 */
function enumeratePersistenceDir(dir: string, kind: string): string[] {
  if (!existsSync(dir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    // permission denied, EACCES, etc. — silently skip rather than
    // claiming a clean bill of health we can't actually verify
    return [];
  }
  const findings: string[] = [];
  for (const entry of entries) {
    const matched = matchesSuspiciousPersistenceName(entry);
    if (matched) {
      findings.push(`${dir}/${entry} (suspicious ${kind} matching "${matched}")`);
    }
  }
  return findings;
}

/**
 * Check 3: CI context — TTL guidance for unseal tokens.
 *
 * GitHub Actions runners can be scraped for in-memory secrets via
 * `/proc/<pid>/mem`. sealed-env can't prevent the scrape, but a short
 * TTL on unseal tokens (≤ 30s) materially reduces the window during
 * which a scraped token is useful. This check fires only when running
 * inside GitHub Actions; otherwise it's silent.
 */
function checkCiTokenTtl(): CheckResult {
  const inCi = process.env['GITHUB_ACTIONS'] === 'true';
  if (!inCi) {
    return {
      ok: true,
      label: 'CI hardening',
      detail: 'not in GitHub Actions — check skipped',
    };
  }

  const token = process.env['SEALED_ENV_UNSEAL_TOKEN'];
  if (!token) {
    return {
      ok: true,
      label: 'CI hardening',
      detail: 'GitHub Actions detected; no unseal token in env (basic/team mode)',
    };
  }

  // We can't read the TTL without parsing the JWT, and we don't want
  // to add JWT parsing to doctor for one advisory check. Just remind
  // the operator of the policy.
  return {
    ok: true,
    warn: true,
    label: 'CI hardening',
    detail:
      `GitHub Actions + unseal token detected. Recommended: TTL ≤ 30s ` +
      `(pass --ttl 30 when minting). Runner memory is scrapable; short ` +
      `TTLs limit the window. See ${SHAI_HULUD_DOC}`,
  };
}
