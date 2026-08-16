/**
 * Persistence-marker detection and remediation.
 *
 * The Shai-Hulud framework persists through two distinct surfaces:
 *
 *  1. IDE config files: `.vscode/tasks.json` with `runOn: folderOpen` and
 *     `.claude/settings.json` with `SessionStart` hooks. These survive
 *     `npm uninstall` of the compromised package because the persistence
 *     vector IS the IDE file, not the package.
 *
 *  2. OS-level daemons: systemd user units (Linux) and LaunchAgents
 *     (macOS), typically named after fake monitoring services
 *     (`gh-token-monitor.service`, `pgsql-monitor.service`).
 *
 * Detection lives here rather than in `doctor.ts` so it can be unit
 * tested against a real temp filesystem with injected roots — the
 * remediation path deletes files, and that deserves tests that exercise
 * actual disk state rather than mocks.
 *
 * ## The remediation safety rule
 *
 * Findings split into two classes, and the split is the whole design:
 *
 *  - **Remediable**: files whose mere existence under that exact name is
 *    the indicator (`.vscode/setup.mjs`, a systemd unit named
 *    `gh-token-monitor.service`). Nothing legitimate owns these names, so
 *    quarantining them destroys no operator work.
 *
 *  - **Manual-only**: config files that legitimate tooling also owns
 *    (`.vscode/tasks.json`, `.claude/settings.json`). A malicious ENTRY
 *    inside them is the indicator, not the file. Deleting the file to
 *    remove one entry would throw away the operator's real configuration,
 *    so `--remediate` reports these and leaves them untouched.
 *
 * See P1.4 in threat-research/analysis/improvement-roadmap.md.
 */

import {
  existsSync,
  readFileSync,
  readdirSync,
  mkdirSync,
  copyFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, basename } from 'node:path';

/** Directory (cwd-relative) where quarantined copies are parked. */
export const QUARANTINE_DIR = '.sealed-env-quarantine';

/**
 * Suspicious filename patterns used as persistence markers by the
 * Shai-Hulud framework and clones. Matched as case-insensitive substrings
 * against systemd unit and LaunchAgent plist filenames.
 *
 * Sources:
 *   - Datadog (gh-token-monitor on macOS LaunchAgent + Linux systemd)
 *   - Upwind (pgsql-monitor.service on Linux systemd)
 *
 * Keep this list narrow on purpose — false positives on persistence
 * markers create a "boy who cried wolf" problem that erodes the doctor's
 * credibility, and under `--remediate` a false positive is no longer just
 * noise: it deletes a file. Add a name here only when at least one
 * researcher publication documents it.
 */
export const SUSPICIOUS_PERSISTENCE_NAMES = [
  'gh-token-monitor',
  'pgsql-monitor',
  'pg-monitor',
  'token-monitor',
];

/**
 * Loader filenames the framework drops next to the IDE config it hijacks.
 * These are dropped files, not config: nothing legitimate creates a file
 * at exactly these paths, which is what makes them safe to quarantine.
 */
const DROPPED_LOADER_FILES = [
  ['.vscode', 'setup.mjs'],
  ['.claude', 'setup.mjs'],
];

export interface PersistenceRoots {
  /** Project directory to inspect for IDE surfaces. */
  cwd: string;
  /** Home directory to inspect for OS-level daemons. */
  home: string;
  /** `process.platform` value; decides which daemon dirs are consulted. */
  platform: string;
}

export interface PersistenceFinding {
  /** Absolute path of the offending file. */
  path: string;
  /** Short human label for the diagnostic report. */
  label: string;
  /** Whether `--remediate` is allowed to quarantine this file. */
  remediable: boolean;
  /** Why it matched, or why it must be handled by hand. */
  reason: string;
}

export interface QuarantinedFile {
  /** Original absolute path, now removed from disk. */
  path: string;
  /** Absolute path of the preserved copy. */
  quarantinedAs: string;
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface RemediationResult {
  quarantined: QuarantinedFile[];
  skipped: SkippedFile[];
  /** Absolute quarantine directory, or `null` if nothing was quarantined. */
  quarantineDir: string | null;
}

function matchesSuspiciousPersistenceName(filename: string): string | null {
  const lower = filename.toLowerCase();
  for (const pat of SUSPICIOUS_PERSISTENCE_NAMES) {
    if (lower.includes(pat)) return pat;
  }
  return null;
}

/** Read a file's first 64KB, or `null` if it can't be read. */
function readHead(path: string): string | null {
  try {
    return readFileSync(path, 'utf8').slice(0, 64 * 1024);
  } catch {
    return null;
  }
}

/**
 * Enumerate a directory expected to contain OS-level daemon definitions
 * and return findings whose filenames match a known suspicious pattern.
 *
 * Safe against missing/unreadable directories — returns an empty array on
 * any I/O error rather than claiming a clean bill of health we can't
 * actually verify. Does NOT recurse: the framework drops files at the top
 * level of the LaunchAgents / systemd user dirs.
 */
function enumeratePersistenceDir(dir: string, kind: string): PersistenceFinding[] {
  if (!existsSync(dir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const findings: PersistenceFinding[] = [];
  for (const entry of entries) {
    const matched = matchesSuspiciousPersistenceName(entry);
    if (matched === null) continue;
    findings.push({
      path: join(dir, entry),
      label: `${kind}: ${entry}`,
      remediable: true,
      reason: `${kind} filename matches the documented marker "${matched}"`,
    });
  }
  return findings;
}

/**
 * Collect every persistence marker visible from the given roots.
 *
 * Read-only. Roots are injected rather than read from `process` so the
 * remediation tests can build a throwaway filesystem and simulate any
 * platform.
 */
export function collectPersistenceFindings(roots: PersistenceRoots): PersistenceFinding[] {
  const findings: PersistenceFinding[] = [];

  // --- IDE surfaces (project-relative) ---

  const vscodeTasks = join(roots.cwd, '.vscode', 'tasks.json');
  if (existsSync(vscodeTasks)) {
    const text = readHead(vscodeTasks);
    if (text !== null && /"runOn"\s*:\s*"folderOpen"/.test(text)) {
      findings.push({
        path: vscodeTasks,
        label: '.vscode/tasks.json (runOn: folderOpen)',
        remediable: false,
        reason:
          'legitimate tooling also owns this file — remove the offending task ' +
          'by hand rather than deleting your whole task configuration',
      });
    }
  }

  const claudeSettings = join(roots.cwd, '.claude', 'settings.json');
  if (existsSync(claudeSettings)) {
    const text = readHead(claudeSettings);
    if (text !== null && /"SessionStart"/.test(text) && /"hooks"/.test(text)) {
      findings.push({
        path: claudeSettings,
        label: '.claude/settings.json (SessionStart hook)',
        remediable: false,
        reason:
          'legitimate tooling also owns this file — remove the offending hook ' +
          'by hand rather than deleting your whole settings file',
      });
    }
  }

  for (const parts of DROPPED_LOADER_FILES) {
    const path = join(roots.cwd, ...parts);
    if (!existsSync(path)) continue;
    const rel = parts.join('/');
    findings.push({
      path,
      label: `${rel} (dropped loader)`,
      remediable: true,
      reason: `nothing legitimate creates a file at ${rel}`,
    });
  }

  // --- OS-level daemons (home-relative, platform-specific) ---

  if (roots.platform === 'linux') {
    findings.push(
      ...enumeratePersistenceDir(
        join(roots.home, '.config', 'systemd', 'user'),
        'systemd user unit',
      ),
    );
  }

  if (roots.platform === 'darwin') {
    findings.push(
      ...enumeratePersistenceDir(join(roots.home, 'Library', 'LaunchAgents'), 'LaunchAgent'),
    );
  }

  // Windows: no equivalent home-relative daemon mechanism is documented in
  // the Shai-Hulud research as of 2026-05. Scheduled Tasks are system-wide
  // and would require elevated enumeration — out of scope for a non-admin
  // diagnostic check.

  return findings;
}

/** Make an arbitrary basename safe to use as a quarantine filename. */
function sanitize(name: string): string {
  return name.replace(/[^A-Za-z0-9._-]+/g, '_');
}

/**
 * Quarantine every remediable finding: copy it under
 * `.sealed-env-quarantine/<stamp>/` first, then remove the original.
 *
 * Copy-then-unlink rather than rename, because a systemd unit under `$HOME`
 * and the project's quarantine dir can live on different mounts, where
 * rename fails with EXDEV.
 *
 * Non-remediable findings are returned in `skipped` and left untouched —
 * see the safety rule in this module's header. `stamp` is injected so the
 * output path is deterministic under test.
 */
export function remediatePersistenceMarkers(
  findings: PersistenceFinding[],
  opts: { cwd: string; stamp: string },
): RemediationResult {
  const quarantined: QuarantinedFile[] = [];
  const skipped: SkippedFile[] = [];

  const remediable: PersistenceFinding[] = [];
  for (const f of findings) {
    if (f.remediable) remediable.push(f);
    else skipped.push({ path: f.path, reason: f.reason });
  }

  if (remediable.length === 0) {
    return { quarantined, skipped, quarantineDir: null };
  }

  const quarantineDir = join(opts.cwd, QUARANTINE_DIR, opts.stamp);
  mkdirSync(quarantineDir, { recursive: true });

  // Index-prefixed names: two different directories can both hold a
  // `setup.mjs`, and the flattened quarantine dir must not lose one of
  // them. The manifest carries the real path back.
  for (let i = 0; i < remediable.length; i++) {
    const finding = remediable[i]!;
    const stored = join(
      quarantineDir,
      `${String(i).padStart(2, '0')}-${sanitize(basename(finding.path))}`,
    );
    try {
      copyFileSync(finding.path, stored);
      unlinkSync(finding.path);
      quarantined.push({ path: finding.path, quarantinedAs: stored });
    } catch (e) {
      // Never leave the operator worse off than before: if the copy or the
      // unlink fails, report it and move on rather than aborting the run
      // half-way through a list of markers.
      skipped.push({
        path: finding.path,
        reason: `could not quarantine: ${e instanceof Error ? e.message : 'unknown error'}`,
      });
    }
  }

  writeFileSync(
    join(quarantineDir, 'manifest.json'),
    `${JSON.stringify(
      {
        tool: 'sealed-env doctor --remediate',
        generatedAt: opts.stamp,
        note: 'Restore a file by copying `stored` back to `original`.',
        entries: quarantined.map((q) => ({ original: q.path, stored: q.quarantinedAs })),
      },
      null,
      2,
    )}\n`,
    'utf8',
  );

  return { quarantined, skipped, quarantineDir };
}
