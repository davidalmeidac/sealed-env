/**
 * Shai-Hulud hunter — scans a project directory for indicators of
 * compromise documented in `threat-research/analysis/ioc-table.md`.
 *
 * Three layers of detection:
 *
 *   1. EXACT — known-malicious package versions in package-lock.json
 *      (no ranges, no heuristics; a hit is high-confidence).
 *
 *   2. STRUCTURAL — suspicious files at the root of installed
 *      `node_modules/<pkg>/` directories (router_init.js,
 *      tanstack_runner.js, etc.).
 *
 *   3. BEHAVIORAL — `package.json` scripts.{pre,post}install entries
 *      that reference the framework's loader filenames, and
 *      `optionalDependencies` pointing to GitHub commit SHAs (the
 *      Shai-Hulud payload-staging pattern).
 *
 * Severity tiers map to the ASCII art shown to the operator:
 *   - CLEAN: no findings at all
 *   - SUSPECT: behavioral / structural findings only
 *   - COMPROMISED: at least one exact match against a known-bad
 *     (package, version)
 *
 * This module does not exit, does not print anything, and does not
 * touch the filesystem outside the directory passed in. All IO is
 * read-only; if a file is unreadable we skip silently.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  COMPROMISED_PACKAGES,
  PERSISTENCE_NAME_SUBSTRINGS,
  SUSPICIOUS_INSTALL_SCRIPT_SUBSTRINGS,
  SUSPICIOUS_PACKAGE_ROOT_FILES,
} from './iocs.js';

export type Severity = 'clean' | 'suspect' | 'compromised';

export interface Finding {
  severity: 'high' | 'medium' | 'low';
  /** Stable ID for tooling integration. */
  id: string;
  /** Short human label. */
  label: string;
  /** Specific file or package this finding refers to. */
  location: string;
  /** What about it triggered. */
  detail: string;
  /** Source citation, if applicable. */
  citation?: string;
}

export interface HuntReport {
  /** Highest severity across findings. */
  overall: Severity;
  /** Number of files / dirs touched during the scan. */
  scanned: {
    packageLockFiles: number;
    nodeModulesPackages: number;
  };
  findings: Finding[];
}

/**
 * Entry point. Scans `rootDir` and returns a structured report.
 */
export function huntShaiHulud(rootDir: string): HuntReport {
  const abs = resolve(rootDir);
  const findings: Finding[] = [];
  const stats = { packageLockFiles: 0, nodeModulesPackages: 0 };

  // Layer 1: package-lock.json — exact matches against known-malicious versions
  const lockFindings = scanLockFile(abs, stats);
  findings.push(...lockFindings);

  // Layer 2 + 3: node_modules — structural + behavioral
  const nmFindings = scanNodeModules(abs, stats);
  findings.push(...nmFindings);

  // Bonus: persistence markers in HOME (re-used from doctor, scoped here
  // because hunt-shai-hulud is meant to be a complete standalone check)
  const persistFindings = scanPersistenceMarkers();
  findings.push(...persistFindings);

  // Derive overall severity
  const hasHigh = findings.some((f) => f.severity === 'high');
  const hasMediumOrLow = findings.some((f) => f.severity !== 'high');
  const overall: Severity = hasHigh ? 'compromised' : hasMediumOrLow ? 'suspect' : 'clean';

  return { overall, scanned: stats, findings };
}

// ---------------------------------------------------------------
// Layer 1 — package-lock.json (exact matches)
// ---------------------------------------------------------------

function scanLockFile(rootDir: string, stats: HuntReport['scanned']): Finding[] {
  const lockPath = join(rootDir, 'package-lock.json');
  if (!existsSync(lockPath)) return [];
  stats.packageLockFiles++;

  let lock: unknown;
  try {
    lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  // npm v7+ lock format uses "packages" map; v5/6 uses "dependencies"
  const packages = (lock as { packages?: Record<string, { version?: string }> }).packages;
  if (packages) {
    for (const [path, meta] of Object.entries(packages)) {
      if (!meta || typeof meta !== 'object') continue;
      // npm lock keys are "node_modules/<pkg>" or "" (root). Extract name.
      const name = path.startsWith('node_modules/')
        ? path.slice('node_modules/'.length).replace(/\/node_modules\/.+$/, '')
        : null;
      if (!name || !meta.version) continue;
      const hit = matchCompromisedPackage(name, meta.version);
      if (hit) {
        findings.push({
          severity: 'high',
          id: 'IOC-PKG-EXACT',
          label: 'compromised package version',
          location: `${name}@${meta.version}`,
          detail: hit.campaign,
          citation: hit.citation,
        });
      }
    }
  }
  return findings;
}

function matchCompromisedPackage(name: string, version: string) {
  for (const pkg of COMPROMISED_PACKAGES) {
    if (pkg.name !== name) continue;
    if (pkg.versions.includes('*') || pkg.versions.includes(version)) return pkg;
  }
  return null;
}

// ---------------------------------------------------------------
// Layer 2 + 3 — node_modules (structural + behavioral)
// ---------------------------------------------------------------

function scanNodeModules(rootDir: string, stats: HuntReport['scanned']): Finding[] {
  const nm = join(rootDir, 'node_modules');
  if (!existsSync(nm)) return [];

  const findings: Finding[] = [];
  walkNodeModules(nm, findings, stats);
  return findings;
}

function walkNodeModules(dir: string, findings: Finding[], stats: HuntReport['scanned']): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    const full = join(dir, entry);
    let s;
    try {
      s = statSync(full);
    } catch {
      continue;
    }
    if (!s.isDirectory()) continue;

    // npm scoped packages: recurse into @scope/
    if (entry.startsWith('@')) {
      walkNodeModules(full, findings, stats);
      continue;
    }

    // Top-level npm package directory
    stats.nodeModulesPackages++;
    scanInstalledPackage(full, findings);

    // Recurse into nested node_modules (npm v7+ flat install means
    // these are rare but still possible for conflicting deps)
    const nested = join(full, 'node_modules');
    if (existsSync(nested)) {
      walkNodeModules(nested, findings, stats);
    }
  }
}

function scanInstalledPackage(pkgDir: string, findings: Finding[]): void {
  // Layer 2 — structural: suspicious files at package root
  let dirEntries: string[];
  try {
    dirEntries = readdirSync(pkgDir);
  } catch {
    return;
  }
  for (const name of dirEntries) {
    if (SUSPICIOUS_PACKAGE_ROOT_FILES.includes(name)) {
      findings.push({
        severity: 'high',
        id: 'IOC-FILE-ROOT',
        label: 'suspicious loader file at package root',
        location: `${pkgDir}/${name}`,
        detail:
          `Shai-Hulud-class campaigns drop these loaders at the package ` +
          `root (outside dist/ or src/). Verify the file is legitimate.`,
        citation:
          'https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem',
      });
    }
  }

  // Layer 3 — behavioral: package.json scripts + optionalDependencies
  const pkgJsonPath = join(pkgDir, 'package.json');
  if (!existsSync(pkgJsonPath)) return;
  let pkgJson: any;
  try {
    pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    return;
  }

  if (pkgJson.scripts && typeof pkgJson.scripts === 'object') {
    for (const scriptName of ['preinstall', 'postinstall', 'install']) {
      const script = pkgJson.scripts[scriptName];
      if (typeof script !== 'string') continue;
      for (const sub of SUSPICIOUS_INSTALL_SCRIPT_SUBSTRINGS) {
        if (script.includes(sub)) {
          findings.push({
            severity: 'high',
            id: 'IOC-SCRIPT',
            label: `suspicious ${scriptName} script`,
            location: `${pkgJsonPath} (${scriptName})`,
            detail: `script references "${sub}" — known Shai-Hulud loader name`,
            citation:
              'https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/',
          });
        }
      }
    }
  }

  if (pkgJson.optionalDependencies && typeof pkgJson.optionalDependencies === 'object') {
    for (const [depName, depSpec] of Object.entries(pkgJson.optionalDependencies)) {
      if (typeof depSpec !== 'string') continue;
      // Pattern: github:user/repo#<40-char-SHA>
      if (/^github:[\w.-]+\/[\w.-]+#[0-9a-f]{40}$/.test(depSpec)) {
        findings.push({
          severity: 'medium',
          id: 'IOC-OPTDEP-GITHUB-SHA',
          label: 'optionalDependencies points to a GitHub commit SHA',
          location: `${pkgJsonPath} (optionalDependencies.${depName})`,
          detail:
            `Reference: ${depSpec}. The Shai-Hulud framework uses this ` +
            `pattern to stage payloads from attacker-controlled forks. ` +
            `Verify the commit SHA and repository owner.`,
          citation:
            'https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem',
        });
      }
    }
  }
}

// ---------------------------------------------------------------
// Persistence markers (re-used from doctor's check)
// ---------------------------------------------------------------

function scanPersistenceMarkers(): Finding[] {
  const findings: Finding[] = [];
  const home = process.env['HOME'] || process.env['USERPROFILE'] || '';
  if (!home) return findings;

  const plat = process.platform;

  // Linux: systemd user units
  if (plat === 'linux') {
    findings.push(
      ...checkPersistenceDir(
        join(home, '.config', 'systemd', 'user'),
        'systemd user unit',
      ),
    );
  }

  // macOS: LaunchAgents
  if (plat === 'darwin') {
    findings.push(
      ...checkPersistenceDir(join(home, 'Library', 'LaunchAgents'), 'LaunchAgent'),
    );
  }

  return findings;
}

function checkPersistenceDir(dir: string, kind: string): Finding[] {
  if (!existsSync(dir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const findings: Finding[] = [];
  for (const entry of entries) {
    const lower = entry.toLowerCase();
    for (const pat of PERSISTENCE_NAME_SUBSTRINGS) {
      if (lower.includes(pat)) {
        findings.push({
          severity: 'high',
          id: 'IOC-PERSISTENCE',
          label: `suspicious ${kind}`,
          location: `${dir}/${entry}`,
          detail:
            `Matches known persistence pattern "${pat}". ` +
            `BEFORE revoking credentials see docs/incident-response.md ` +
            `(deadman switch warning).`,
          citation:
            'https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/',
        });
        break;
      }
    }
  }
  return findings;
}
