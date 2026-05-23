/**
 * `sealed-env hunt-shai-hulud [path] [--json]`
 *
 * A focused, opinionated scanner for indicators of compromise from
 * the open-sourced TeamPCP Shai-Hulud framework and its variants
 * (Mini Shai-Hulud, TanStack campaign, AntV campaign, etc.).
 *
 * What it does NOT do: replace Snyk, Socket, or Phylum. Those are
 * commercial scanners with much broader coverage and faster IOC
 * updates. This command is the open-source narrow-scope check that
 * sealed-env users can run as a default first line of defense — and
 * it's tied to our own threat-research documentation so the output
 * is verifiable against citations.
 *
 * Output modes:
 *   default — human-readable with the Dune sandworm ASCII
 *   --json  — schema sealed-env-hunt-shai-hulud/v1 for CI integration
 *
 * Exit codes:
 *   0 — clean
 *   1 — suspect (medium/low severity findings only)
 *   2 — compromised (at least one confirmed-malicious match)
 */

import { relative, resolve } from 'node:path';

import { SealedEnvError } from '../../core/errors.js';
import { huntShaiHulud, type HuntReport } from '../hunt/scanner.js';
import {
  SANDWORM_CLEAN,
  SANDWORM_COMPROMISED,
  SANDWORM_SUSPECT,
} from '../hunt/sandworm-ascii.js';

interface HuntOptions {
  path: string;
  json: boolean;
}

const SHAI_HULUD_DOC =
  'https://github.com/davidalmeidac/sealed-env/blob/main/threat-research/analysis/shai-hulud-defense.md';

export function huntShaiHuludCommand(argv: string[]): void {
  const opts = parseArgs(argv);
  const report = huntShaiHulud(opts.path);

  if (opts.json) {
    printJson(report, opts.path);
  } else {
    printHuman(report, opts.path);
  }

  // Exit code semantics:
  // 0 = clean | 1 = suspect | 2 = compromised
  process.exitCode = report.overall === 'clean' ? 0 : report.overall === 'suspect' ? 1 : 2;
}

function parseArgs(argv: string[]): HuntOptions {
  let path = '.';
  let json = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') {
      json = true;
    } else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else if (a.startsWith('--')) {
      throw new SealedEnvError('CONFIG_ERROR', `unknown flag: ${a}`);
    } else {
      path = a;
    }
  }

  return { path, json };
}

function printHelp(): void {
  process.stdout.write(
    [
      'sealed-env hunt-shai-hulud — scan a project for Shai-Hulud IOCs',
      '',
      'Usage:',
      '  sealed-env hunt-shai-hulud [path] [--json]',
      '',
      'What it checks:',
      '  - package-lock.json for known-malicious package versions',
      '  - node_modules/*/package.json for suspicious pre/post-install scripts',
      '  - node_modules/*/  for loader files at package root',
      '    (router_init.js, tanstack_runner.js, setup.mjs, ...)',
      '  - optionalDependencies pointing to github: commit SHAs',
      '  - OS-level persistence markers (systemd user units, LaunchAgents)',
      '',
      'Exit codes:',
      '  0  clean (no findings)',
      '  1  suspect (only medium/low severity findings)',
      '  2  compromised (at least one confirmed-malicious match)',
      '',
      `Full analysis: ${SHAI_HULUD_DOC}`,
      '',
    ].join('\n'),
  );
}

function printHuman(report: HuntReport, scanPath: string): void {
  const cwd = resolve('.');
  process.stdout.write('sealed-env hunt-shai-hulud — IOC scan\n\n');

  // Print findings BEFORE the ASCII art so the operator sees the
  // technical detail first; the worm is the summary, not the body.
  if (report.findings.length === 0) {
    process.stdout.write(
      `✓ No Shai-Hulud IOCs detected in ${scanPath}\n` +
        `  (${report.scanned.packageLockFiles} lockfile scanned, ` +
        `${report.scanned.nodeModulesPackages} packages in node_modules)\n`,
    );
  } else {
    process.stdout.write(`Findings (${report.findings.length}):\n\n`);
    for (const f of report.findings) {
      const tag = f.severity === 'high' ? '✖' : '!';
      const loc = f.location.startsWith('/') || f.location.includes(':')
        ? relative(cwd, f.location) || f.location
        : f.location;
      process.stdout.write(`  [${tag}] ${f.id} — ${f.label} (${f.severity})\n`);
      process.stdout.write(`      ${loc}\n`);
      process.stdout.write(`      ${f.detail}\n`);
      if (f.citation) process.stdout.write(`      ref: ${f.citation}\n`);
      process.stdout.write('\n');
    }
  }

  // Sandworm ASCII at the end — visual summary of the verdict.
  const art =
    report.overall === 'compromised'
      ? SANDWORM_COMPROMISED
      : report.overall === 'suspect'
        ? SANDWORM_SUSPECT
        : SANDWORM_CLEAN;
  process.stdout.write(art);
  process.stdout.write('\n');

  process.stdout.write(`Full analysis & IOC table: ${SHAI_HULUD_DOC}\n`);
  if (report.overall === 'compromised') {
    process.stdout.write(
      `Compromised? Read docs/incident-response.md BEFORE revoking any credentials.\n`,
    );
  }
}

function printJson(report: HuntReport, scanPath: string): void {
  const payload = {
    schema: 'sealed-env-hunt-shai-hulud/v1',
    scan_path: resolve(scanPath),
    overall: report.overall,
    scanned: report.scanned,
    findings: report.findings.map((f) => ({
      id: f.id,
      label: f.label,
      severity: f.severity,
      location: f.location,
      detail: f.detail,
      citation: f.citation ?? null,
    })),
  };
  process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
}
