/**
 * `sealed-env scan [path]` — scan files for accidentally committed
 * sealed-env secrets (tokens, master keys, signing keys, TOTP secrets).
 *
 *   sealed-env scan                  Scan current directory recursively.
 *   sealed-env scan src/             Scan a specific directory.
 *   sealed-env scan .env.local       Scan a specific file.
 *   sealed-env scan --staged         Only files staged for commit (pre-commit).
 *   sealed-env scan --json           Machine-readable output (for CI).
 *   sealed-env scan --explain SE-T1  Print the long-form description of a pattern.
 *
 * Exit codes:
 *   0  No findings.
 *   1  Findings reported. Block the commit / fail the CI.
 *   2  Invocation error (path doesn't exist, bad flag, etc).
 *
 * This is the local mirror of the patterns we ship for gitleaks and
 * trufflehog. It exists so projects that pin sealed-env can scan
 * without installing an extra binary, and so we have a reference
 * implementation we control.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { execFileSync } from 'node:child_process';

import { SealedEnvError } from '../../core/errors.js';
import { PATTERNS, getPattern, type SecretPattern } from '../scan/patterns.js';

interface Finding {
  file: string;
  line: number;
  pattern: SecretPattern;
  /** The exact matched substring (will be truncated for display). */
  match: string;
}

interface ScanOptions {
  paths: string[];
  json: boolean;
  staged: boolean;
  explain: string | null;
}

const DEFAULT_SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'target', // Java
  '.next',
  '.turbo',
  '.cache',
  'coverage',
]);

/**
 * Files we always skip: this repo's own canonical spec and test corpus
 * (they intentionally contain things that look like secrets but are
 * fixtures). Downstream users get this for free because their projects
 * don't have these paths — they're only relevant when scanning sealed-env
 * itself.
 */
const DEFAULT_SKIP_PATTERNS = [
  /SECRET-PATTERNS\.md$/,
  /[/\\]tests[/\\]secret-patterns[/\\]/,
  /[/\\]test-vectors[/\\]/,
];

/** Don't bother reading non-text-looking files. */
const TEXT_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.env',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.ps1',
  '.md',
  '.txt',
  '.java',
  '.kt',
  '.rs',
  '.go',
  '.py',
  '.rb',
  '.php',
  '.html',
  '.xml',
  '.tf',
  '.hcl',
  '.dockerfile',
  '.conf',
  '.cfg',
  '.ini',
  '.properties',
]);

/**
 * Files without an extension that we still want to scan
 * (Dockerfile, Makefile, etc.).
 */
const TEXT_FILENAMES = new Set([
  'Dockerfile',
  'Containerfile',
  'Makefile',
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.test',
  '.envrc',
  '.bashrc',
  '.zshrc',
  '.profile',
  '.pypirc',
  '.npmrc',
]);

const MAX_DISPLAY_MATCH = 80;

export function scanCommand(argv: string[]): void {
  const opts = parseArgs(argv);

  if (opts.explain) {
    explainPattern(opts.explain);
    return;
  }

  const files = opts.staged ? gitStagedFiles() : walkPaths(opts.paths);

  const findings: Finding[] = [];
  for (const file of files) {
    findings.push(...scanFile(file));
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(toJsonReport(findings, files.length), null, 2) + '\n');
  } else {
    printHumanReport(findings, files.length);
  }

  process.exitCode = findings.length > 0 ? 1 : 0;
}

// ---------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------

function parseArgs(argv: string[]): ScanOptions {
  const paths: string[] = [];
  let json = false;
  let staged = false;
  let explain: string | null = null;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') {
      json = true;
    } else if (a === '--staged') {
      staged = true;
    } else if (a === '--explain') {
      const next = argv[++i];
      if (!next) {
        throw new SealedEnvError(
          'CONFIG_ERROR',
          '--explain requires a pattern ID (e.g. --explain SE-T1)',
        );
      }
      explain = next;
    } else if (a.startsWith('--')) {
      throw new SealedEnvError('CONFIG_ERROR', `unknown flag: ${a}`);
    } else {
      paths.push(a);
    }
  }

  if (paths.length === 0 && !staged && !explain) {
    paths.push('.');
  }

  return { paths, json, staged, explain };
}

// ---------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------

function walkPaths(paths: string[]): string[] {
  const out: string[] = [];
  for (const p of paths) {
    const abs = resolve(p);
    if (!existsSync(abs)) {
      throw new SealedEnvError('CONFIG_ERROR', `path not found: ${p}`);
    }
    const s = statSync(abs);
    if (s.isFile()) {
      if (isScannable(abs)) out.push(abs);
    } else if (s.isDirectory()) {
      walkDir(abs, out);
    }
  }
  return out;
}

function walkDir(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return; // permission denied, etc. — skip silently
  }
  for (const name of entries) {
    if (DEFAULT_SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let s;
    try {
      s = statSync(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      walkDir(full, out);
    } else if (s.isFile() && isScannable(full)) {
      out.push(full);
    }
  }
}

function isScannable(file: string): boolean {
  for (const skip of DEFAULT_SKIP_PATTERNS) {
    if (skip.test(file)) return false;
  }
  const base = file.split(sep).pop()!;
  if (TEXT_FILENAMES.has(base)) return true;
  // Catch `.env.something` patterns generically
  if (base.startsWith('.env')) return true;
  const dot = base.lastIndexOf('.');
  if (dot < 0) return false;
  const ext = base.slice(dot).toLowerCase();
  return TEXT_EXTENSIONS.has(ext);
}

function gitStagedFiles(): string[] {
  let raw: string;
  try {
    raw = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], {
      encoding: 'utf8',
    });
  } catch {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      '--staged requires git and a git repository in the current directory',
    );
  }
  return raw
    .split(/\r?\n/)
    .filter(Boolean)
    .map((f) => resolve(f))
    .filter((f) => existsSync(f) && isScannable(f));
}

// ---------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------

function scanFile(file: string): Finding[] {
  let content: string;
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    return [];
  }

  // Cheap binary guard: if there are null bytes in the first 1KB,
  // skip the file. (Saves us from regexing accidentally-included
  // binary assets that have a text-like extension.)
  if (content.slice(0, 1024).includes('\0')) return [];

  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const pattern of PATTERNS) {
      const m = pattern.regex.exec(line);
      if (m) {
        findings.push({
          file,
          line: i + 1,
          pattern,
          match: m[0],
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------
// Output
// ---------------------------------------------------------------

function printHumanReport(findings: Finding[], filesScanned: number): void {
  const cwd = resolve('.');
  process.stdout.write('sealed-env scan — secret detection\n\n');

  if (findings.length === 0) {
    process.stdout.write(`✓ No findings (${filesScanned} file${filesScanned === 1 ? '' : 's'} scanned)\n`);
    return;
  }

  // Group by file so the output is easy to skim and to fix.
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  for (const [file, list] of byFile) {
    const rel = relative(cwd, file) || file;
    for (const f of list) {
      const shown =
        f.match.length > MAX_DISPLAY_MATCH
          ? f.match.slice(0, MAX_DISPLAY_MATCH) + '…'
          : f.match;
      process.stdout.write(
        `[✖] ${rel}:${f.line}\n    ${f.pattern.id} — ${f.pattern.label} (${f.pattern.severity})\n    ${shown}\n\n`,
      );
    }
  }

  const fileWord = byFile.size === 1 ? 'file' : 'files';
  process.stdout.write(
    `${findings.length} finding${findings.length === 1 ? '' : 's'} in ${byFile.size} ${fileWord} ` +
      `(${filesScanned} scanned total)\n`,
  );
  process.stdout.write(
    `\nFor remediation guidance: sealed-env scan --explain <ID>\n` +
      `Spec: https://github.com/davidalmeidac/sealed-env/blob/main/SECRET-PATTERNS.md\n`,
  );
}

function toJsonReport(findings: Finding[], filesScanned: number): unknown {
  return {
    schema: 'sealed-env-scan/v1',
    summary: {
      findings: findings.length,
      files_with_findings: new Set(findings.map((f) => f.file)).size,
      files_scanned: filesScanned,
    },
    findings: findings.map((f) => ({
      file: relative(resolve('.'), f.file) || f.file,
      line: f.line,
      pattern_id: f.pattern.id,
      pattern_label: f.pattern.label,
      severity: f.pattern.severity,
      match_preview:
        f.match.length > MAX_DISPLAY_MATCH ? f.match.slice(0, MAX_DISPLAY_MATCH) + '…' : f.match,
    })),
  };
}

function explainPattern(id: string): void {
  let pattern: SecretPattern;
  try {
    pattern = getPattern(id);
  } catch {
    process.stderr.write(`sealed-env scan: unknown pattern id "${id}"\n\n`);
    process.stderr.write('Known patterns:\n');
    for (const p of PATTERNS) {
      process.stderr.write(`  ${p.id.padEnd(12)} ${p.label} (${p.severity})\n`);
    }
    process.exitCode = 2;
    return;
  }
  process.stdout.write(
    [
      `${pattern.id} — ${pattern.label} (${pattern.severity})`,
      '',
      pattern.description,
      '',
      `Regex: ${pattern.regex.source}`,
      '',
      'Canonical spec: https://github.com/davidalmeidac/sealed-env/blob/main/SECRET-PATTERNS.md',
      '',
    ].join('\n'),
  );
}
