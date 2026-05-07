/**
 * `sealed-env deploy [--health-url <url>] -- <command> [args...]`
 *
 * Production deploy wrapper around `exec`. Adds the safety rails that
 * a hand-rolled deploy.sh would otherwise have to implement:
 *
 *   - Auto-detects `deploy_id` from `git rev-parse HEAD`.
 *   - Refuses to deploy with a dirty working tree (uncommitted changes
 *     would silently NOT be in the build, since the deploy_id binds to
 *     the committed sha).
 *   - Prompts the operator for the TOTP code (hidden from logs).
 *   - Mints the unseal token IN MEMORY and injects only the resulting
 *     plaintext env vars into the child. The master/signing/TOTP
 *     credentials never reach the child process or stdout.
 *   - Optionally polls a health endpoint after the command exits.
 *
 *   $ sealed-env deploy -- docker compose up -d --build status
 *   $ sealed-env deploy --health-url http://127.0.0.1:8090/actuator/health -- ./up.sh
 *
 * For the file path, defaults to `.env.sealed`. Override with --file.
 *
 * Compared to a hand-written deploy.sh: ~5 lines instead of ~130, and
 * the token never appears in stdout (no fragile grep).
 */

import { execSync } from 'node:child_process';

import { SealedEnvError } from '../../core/errors.js';
import { execCommand } from './exec.js';
import { parseFlags } from '../utils/flags.js';

export async function deployCommand(argv: string[]): Promise<void> {
  const sepIndex = argv.indexOf('--');
  if (sepIndex === -1) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env deploy [--file <path>] [--health-url <url>] [--health-timeout <s>] [--allow-dirty] -- <command> [args...]\n' +
        '\nThe `--` separator marks where sealed-env flags end.',
    );
  }

  const sealedArgs = argv.slice(0, sepIndex);
  const childArgs = argv.slice(sepIndex + 1);

  if (childArgs.length === 0) {
    throw new SealedEnvError('CONFIG_ERROR', 'no command given after `--`');
  }

  const { values } = parseFlags(sealedArgs, {
    file: { type: 'string', default: '.env.sealed' },
    'health-url': { type: 'string', default: '' },
    'health-timeout': { type: 'string', default: '30' },
    'allow-dirty': { type: 'boolean', default: false },
    totp: { type: 'string', default: '' },
    'deploy-id': { type: 'string', default: '' },
  });

  // ── Pre-flight ────────────────────────────────────────────────
  let deployId = (values['deploy-id'] as string).trim();
  if (!deployId) {
    deployId = tryGitHead();
  }

  const allowDirty = values['allow-dirty'] as boolean;
  if (!allowDirty && isInGitRepo() && isWorkingTreeDirty()) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'working tree is dirty — refusing to deploy.\n' +
        'Commit or stash your changes first, or pass --allow-dirty (NOT recommended for prod).\n' +
        'The deploy_id binds to the committed sha; uncommitted changes would silently not be in the build.',
    );
  }

  // ── Banner ────────────────────────────────────────────────────
  const banner = buildBanner(deployId);
  process.stderr.write(banner);

  // ── Delegate to exec ──────────────────────────────────────────
  // exec handles: enterprise mode detection, TOTP prompt, token mint
  // in memory, plaintext injection, signal forwarding, exit code
  // propagation. We just feed it the right arguments.
  const execArgs: string[] = [
    '--file',
    values.file as string,
  ];
  if (deployId) execArgs.push('--deploy-id', deployId);
  if (values.totp) execArgs.push('--totp', values.totp as string);
  execArgs.push('--', ...childArgs);

  await execCommand(execArgs);

  // If the child exited non-zero, exec already set process.exitCode.
  // No point health-checking a failed deploy.
  if (process.exitCode && process.exitCode !== 0) {
    return;
  }

  // ── Optional health check ────────────────────────────────────
  const healthUrl = (values['health-url'] as string).trim();
  if (healthUrl) {
    const timeoutS = Math.max(Number(values['health-timeout']) || 30, 1);
    process.stderr.write(`\n▸ Waiting for ${healthUrl} (up to ${timeoutS}s)...\n`);
    const ok = await pollHealth(healthUrl, timeoutS * 1000);
    if (!ok) {
      process.stderr.write(`✗ health check failed after ${timeoutS}s\n`);
      process.exitCode = 1;
      return;
    }
    process.stderr.write(`✓ ${healthUrl} returned 200\n`);
  }

  process.stderr.write(
    `\n✓ Deploy successful${deployId ? ` (${deployId.substring(0, 7)})` : ''}\n`,
  );
}

function tryGitHead(): string {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .trim();
  } catch {
    return '';
  }
}

function isInGitRepo(): boolean {
  try {
    execSync('git rev-parse --is-inside-work-tree', {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

function isWorkingTreeDirty(): boolean {
  try {
    execSync('git diff-index --quiet HEAD --', {
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return false;
  } catch {
    return true;
  }
}

function buildBanner(deployId: string): string {
  const short = deployId ? deployId.substring(0, 7) : '(no git)';
  let branch = '';
  let subject = '';
  try {
    branch = execSync('git rev-parse --abbrev-ref HEAD', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    subject = execSync('git log -1 --pretty=%s', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .trim()
      .substring(0, 60);
  } catch {
    /* not a git repo, skip */
  }
  return [
    '',
    '  ┌─ sealed-env deploy ──────────────────────────────────────┐',
    `  │  branch:  ${branch || '(unknown)'}`,
    `  │  commit:  ${short}`,
    ...(subject ? [`  │  message: ${subject}`] : []),
    '  └──────────────────────────────────────────────────────────┘',
    '',
  ].join('\n');
}

/**
 * Poll an HTTP endpoint until it returns 2xx or the timeout elapses.
 * Uses Node's built-in fetch (Node 18+). 1s between attempts.
 */
async function pollHealth(url: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return true;
    } catch {
      /* swallow, keep retrying */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}
