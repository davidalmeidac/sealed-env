/**
 * `sealed-env deploy [--remote user@host] [--health-url <url>] -- <command>`
 *
 * Production deploy wrapper around `exec`. Adds the safety rails that
 * a hand-rolled deploy.sh would otherwise have to implement:
 *
 *   - Auto-detects `deploy_id` from `git rev-parse HEAD`.
 *   - Refuses to deploy with a dirty working tree.
 *   - Prompts for the TOTP code (hidden from logs).
 *   - Mints the unseal token IN MEMORY and injects only the resulting
 *     plaintext env vars into the target.
 *   - Optionally polls a health endpoint after the command exits.
 *
 *   $ sealed-env deploy -- docker compose up -d --build
 *   $ sealed-env deploy --health-url http://127.0.0.1:8090/actuator/health -- ./up.sh
 *
 * With `--remote`, this becomes a Model A (host-side decrypt) deploy:
 * decryption happens locally, only plaintext env vars cross the
 * network through an SSH tunnel. The remote server never sees the
 * master key, the signing key, or the sealed file.
 *
 *   $ sealed-env deploy --remote user@prod -- ./up.sh
 *   $ sealed-env deploy --remote ops@1.2.3.4 --ssh-port 2222 -- docker compose up -d
 *
 * See docs/10-decrypt-strategies.md for the trade-off vs Model B.
 *
 * Compared to a hand-written deploy.sh: ~5 lines instead of ~130, and
 * the secrets never appear in stdout, argv, or the remote `ps aux`.
 */

import { execSync } from 'node:child_process';

import { SealedEnvError } from '../../core/errors.js';
import { execCommand } from './exec.js';
import { parseFlags } from '../utils/flags.js';
import { pollHealth } from '../utils/health-check.js';
import { prepareEnvFromSealed } from '../utils/prepare-env.js';
import {
  execOverSsh,
  parseSshTarget,
  type SshOptions,
  validateSshConnection,
} from '../utils/ssh.js';

export async function deployCommand(argv: string[]): Promise<void> {
  const sepIndex = argv.indexOf('--');
  if (sepIndex === -1) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env deploy [--file <path>] [--remote <user@host>]\n' +
        '                        [--ssh-port <port>] [--ssh-key <path>]\n' +
        '                        [--health-url <url>] [--health-timeout <s>]\n' +
        '                        [--allow-dirty] [--totp <code>]\n' +
        '                        -- <command> [args...]\n' +
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
    remote: { type: 'string', default: '' },
    'ssh-port': { type: 'string', default: '22' },
    'ssh-key': { type: 'string', default: '' },
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

  const remoteTarget = (values.remote as string).trim();
  const isRemote = remoteTarget.length > 0;

  // ── Banner ────────────────────────────────────────────────────
  process.stderr.write(buildBanner(deployId, isRemote ? remoteTarget : null));

  // ── Branch on local vs remote ────────────────────────────────
  if (isRemote) {
    await deployRemote({
      target: remoteTarget,
      port: parseSshPort(values['ssh-port'] as string),
      identity: ((values['ssh-key'] as string) || '').trim() || undefined,
      filePath: values.file as string,
      totp: (values.totp as string).trim(),
      deployId,
      childArgs,
    });
  } else {
    // Local deploy: delegate to execCommand (existing behaviour).
    const execArgs: string[] = ['--file', values.file as string];
    if (deployId) execArgs.push('--deploy-id', deployId);
    if (values.totp) execArgs.push('--totp', values.totp as string);
    execArgs.push('--', ...childArgs);
    await execCommand(execArgs);
  }

  // If the child exited non-zero, we already set process.exitCode.
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

interface RemoteDeployArgs {
  target: string;
  port: number;
  identity: string | undefined;
  filePath: string;
  totp: string;
  deployId: string;
  childArgs: string[];
}

/**
 * Model A path: decrypt locally, ship plaintext via SSH.
 *
 * Order of operations is deliberate:
 *   1. Validate SSH FIRST. If we can't reach the host, we don't want
 *      decrypted plaintext sitting in this process's RAM waiting.
 *   2. Decrypt + mint token (via prepareEnvFromSealed).
 *   3. execOverSsh ships the env vars through stdin to /bin/sh on the
 *      remote — values never appear in argv or `ps aux`.
 */
async function deployRemote(args: RemoteDeployArgs): Promise<void> {
  const { user, host } = parseSshTarget(args.target);
  const sshOpts: SshOptions = {
    user,
    host,
    port: args.port,
    ...(args.identity ? { identity: args.identity } : {}),
  };

  process.stderr.write(`▸ ssh pre-flight to ${user}@${host}...\n`);
  await validateSshConnection(sshOpts);
  process.stderr.write(`✓ ssh reachable\n`);

  const prepared = await prepareEnvFromSealed({
    filePath: args.filePath,
    totp: args.totp,
    deployId: args.deployId,
  });

  process.stderr.write(
    `▸ decrypted ${prepared.envVars.size} env vars locally · shipping via SSH...\n`,
  );

  const exitCode = await execOverSsh(sshOpts, prepared.envVars, args.childArgs);
  process.exitCode = exitCode;

  // Best-effort wipe: blank the values in the Map so they don't linger
  // in the parent process longer than needed.
  for (const k of prepared.envVars.keys()) {
    prepared.envVars.set(k, '');
  }
}

function parseSshPort(raw: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new SealedEnvError('CONFIG_ERROR', `invalid --ssh-port "${raw}" (must be 1-65535)`);
  }
  return n;
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

function buildBanner(deployId: string, remote: string | null): string {
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
    ...(remote ? [`  │  remote:  ${remote}  (Model A · host-side decrypt)`] : []),
    '  └──────────────────────────────────────────────────────────┘',
    '',
  ].join('\n');
}
