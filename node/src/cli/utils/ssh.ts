/**
 * Thin wrapper around the system `ssh` binary for `deploy --remote`.
 *
 * Why the binary instead of a library:
 *   - Honors the zero-deps promise of the core. The CLI shells out to
 *     `ssh`, which is universally available (OpenSSH on Linux/macOS,
 *     Win32-OpenSSH on Windows 10+).
 *   - Reuses the operator's SSH config, agent, and known-hosts file
 *     instead of re-implementing key management, host verification,
 *     and the agent protocol.
 *
 * Why we ship plaintext env vars over stdin instead of as `env VAR=val`:
 *   - Args are visible in `ps aux` on the remote host while the command
 *     runs. Stdin is not. An attacker with shell on the remote during
 *     deploy can race the args; they cannot race a stdin pipe to a
 *     spawned shell.
 *
 * Quoting strategy: every value is wrapped in single quotes, with any
 * internal single quotes turned into the four-character sequence
 * `'\''`. That's bash-safe for ANY content including newlines, dollars,
 * backticks, and unicode.
 */

import { spawn } from 'node:child_process';

import { SealedEnvError } from '../../core/errors.js';

export interface SshOptions {
  /** SSH user (left of `@`). */
  user: string;
  /** Hostname or IP (right of `@`). */
  host: string;
  /** SSH port. Default: 22. */
  port?: number;
  /** Path to private key file. If unset, uses the SSH agent / default keys. */
  identity?: string;
}

/**
 * Parse a `user@host` string. Throws if malformed.
 */
export function parseSshTarget(target: string): { user: string; host: string } {
  const trimmed = target.trim();
  const at = trimmed.lastIndexOf('@');
  if (at <= 0 || at === trimmed.length - 1) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      `--remote must be in user@host form (got "${target}")`,
    );
  }
  return { user: trimmed.slice(0, at), host: trimmed.slice(at + 1) };
}

/**
 * Single-quote-wrap a value so it can be safely embedded in a /bin/sh
 * command. Handles every character including embedded single quotes
 * (encoded as `'\''`) and newlines (preserved literally).
 */
export function shellEscape(value: string): string {
  return "'" + String(value).replace(/'/g, "'\\''") + "'";
}

/**
 * Build the script that gets piped to the remote /bin/sh: a series of
 * `export KEY='value'` lines followed by `exec <command>`. The export
 * lines are sorted by key so the byte stream is deterministic — this
 * lets the cross-stack vector test compare Node and Java output for
 * byte equality.
 */
export function buildRemoteScript(
  envVars: Map<string, string>,
  command: string[],
): string {
  if (command.length === 0) {
    throw new SealedEnvError('CONFIG_ERROR', 'no command provided to run on remote host');
  }
  const sortedKeys = [...envVars.keys()].sort();
  const exports = sortedKeys.map((k) => `export ${k}=${shellEscape(envVars.get(k) ?? '')}`);
  const cmdLine = command.map(shellEscape).join(' ');
  return [...exports, `exec ${cmdLine}`, ''].join('\n');
}

/**
 * Build the argv passed to ssh(1). Common flags are applied to both
 * validation and execution paths so behaviour stays consistent.
 */
function sshArgs(opts: SshOptions, extra: string[] = []): string[] {
  const args: string[] = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
  ];
  if (opts.port && opts.port !== 22) {
    args.push('-p', String(opts.port));
  }
  if (opts.identity) {
    args.push('-i', opts.identity);
  }
  args.push(...extra);
  args.push(`${opts.user}@${opts.host}`);
  return args;
}

/**
 * Verify that `ssh user@host` works before doing anything else.
 *
 * Why pre-flight? If SSH is going to fail, it's better to fail BEFORE
 * we decrypt the sealed file and have plaintext sitting in this
 * process's RAM. A 10-second timeout prevents us from hanging on an
 * unreachable host.
 *
 * Throws SealedEnvError on any failure with a hint about what to check.
 */
export async function validateSshConnection(opts: SshOptions): Promise<void> {
  return new Promise((resolveOuter, rejectOuter) => {
    const args = sshArgs(opts, ['-o', 'ConnectTimeout=10', '--', 'echo', 'OK']);
    const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (b) => { stdout += b.toString('utf8'); });
    child.stderr.on('data', (b) => { stderr += b.toString('utf8'); });

    child.on('error', (err) => {
      rejectOuter(
        new SealedEnvError(
          'CONFIG_ERROR',
          `failed to launch ssh: ${err.message}\n` +
            `(make sure the OpenSSH client is installed and on PATH)`,
        ),
      );
    });

    child.on('exit', (code) => {
      if (code === 0 && stdout.trim() === 'OK') {
        resolveOuter();
        return;
      }
      const hint = stderr.includes('Permission denied')
        ? '\n  hint: SSH key auth failed. Check your ssh-agent / ~/.ssh/config / --ssh-key.'
        : stderr.includes('Connection refused')
          ? '\n  hint: nothing answering on the SSH port. Wrong host/port or service down.'
          : stderr.includes('No route to host')
            ? '\n  hint: network unreachable. Check VPN / firewall.'
            : stderr.includes('Could not resolve hostname')
              ? '\n  hint: DNS lookup failed. Check the hostname.'
              : '';
      rejectOuter(
        new SealedEnvError(
          'CONFIG_ERROR',
          `ssh pre-flight to ${opts.user}@${opts.host} failed (exit ${code})\n` +
            (stderr ? stderr.trim().split('\n').map((l) => `  ${l}`).join('\n') + '\n' : '') +
            hint,
        ),
      );
    });
  });
}

/**
 * Run `command` on the remote host with `envVars` exported into its
 * environment. Plaintext values flow through stdin to a remote shell;
 * they never appear on the remote command line and so are not visible
 * via `ps aux`.
 *
 * stdin/stdout/stderr of the remote command are inherited by the
 * caller — the operator sees the deploy output live.
 *
 * Returns the remote command's exit code.
 */
export async function execOverSsh(
  opts: SshOptions,
  envVars: Map<string, string>,
  command: string[],
): Promise<number> {
  const script = buildRemoteScript(envVars, command);
  const args = sshArgs(opts, ['--', '/bin/sh']);

  return new Promise((resolveOuter, rejectOuter) => {
    const child = spawn('ssh', args, {
      stdio: ['pipe', 'inherit', 'inherit'],
    });

    child.on('error', (err) => {
      rejectOuter(
        new SealedEnvError(
          'CONFIG_ERROR',
          `failed to launch ssh: ${err.message}`,
        ),
      );
    });

    child.on('exit', (code, signal) => {
      if (signal) {
        // Re-raise the signal in this process so the parent shell sees
        // the same exit cause.
        process.kill(process.pid, signal);
      } else {
        resolveOuter(code ?? 0);
      }
    });

    // Forward Ctrl+C to the remote child via SSH (which forwards it to
    // the remote shell, which forwards it to the deployed process).
    const forward = (sig: NodeJS.Signals) => () => {
      if (!child.killed) child.kill(sig);
    };
    const sigInt = forward('SIGINT');
    const sigTerm = forward('SIGTERM');
    process.on('SIGINT', sigInt);
    process.on('SIGTERM', sigTerm);
    child.on('exit', () => {
      process.off('SIGINT', sigInt);
      process.off('SIGTERM', sigTerm);
    });

    child.stdin.write(script);
    child.stdin.end();
  });
}
