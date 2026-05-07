/**
 * `sealed-env exec --file <.env.sealed> -- <command> [args...]`
 *
 * Decrypt the sealed file, inject every key/value pair into the
 * environment of a child process, run the command, and exit with the
 * child's exit code.
 *
 *   $ sealed-env exec --file .env.sealed -- node server.js
 *   $ sealed-env exec --file .env.sealed -- npm start
 *   $ sealed-env exec --file prod/.env.sealed -- ./deploy.sh
 *
 * Why prefer this over `sealed-env decrypt > .env`:
 *   - The plaintext never lands on disk. It exists only in process
 *     memory and is wiped after spawn.
 *   - Existing `process.env` values are NOT overridden by default
 *     (the host environment wins). Pass `--override` to flip this.
 *   - The command's exit code is propagated, so it composes cleanly
 *     with shell pipelines and `npm run` chains.
 *
 * Notes for ops:
 *   - On Linux the plaintext touches the kernel briefly during the
 *     spawn ABI, but never the filesystem.
 *   - The child inherits stdio (stdout/stderr/stdin) directly. No
 *     line-buffering, no munging, no log capture by sealed-env.
 *   - Signals (SIGINT, SIGTERM) sent to sealed-env are forwarded
 *     to the child so Ctrl+C works as expected.
 */

import { spawn } from 'node:child_process';

import { SealedEnvError } from '../../core/errors.js';
import { parseFlags } from '../utils/flags.js';
import { decryptSealedFile, parseDotenv } from '../utils/io.js';

export function execCommand(argv: string[]): Promise<void> {
  // Split on `--` so flags before it belong to sealed-env, and
  // everything after is the command + its args. This is the standard
  // POSIX convention used by env(1), nice(1), sudo(8), and many others.
  const sepIndex = argv.indexOf('--');
  if (sepIndex === -1) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env exec [--file <.env.sealed>] [--override] -- <command> [args...]\n' +
        '\nThe `--` separator is required to mark where sealed-env flags end\n' +
        'and the command to run begins.',
    );
  }

  const sealedArgs = argv.slice(0, sepIndex);
  const childArgs = argv.slice(sepIndex + 1);

  if (childArgs.length === 0) {
    throw new SealedEnvError('CONFIG_ERROR', 'no command given after `--`');
  }

  const { values } = parseFlags(sealedArgs, {
    file: { type: 'string', default: '.env.sealed' },
    override: { type: 'boolean', default: false },
  });

  const filePath = values.file as string;
  const override = values.override as boolean;

  // Decrypt + parse. decryptSealedFile already throws shell-hint-aware
  // MISSING_KEY errors if env vars are missing.
  const { plaintext } = decryptSealedFile(filePath);
  const { pairs } = parseDotenv(plaintext.toString('utf8'));

  // Build the child env. Defaults to host-wins so an operator can
  // override a single var on the command line:
  //
  //   DATABASE_URL=postgres://staging \
  //     sealed-env exec --file .env.sealed -- node server.js
  //
  // would use the staging URL even if the sealed file declared prod.
  // Pass --override to flip that.
  const childEnv: Record<string, string> = { ...process.env } as Record<string, string>;
  for (const [key, value] of pairs) {
    if (override || childEnv[key] === undefined) {
      childEnv[key] = value;
    }
  }

  // Best-effort wipe of the plaintext buffer. Once the env vars are
  // copied into childEnv, the original buffer is no longer needed.
  plaintext.fill(0);

  const [cmd, ...cmdArgs] = childArgs as [string, ...string[]];

  // shell:false to avoid shell interpolation of args. The user already
  // chose their command and args explicitly.
  const child = spawn(cmd, cmdArgs, {
    env: childEnv,
    stdio: 'inherit',
    shell: false,
  });

  // Forward signals so Ctrl+C in sealed-env reaches the child.
  const forward = (sig: NodeJS.Signals) => () => {
    if (!child.killed) child.kill(sig);
  };
  const sigInt = forward('SIGINT');
  const sigTerm = forward('SIGTERM');
  process.on('SIGINT', sigInt);
  process.on('SIGTERM', sigTerm);

  return new Promise<void>((resolveOuter, rejectOuter) => {
    child.on('error', (err) => {
      process.off('SIGINT', sigInt);
      process.off('SIGTERM', sigTerm);
      rejectOuter(
        new SealedEnvError('CONFIG_ERROR', `failed to launch "${cmd}": ${err.message}`),
      );
    });

    child.on('exit', (code, signal) => {
      process.off('SIGINT', sigInt);
      process.off('SIGTERM', sigTerm);
      if (signal) {
        // Re-raise the signal in this process so the parent shell sees
        // the same exit cause. process.exit alone wouldn't carry it.
        process.kill(process.pid, signal);
      } else {
        process.exitCode = code ?? 0;
      }
      resolveOuter();
    });
  });
}
