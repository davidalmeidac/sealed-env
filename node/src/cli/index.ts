#!/usr/bin/env node
/**
 * sealed-env CLI entry point.
 *
 * @see /SPEC.md
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { initCommand } from './commands/init.js';
import { encryptCommand } from './commands/encrypt.js';
import { decryptCommand } from './commands/decrypt.js';
import { unsealCommand } from './commands/unseal.js';
import { getCommand } from './commands/get.js';
import { setCommand } from './commands/set.js';
import { editCommand } from './commands/edit.js';
import { diffCommand } from './commands/diff.js';
import { doctorCommand } from './commands/doctor.js';
import { execCommand } from './commands/exec.js';
import { rotateCommand } from './commands/rotate.js';
import { SealedEnvError } from '../core/errors.js';

const COMMANDS: Record<string, (argv: string[]) => Promise<void> | void> = {
  init: initCommand,
  encrypt: encryptCommand,
  decrypt: decryptCommand,
  get: getCommand,
  set: setCommand,
  edit: editCommand,
  diff: diffCommand,
  unseal: unsealCommand,
  exec: execCommand,
  rotate: rotateCommand,
  doctor: doctorCommand,
  help: helpCommand,
  version: versionCommand,
};

async function main(): Promise<void> {
  // Top-level --version / -v / --help / -h handling, before the
  // sub-command dispatcher. This lets `sealed-env --version` work the
  // way users expect from any modern CLI.
  const argv = process.argv.slice(2);
  if (argv.length > 0 && (argv[0] === '--version' || argv[0] === '-v' || argv[0] === '-V')) {
    versionCommand();
    return;
  }
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    helpCommand();
    return;
  }

  const [cmd, ...rest] = argv;
  const handler = COMMANDS[cmd!];
  if (!handler) {
    process.stderr.write(`sealed-env: unknown command "${cmd}"\n\n`);
    helpCommand();
    process.exitCode = 1;
    return;
  }

  try {
    await handler(rest);
  } catch (e) {
    if (e instanceof SealedEnvError) {
      process.stderr.write(`sealed-env [${e.code}]: ${e.message}\n`);
      process.exitCode = 1;
      return;
    }
    process.stderr.write(`sealed-env: unexpected error\n  ${(e as Error).message}\n`);
    process.exitCode = 2;
    return;
  }
}

function helpCommand(): void {
  process.stdout.write(
    [
      'sealed-env — encrypted .env files with optional TOTP unsealing',
      '',
      'Usage:',
      '  sealed-env <command> [options]',
      '',
      'Set up:',
      '  init [--mode <basic|team|enterprise>] [--dir .]',
      '      Generate keys and create .env.sealed structure.',
      '',
      'Encrypt / decrypt:',
      '  encrypt <input.env> [--out <path>] [--mode <basic|team|enterprise>]',
      '      Seal a plaintext .env file.',
      '  decrypt <file.env.sealed>',
      '      Print the full plaintext to stdout. Use carefully — pipe',
      '      to grep or your editor; do NOT redirect to a committed file.',
      '',
      'Inspect / modify (operational):',
      '  get <file.env.sealed> <KEY>',
      '      Print ONE variable. Composable: VAR=$(sealed-env get f.sealed VAR).',
      '  set <file.env.sealed> <KEY> <VALUE>',
      '      Update or add ONE variable, re-seal in place. Backs up to <file>.bak.',
      '  edit <file.env.sealed>',
      '      Open $EDITOR with the plaintext (in tmpfs when available),',
      '      re-seal on save. Backs up to <file>.bak.',
      '  diff <old.env.sealed> <new.env.sealed> [--show-values]',
      '      Show which keys were added/removed/changed. Values are',
      '      hidden by default; pass --show-values to reveal them.',
      '  rotate <file.env.sealed>',
      '      Re-seal with a fresh salt + nonce without changing values.',
      '      Invalidates any unseal tokens previously minted for this file.',
      '      Use after a suspected token leak or on a regular cadence.',
      '',
      'Run a command with sealed env vars injected:',
      '  exec [--file <.env.sealed>] [--override] -- <command> [args...]',
      '      Decrypt the file in memory and run <command> with each',
      '      KEY=value injected into its environment. The plaintext',
      '      never lands on disk. Host env wins by default; pass',
      '      --override to let the sealed file win. Forwards Ctrl+C',
      '      and propagates the child exit code.',
      '',
      '      Example:  sealed-env exec --file .env.sealed -- node server.js',
      '',
      'Production deploys (enterprise mode only):',
      '  unseal --file <.env.sealed> [--totp <code>] [--deploy-id <sha>] [--ttl 60]',
      '      Generate a short-lived unseal token (60s default).',
      '',
      'Diagnostics:',
      '  doctor [<file.env.sealed>]',
      '      Validate your env vars, file, and roundtrip without printing',
      '      any secret values. Safe to paste into a CI log or support thread.',
      '',
      'Other:',
      '  --version, -v       Print sealed-env version.',
      '  --help, -h          Print this help.',
      '',
      'Required environment variables:',
      '  SEALED_ENV_KEY          (all modes — master key, hex or base64)',
      '  SEALED_ENV_SIGNING_KEY  (team, enterprise)',
      '  SEALED_ENV_TOTP_SECRET  (enterprise: at "encrypt" / "set" / "edit" time, base32)',
      '  SEALED_ENV_UNSEAL_TOKEN (enterprise: at "decrypt" / "get" / "set" / "edit" time)',
      '  SEALED_ENV_DEPLOY_ID    (enterprise: when CHALLENGE-BIND=enabled)',
      '',
      'Documentation: https://github.com/davidalmeidac/sealed-env',
      '',
    ].join('\n'),
  );
}

/**
 * Print the package version. Reads from package.json so we don't need
 * a build step to keep it in sync. The package.json sits at the
 * package root, two levels above this file (dist/cli/index.js).
 */
function versionCommand(): void {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/cli/index.js → dist/.. → package.json
    const pkgPath = resolve(here, '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };
    process.stdout.write(`sealed-env ${pkg.version}\n`);
  } catch {
    // Defensive fallback so --version never crashes. Shouldn't happen
    // unless the package was assembled in an unusual way.
    process.stdout.write('sealed-env (version unknown)\n');
  }
}

main();
