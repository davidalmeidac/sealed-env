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
import { deployCommand } from './commands/deploy.js';
import { keychainCommand } from './commands/keychain.js';
import { autoloadSealedEnvLocal } from './utils/io.js';
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
  deploy: deployCommand,
  rotate: rotateCommand,
  keychain: keychainCommand,
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

  // Auto-load `SEALED_ENV_*` variables from `.env.local` in the current
  // directory if it exists. CI / explicit env vars always win; this only
  // fills in what's missing. Skipped for `init` (which CREATES that file
  // and shouldn't be influenced by an existing one) and for `version` /
  // `help` (which don't touch keys at all).
  const skipAutoload =
    cmd === 'init' || cmd === 'version' || cmd === 'help' || cmd === 'keychain';
  if (!skipAutoload && process.env['SEALED_ENV_NO_AUTOLOAD'] !== '1') {
    const { loaded, source } = autoloadSealedEnvLocal();
    if (loaded > 0) {
      process.stderr.write(
        `(loaded ${loaded} SEALED_ENV_* var${loaded === 1 ? '' : 's'} from ${source})\n`,
      );
    }
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
      '  exec [--file <path>] [--override] [--totp <code>] [--deploy-id <sha>] -- <command>',
      '      Decrypt the file in memory and run <command> with each',
      '      KEY=value injected into its environment. The plaintext',
      '      never lands on disk. Host env wins by default; pass',
      '      --override to let the sealed file win. Forwards Ctrl+C',
      '      and propagates the child exit code. For enterprise files,',
      '      mints the unseal token in memory (TOTP prompt or --totp).',
      '',
      '      Example:  sealed-env exec --file .env.sealed -- node server.js',
      '',
      'Production deploy (recommended over hand-rolled deploy.sh):',
      '  deploy [--file <path>] [--health-url <url>] [--health-timeout <s>] -- <command>',
      '      Wraps `exec` with deploy-time safety rails: auto-detects',
      '      deploy_id from `git rev-parse HEAD`, refuses dirty trees,',
      '      and optionally polls a health endpoint after the command.',
      '',
      '      Example:',
      '        sealed-env deploy --health-url http://127.0.0.1:8090/actuator/health \\',
      '          -- docker compose up -d --build status',
      '',
      'Production deploys (manual token mint):',
      '  unseal --file <.env.sealed> [--totp <code>] [--deploy-id <sha>] [--ttl 60] [--token-only]',
      '      Generate a short-lived unseal token (60s default).',
      '      --token-only prints just the token (no surrounding text)',
      '      for shell scripts: TOKEN=$(sealed-env unseal --token-only ...)',
      '',
      'Hardened key storage (optional, more secure than .env.local):',
      '  keychain push',
      '      Move SEALED_ENV_* from .env.local to the OS keychain',
      '      (Windows Credential Manager / macOS Keychain / libsecret).',
      '      Auto-load picks them up automatically afterwards.',
      '  keychain pull',
      '      Write keychain secrets back to .env.local (migration).',
      '  keychain status',
      '      Show which entries are stored (no values printed).',
      '  keychain clear',
      '      Remove all sealed-env entries from the keychain.',
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
