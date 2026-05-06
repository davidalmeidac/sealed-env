#!/usr/bin/env node
/**
 * sealed-env CLI entry point.
 *
 * Subcommands:
 *   init        Generate master key and create .env.sealed structure.
 *   encrypt     Encrypt a plaintext .env into .env.sealed.
 *   decrypt     Print the plaintext to stdout (no disk write).
 *   edit        Open $EDITOR with the plaintext, re-seal on save.
 *   unseal      Generate an unseal token (enterprise mode).
 *   rotate      Rotate the master key, re-encrypt the file.
 *   upgrade     Change the mode of an existing file.
 *   help        Print this help.
 *
 * @see /SPEC.md
 */

import { initCommand } from './commands/init.js';
import { encryptCommand } from './commands/encrypt.js';
import { decryptCommand } from './commands/decrypt.js';
import { unsealCommand } from './commands/unseal.js';
import { SealedEnvError } from '../core/errors.js';

const COMMANDS: Record<string, (argv: string[]) => Promise<void> | void> = {
  init: initCommand,
  encrypt: encryptCommand,
  decrypt: decryptCommand,
  unseal: unsealCommand,
  help: helpCommand,
};

async function main(): Promise<void> {
  const [, , cmd = 'help', ...rest] = process.argv;
  const handler = COMMANDS[cmd];
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
      'Commands:',
      '  init [--mode <basic|team|enterprise>] [--dir .]',
      '  encrypt <input.env> [--out .env.sealed] [--mode <basic|team|enterprise>]',
      '  decrypt <file.env.sealed>',
      '  unseal --file <.env.sealed> [--totp <code>] [--deploy-id <sha>] [--ttl 60]',
      '  help',
      '',
      'Required environment variables:',
      '  SEALED_ENV_KEY          (all modes)',
      '  SEALED_ENV_SIGNING_KEY  (team, enterprise)',
      '  SEALED_ENV_TOTP_SECRET  (enterprise: only for `unseal` cmd)',
      '  SEALED_ENV_UNSEAL_TOKEN (enterprise: at runtime to decrypt)',
      '  SEALED_ENV_DEPLOY_ID    (enterprise: when challenge-bind=enabled)',
      '',
      'Documentation: https://github.com/davidalmeidac/sealed-env',
      '',
    ].join('\n'),
  );
}

main();
