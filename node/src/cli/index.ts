#!/usr/bin/env node
/**
 * sealed-env CLI entry point.
 *
 * @see /SPEC.md
 */

import { initCommand } from './commands/init.js';
import { encryptCommand } from './commands/encrypt.js';
import { decryptCommand } from './commands/decrypt.js';
import { unsealCommand } from './commands/unseal.js';
import { getCommand } from './commands/get.js';
import { setCommand } from './commands/set.js';
import { editCommand } from './commands/edit.js';
import { diffCommand } from './commands/diff.js';
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
      '',
      'Production deploys (enterprise mode only):',
      '  unseal --file <.env.sealed> [--totp <code>] [--deploy-id <sha>] [--ttl 60]',
      '      Generate a short-lived unseal token (60s default).',
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

main();
