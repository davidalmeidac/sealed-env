/**
 * `sealed-env get <file.env.sealed> <KEY>` — print ONE variable's value.
 *
 * Use this instead of `decrypt | grep` when you want to inspect a single
 * variable without scrolling the whole plaintext through your terminal.
 *
 *   $ sealed-env get .env.sealed DATABASE_URL
 *   postgresql://demo-user:demo-pass@localhost:5432/demo
 *
 * Exits with code 1 if the key is not found.
 */

import { existsSync } from 'node:fs';

import { SealedEnvError } from '../../core/errors.js';
import { decryptSealedFile, parseDotenv } from '../utils/io.js';

export function getCommand(argv: string[]): void {
  const [input, key] = argv;
  if (!input || !key) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env get <file.env.sealed> <KEY>',
    );
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }

  const { plaintext } = decryptSealedFile(input);
  const { pairs } = parseDotenv(plaintext.toString('utf8'));

  if (!pairs.has(key)) {
    throw new SealedEnvError(
      'MISSING_FIELD',
      `key "${key}" not found in ${input}. Available keys: ${Array.from(pairs.keys()).join(', ')}`,
    );
  }

  // Print the raw value (no `KEY=` prefix). This makes the command
  // composable: `STRIPE_KEY=$(sealed-env get .env.sealed STRIPE_KEY)`.
  process.stdout.write(pairs.get(key)!);
  process.stdout.write('\n');
}
