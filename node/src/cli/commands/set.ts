/**
 * `sealed-env set <file.env.sealed> <KEY> <VALUE>` — change one variable
 * and re-seal in place. Other keys, comments, and blank lines are
 * preserved.
 *
 *   $ sealed-env set .env.sealed STRIPE_KEY "sk_live_..."
 *
 * The plaintext is never written to disk during this operation — it
 * lives in process memory only, and only the new sealed file is
 * written. Backs up the previous sealed file as <file>.bak before
 * overwriting.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { SealedEnvError } from '../../core/errors.js';
import {
  decryptSealedFile,
  parseDotenv,
  resealLikeSource,
  serializeDotenv,
  writeSealedFile,
} from '../utils/io.js';

export function setCommand(argv: string[]): void {
  const [input, key, ...valueParts] = argv;
  if (!input || !key || valueParts.length === 0) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env set <file.env.sealed> <KEY> <VALUE>',
    );
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new SealedEnvError('CONFIG_ERROR', `invalid key name: "${key}"`);
  }
  // Recompose the value in case the shell split on spaces (handle case
  // where the user didn't quote it). Best practice is to quote, but be
  // forgiving.
  const value = valueParts.join(' ');

  const { file: source, plaintext } = decryptSealedFile(input);
  const { pairs, rawLines } = parseDotenv(plaintext.toString('utf8'));

  const previous = pairs.get(key);
  pairs.set(key, value);

  const newPlaintext = serializeDotenv(pairs, rawLines);
  const newSealed = resealLikeSource(source, newPlaintext);

  const absolute = resolve(input);
  writeSealedFile(absolute, newSealed, { preserveBackup: { backupPath: absolute + '.bak' } });

  process.stdout.write(
    [
      `✓ ${previous === undefined ? 'Added' : 'Updated'} ${key} in ${input}`,
      `  Backup of previous file: ${input}.bak`,
      '',
    ].join('\n'),
  );
}
