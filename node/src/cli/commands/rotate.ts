/**
 * `sealed-env rotate <file.env.sealed>` — re-seal in place with a
 * fresh salt and nonce, without changing the underlying plaintext.
 *
 * Why this exists: the threat model documented in T13 says that a
 * leaked unseal token is bound to the file's salt — a re-seal with a
 * fresh salt invalidates the leaked token. Normal `set` and `edit`
 * already rotate salt as a side effect (every seal generates a new
 * salt). But sometimes you need to rotate the salt WITHOUT changing
 * any value:
 *
 *   - You suspect a token leaked but you can't pinpoint which.
 *   - You're on a regular rotation cadence (e.g. weekly cron).
 *   - You're rotating after offboarding an operator (their old TOTP
 *     code still validates today; rotation invalidates any pre-existing
 *     token they may have minted).
 *
 *   $ sealed-env rotate .env.sealed
 *   ✓ Rotated salt + nonce in .env.sealed
 *     Backup of previous file: .env.sealed.bak
 *     Pre-rotation tokens are now invalid for this file.
 *
 * Backs up to <file>.bak before overwriting, same as set/edit.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { SealedEnvError } from '../../core/errors.js';
import { decryptSealedFile, resealLikeSource, writeSealedFile } from '../utils/io.js';

export function rotateCommand(argv: string[]): void {
  const input = argv[0];
  if (!input) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env rotate <file.env.sealed>',
    );
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }

  const { file: source, plaintext } = decryptSealedFile(input);

  // resealLikeSource calls seal(), which generates a fresh random salt
  // and nonce every time. The plaintext is fed back unchanged.
  const newSealed = resealLikeSource(source, plaintext.toString('utf8'));

  // Defense in depth: zero out the plaintext buffer once we've handed
  // the string to seal(). The string copy is in V8's heap and out of
  // our reach, but the original Buffer is not.
  plaintext.fill(0);

  const absolute = resolve(input);
  writeSealedFile(absolute, newSealed, { preserveBackup: { backupPath: absolute + '.bak' } });

  process.stdout.write(
    [
      `✓ Rotated salt + nonce in ${input}`,
      `  Backup of previous file: ${input}.bak`,
      `  Pre-rotation unseal tokens are now invalid for this file.`,
      '',
    ].join('\n'),
  );
}
