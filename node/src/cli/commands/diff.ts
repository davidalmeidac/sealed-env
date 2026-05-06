/**
 * `sealed-env diff <old.env.sealed> <new.env.sealed>` — show what
 * changed between two sealed files. By default the actual values are
 * NOT printed — the output shows which keys were added, removed, or
 * changed without leaking the secrets.
 *
 *   $ sealed-env diff .env.sealed.bak .env.sealed
 *   ~ STRIPE_KEY        (changed)
 *   + NEW_FEATURE_FLAG  (added)
 *   - OLD_VAR           (removed)
 *
 * Pass --show-values to print before/after for each changed key.
 *
 *   $ sealed-env diff old new --show-values
 *
 * Exits with code 0 if files are identical, 1 if they differ.
 */

import { existsSync } from 'node:fs';

import { SealedEnvError } from '../../core/errors.js';
import { decryptSealedFile, parseDotenv } from '../utils/io.js';
import { parseFlags } from '../utils/flags.js';

export function diffCommand(argv: string[]): void {
  const { values, positional } = parseFlags(argv, {
    'show-values': { type: 'boolean', default: false },
  });
  const [oldPath, newPath] = positional;
  if (!oldPath || !newPath) {
    throw new SealedEnvError(
      'CONFIG_ERROR',
      'usage: sealed-env diff <old.env.sealed> <new.env.sealed> [--show-values]',
    );
  }
  for (const p of [oldPath, newPath]) {
    if (!existsSync(p)) {
      throw new SealedEnvError('CONFIG_ERROR', `file not found: ${p}`);
    }
  }

  const showValues = !!values['show-values'];

  const oldDecrypted = decryptSealedFile(oldPath);
  const newDecrypted = decryptSealedFile(newPath);
  const oldPairs = parseDotenv(oldDecrypted.plaintext.toString('utf8')).pairs;
  const newPairs = parseDotenv(newDecrypted.plaintext.toString('utf8')).pairs;

  const allKeys = new Set([...oldPairs.keys(), ...newPairs.keys()]);
  const added: string[] = [];
  const removed: string[] = [];
  const changed: { key: string; before: string; after: string }[] = [];

  for (const key of [...allKeys].sort()) {
    const before = oldPairs.get(key);
    const after = newPairs.get(key);
    if (before === undefined && after !== undefined) added.push(key);
    else if (before !== undefined && after === undefined) removed.push(key);
    else if (before !== after) changed.push({ key, before: before!, after: after! });
  }

  if (added.length === 0 && removed.length === 0 && changed.length === 0) {
    process.stdout.write('No differences. The two files have identical key/value pairs.\n');
    return;
  }

  // Find the longest key name for column alignment.
  const longest = Math.max(
    0,
    ...added.map((k) => k.length),
    ...removed.map((k) => k.length),
    ...changed.map((c) => c.key.length),
  );

  const lines: string[] = [];
  for (const key of changed) {
    if (showValues) {
      lines.push(`~ ${key.key.padEnd(longest)}  (changed)`);
      lines.push(`    -  ${redactIfLong(key.before)}`);
      lines.push(`    +  ${redactIfLong(key.after)}`);
    } else {
      lines.push(`~ ${key.key.padEnd(longest)}  (changed)`);
    }
  }
  for (const key of added) {
    if (showValues) {
      lines.push(`+ ${key.padEnd(longest)}  (added)`);
      lines.push(`    +  ${redactIfLong(newPairs.get(key)!)}`);
    } else {
      lines.push(`+ ${key.padEnd(longest)}  (added)`);
    }
  }
  for (const key of removed) {
    if (showValues) {
      lines.push(`- ${key.padEnd(longest)}  (removed)`);
      lines.push(`    -  ${redactIfLong(oldPairs.get(key)!)}`);
    } else {
      lines.push(`- ${key.padEnd(longest)}  (removed)`);
    }
  }

  process.stdout.write(lines.join('\n') + '\n');

  if (!showValues) {
    process.stdout.write(
      '\n(Pass --show-values to see the actual before/after values.)\n',
    );
  }

  process.exitCode = 1;
}

/** Long strings (> 60 chars) are truncated for terminal sanity. */
function redactIfLong(s: string): string {
  if (s.length <= 60) return s;
  return s.substring(0, 60) + '… [truncated]';
}
