/**
 * `sealed-env decrypt <file.env.sealed>` — print plaintext to stdout.
 *
 * IMPORTANT: this writes plaintext to stdout. Use carefully — pipe to your
 * editor or grep, do NOT redirect to a committed file.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { unseal } from '../../core/api.js';
import { SealedEnvError } from '../../core/errors.js';
import { parseSealedFile } from '../../format/parser.js';

export function decryptCommand(argv: string[]): void {
  const input = argv[0];
  if (!input) {
    throw new SealedEnvError('CONFIG_ERROR', 'usage: sealed-env decrypt <file.env.sealed>');
  }
  if (!existsSync(input)) {
    throw new SealedEnvError('CONFIG_ERROR', `file not found: ${input}`);
  }

  const masterKey = readEnvKey('SEALED_ENV_KEY');
  const text = readFileSync(resolve(input), 'utf8');
  const file = parseSealedFile(text);

  const opts: Parameters<typeof unseal>[0] = { file, masterKey };

  if (file.mode === 'team' || file.mode === 'enterprise') {
    opts.signingKey = readEnvKey('SEALED_ENV_SIGNING_KEY');
  }
  if (file.mode === 'enterprise') {
    const t = process.env['SEALED_ENV_UNSEAL_TOKEN'];
    if (!t) {
      throw new SealedEnvError(
        'MISSING_TOKEN',
        'enterprise file requires SEALED_ENV_UNSEAL_TOKEN',
      );
    }
    opts.unsealToken = t;
    if (file.challengeBind === 'enabled') {
      const d = process.env['SEALED_ENV_DEPLOY_ID'];
      if (!d) {
        throw new SealedEnvError(
          'MISSING_TOKEN',
          'challenge-bound file requires SEALED_ENV_DEPLOY_ID',
        );
      }
      opts.deployId = d;
    }
  }

  const plaintext = unseal(opts);
  process.stdout.write(plaintext);
  if (!plaintext.toString('utf8').endsWith('\n')) {
    process.stdout.write('\n');
  }
}

function readEnvKey(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) {
    throw new SealedEnvError('MISSING_KEY', `environment variable ${varName} is required`);
  }
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}
