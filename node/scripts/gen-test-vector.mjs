#!/usr/bin/env node
/**
 * Generates a cross-stack test vector: a Node-sealed file plus the
 * decryption inputs needed to verify it from Java (and vice versa).
 *
 * Output: a single JSON object on stdout, suitable for piping into a
 * Java test harness.
 *
 * Usage:
 *   node scripts/gen-test-vector.mjs [basic|team|enterprise] > vector.json
 */
import { seal } from '../dist/src/index.js';
import { randomBytes } from 'node:crypto';

const mode = (process.argv[2] || 'basic').toLowerCase();
if (!['basic', 'team', 'enterprise'].includes(mode)) {
  console.error(`unknown mode "${mode}"`);
  process.exit(2);
}

const masterKey = Buffer.from('a'.repeat(64), 'hex');
const signingKey = Buffer.from('b'.repeat(64), 'hex');
const totpSecret = randomBytes(20);
const plaintext = 'API_KEY=cross-stack\nDB_URL=postgres://prod\n';

const sealOpts = { plaintext, masterKey, mode };
if (mode === 'team' || mode === 'enterprise') sealOpts.signingKey = signingKey;
if (mode === 'enterprise') {
  sealOpts.totpSecret = totpSecret;
  sealOpts.challengeBind = false;
}

const { serialized } = seal(sealOpts);

const out = {
  mode,
  masterKeyHex: masterKey.toString('hex'),
  signingKeyHex: signingKey.toString('hex'),
  totpSecretHex: totpSecret.toString('hex'),
  plaintext,
  serialized,
};
process.stdout.write(JSON.stringify(out, null, 2) + '\n');
