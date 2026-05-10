#!/usr/bin/env node
/**
 * Generates test-vectors/v1/enterprise-scrypt-N131072.json
 *
 * Uses FIXED keys and deterministic inputs so reruns produce different
 * ciphertext (salt/nonce are random per seal()) but the plaintext/keys
 * are stable for cross-stack validation.
 *
 * Usage: node node/scripts/gen-scrypt-n131072-vector.mjs
 *
 * Run from the repo root.
 */

import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Import compiled sources from dist/src/ (test compile output)
const { seal } = await import('../dist/src/core/api.js');

const masterKeyHex = 'a'.repeat(64);
const masterKey = Buffer.from(masterKeyHex, 'hex');
const plaintext = 'SEC002_TEST=n131072\nDB_HOST=db.example.com\n';

const { serialized } = seal({
  plaintext,
  masterKey,
  mode: 'basic',
  // Do NOT pass scryptParams override — use DEFAULT_SCRYPT_PARAMS (now N=131072)
});

const vector = {
  name: 'enterprise-scrypt-N131072',
  purpose: 'Node-sealed file with N=131072 (OWASP 2024 floor, SEC-002). Java must decrypt this successfully.',
  masterKeyHex,
  plaintext,
  serialized,
};

const outPath = join(here, '..', '..', 'test-vectors', 'v1', 'enterprise-scrypt-N131072.json');
writeFileSync(outPath, JSON.stringify(vector, null, 2) + '\n');
console.log('Written:', outPath);
console.log('Serialized starts with:', serialized.split('\n')[0]);
