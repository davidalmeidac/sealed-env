#!/usr/bin/env node
/**
 * Generates test-vectors/v1/enterprise-token-malformed-epoch.json
 *
 * Produces a signed token whose payload.epoch contains a tab character.
 * Uses FIXED keys (deterministic). The token is re-signed with the derived
 * key so signature validation passes — the vector tests the epoch decode gate.
 *
 * Usage (from repo root): node node/scripts/gen-malformed-epoch-vector.mjs
 *
 * Requires: npm run test:compile (so dist/src/ is populated)
 */

import { createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// Import compiled sources
const { hmacSha256 } = await import('../dist/src/core/crypto.js');

// Fixed keys (same as token-base64-strict test)
const masterKeyHex = 'a'.repeat(64);
const totpSecretHex = 'c'.repeat(40);
const saltHex = '0'.repeat(32); // 16 zero bytes

const masterKey = Buffer.from(masterKeyHex, 'hex');
const totpSecret = Buffer.from(totpSecretHex, 'hex');
const salt = Buffer.from(saltHex, 'hex');

// Derive enterprise epoch: HMAC(totpSecret, salt || "epoch-v1")
const epochTag = Buffer.from('epoch-v1', 'utf8');
const epochInput = Buffer.concat([salt, epochTag]);
const epochBytes = hmacSha256(totpSecret, epochInput);
const epochB64 = epochBytes.toString('base64'); // standard base64, NOT url-safe

// Simulate a derived key (normally deriveMasterKey(masterKey, salt, kdfParams))
// For the vector, use the master key directly as the signing key for simplicity.
// The test only cares that the token is validly signed but epoch is invalid.
// Use HMAC(masterKey, salt) as a simplified derived key for reproducibility.
const derivedKey = hmacSha256(masterKey, salt);

function base64UrlEncode(buf) {
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

const now = Math.floor(Date.now() / 1000);
const header = { alg: 'HS256', typ: 'sealed-env-unseal/v1' };
const payload = {
  iss: 'sealed-env-cli',
  iat: now,
  exp: now + 3600, // 1 hour so the vector is testable for a while
  // TAB injected before the base64 epoch
  epoch: '\t' + epochB64,
  deploy_id: null,
  ops_id: 'gen-vector-fixed-ops-id',
};

const hB64 = base64UrlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
const pB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
const signingInput = Buffer.from(`${hB64}.${pB64}`, 'utf8');
const sig = hmacSha256(derivedKey, signingInput);

const token = `usl_${hB64}.${pB64}.${base64UrlEncode(sig)}`;

const vector = {
  name: 'enterprise-token-malformed-epoch',
  purpose: 'Token whose payload.epoch contains a tab character (invalid base64). ' +
    'All stacks MUST reject with TOKEN_INVALID (or stack-equivalent).',
  masterKeyHex,
  totpSecretHex,
  saltHex,
  derivedKeyHex: derivedKey.toString('hex'),
  token,
  expectedError: 'TOKEN_INVALID',
};

const outPath = join(here, '..', '..', 'test-vectors', 'v1', 'enterprise-token-malformed-epoch.json');
writeFileSync(outPath, JSON.stringify(vector, null, 2) + '\n');
console.log('Written:', outPath);
console.log('Token starts with:', token.substring(0, 30) + '...');
