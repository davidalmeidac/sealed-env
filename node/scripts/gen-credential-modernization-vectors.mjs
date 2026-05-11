#!/usr/bin/env node
/**
 * Generates the 11 byte-identical credential-modernization test vectors:
 *
 *   test-vectors/v1/credential-modernization-*.json
 *
 * The output of this script is the cross-stack contract: Node, Java, and
 * Rust (sister `sealed-env-studio` repo) MUST reproduce every byte of every
 * token and every fixture from these same inputs.
 *
 * No npm dependencies. A tiny deterministic CBOR encoder (RFC 8949 §4.2.1)
 * lives inline. Self-checks run before writing.
 *
 * Usage (from repo root):
 *   node node/scripts/gen-credential-modernization-vectors.mjs
 *
 * Doc-only PR — the runtime that consumes these tokens does not yet exist
 * in any stack. The fixtures freeze the contract before implementation.
 */

import { createHmac, createHash, hkdfSync, scryptSync } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', '..', 'test-vectors', 'v1');

// ---------------------------------------------------------------------------
// Fixed test material (SPEC §12.10 — all stacks share these constants)
// ---------------------------------------------------------------------------

const MASTER_KEY = Buffer.alloc(32, 0xaa);
const SIGNING_KEY = Buffer.alloc(32, 0xbb);
const TOTP_SECRET = Buffer.alloc(20, 0xcc);
const SALT = Buffer.alloc(16, 0x00);
const TIER_B_NONCE = Buffer.alloc(16, 0x11);
const EXP_FUTURE = 4102444800; // 2100-01-01T00:00:00Z
const EXP_PAST = 1000000000; // 2001-09-09

// ---------------------------------------------------------------------------
// Minimal deterministic CBOR encoder (RFC 8949 §4.2.1)
// Supports: uint (mt 0), bstr (mt 2), tstr (mt 3), null, definite-length map (mt 5)
// ---------------------------------------------------------------------------

function encodeHead(majorType, value) {
  const mt = majorType << 5;
  if (value < 24) return Buffer.from([mt | value]);
  if (value < 0x100) return Buffer.from([mt | 24, value]);
  if (value < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  if (value < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(value, 1);
    return b;
  }
  // 64-bit
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  const hi = Math.floor(value / 0x100000000);
  const lo = value >>> 0;
  b.writeUInt32BE(hi, 1);
  b.writeUInt32BE(lo, 5);
  return b;
}

function encodeUint(n) {
  if (n < 0 || !Number.isFinite(n)) throw new Error(`bad uint: ${n}`);
  return encodeHead(0, n);
}

function encodeBstr(buf) {
  return Buffer.concat([encodeHead(2, buf.length), buf]);
}

function encodeTstr(s) {
  const u = Buffer.from(s, 'utf8');
  return Buffer.concat([encodeHead(3, u.length), u]);
}

function encodeNull() {
  return Buffer.from([0xf6]);
}

function encodeValue(v) {
  if (v === null) return encodeNull();
  if (Buffer.isBuffer(v)) return encodeBstr(v);
  if (typeof v === 'number') return encodeUint(v);
  if (typeof v === 'string') return encodeTstr(v);
  throw new Error(`unsupported CBOR value: ${typeof v}`);
}

function encodeMap(obj) {
  // Sort keys by bytewise lexicographic order of their canonical CBOR
  // encoding (RFC 8949 §4.2.1). For text-string keys: shorter first, then
  // lex on the UTF-8 bytes — see SPEC §11.5.
  const entries = Object.keys(obj).map((k) => {
    const keyBytes = encodeTstr(k);
    const valBytes = encodeValue(obj[k]);
    return { k, keyBytes, valBytes };
  });
  entries.sort((a, b) => Buffer.compare(a.keyBytes, b.keyBytes));
  const head = encodeHead(5, entries.length);
  return Buffer.concat([head, ...entries.flatMap((e) => [e.keyBytes, e.valBytes])]);
}

function cborEncode(obj) {
  return encodeMap(obj);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TOKEN_CHECKSUM_KEY = Buffer.from('sealed-env:token-checksum:v1', 'utf8');
const VAULT_ID_PREFIX = Buffer.from('sealed-env:vault-id:v1', 'utf8');
const DEPLOY_SIG_INFO = Buffer.from('sealed-env:deploy-sig:v1', 'utf8');
const EPOCH_INFO = Buffer.from('epoch-v1', 'utf8');
const UNSEAL_TOKEN_KEY_INFO = Buffer.from('sealed-env:unseal-token-key:v1', 'utf8');

// scrypt params — match sealed-env 0.1.1 default (SEC-002 OWASP 2024 floor).
// Fixtures pin these so any stack can re-derive ek byte-identically.
const SCRYPT_N = 131072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
// scryptSync needs maxmem >= 128 * N * r bytes. For N=131072, r=8 → 128 MiB.
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

function scryptDerive(masterKey, salt) {
  return scryptSync(masterKey, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

function base64url(buf) {
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function hmacSha256(key, msg) {
  return createHmac('sha256', key).update(msg).digest();
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

function hkdfSha256(ikm, salt, info, length) {
  // Node hkdfSync returns ArrayBuffer; wrap as Buffer for consistency.
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
}

function vaultId(salt) {
  return sha256(Buffer.concat([VAULT_ID_PREFIX, salt]));
}

function tokenChecksum(payloadText) {
  const mac = hmacSha256(TOKEN_CHECKSUM_KEY, Buffer.from(payloadText, 'utf8'));
  return mac.subarray(0, 2).toString('hex');
}

function mintToken(mode, payloadObj) {
  const payloadText = base64url(cborEncode(payloadObj));
  const cksum = tokenChecksum(payloadText);
  return `sealed_env_${mode}_${cksum}_${payloadText}`;
}

function corruptChecksum(token) {
  // Flip one nibble in the checksum so the typo-detection path triggers.
  const parts = token.split('_');
  const cksum = parts[3];
  const flipped = (cksum[0] === 'f' ? '0' : 'f') + cksum.slice(1);
  parts[3] = flipped;
  return parts.join('_');
}

function tamperPayload(token) {
  // Flip the LAST byte of the base64url payload string. Re-derive the
  // checksum so the token survives the §11.4 gate and reaches the §12.7
  // sig-verification gate.
  const parts = token.split('_');
  const payloadText = parts[4];
  const lastChar = payloadText[payloadText.length - 1];
  const newLast = lastChar === 'A' ? 'B' : 'A';
  const tampered = payloadText.slice(0, -1) + newLast;
  parts[4] = tampered;
  parts[3] = tokenChecksum(tampered);
  return parts.join('_');
}

// ---------------------------------------------------------------------------
// Tier B deploy-token construction (SPEC §12.5)
// ---------------------------------------------------------------------------

function buildTierBToken({ masterKey, salt, exp, nonce, overrideVaultId }) {
  // ek = derived_key per SPEC §12.5 (locked option A). Fixtures use the
  // 0.1.1 default scrypt params (N=131072, r=8, p=1) so any conformant
  // stack can re-derive ek byte-for-byte from masterKey + salt + the
  // fixture's vault.kdf_params.
  const ek = scryptDerive(masterKey, salt);
  const vid = overrideVaultId ?? vaultId(salt);
  const payloadNoSig = cborEncode({ ek, exp, nonce, vault_id: vid });
  const hmacKey = hkdfSha256(masterKey, salt, DEPLOY_SIG_INFO, 32);
  const sig = hmacSha256(hmacKey, payloadNoSig);
  return mintToken('d', { ek, exp, sig, nonce, vault_id: vid });
}

// Builds a u-mode token: wire-form re-wrap of the legacy JWS Compact
// unseal token (SPEC §9 + §11.6). The CBOR payload carries the same
// fields as the JWS payload plus the JWS signature as a separate
// byte string. Reading and writing is lossless (§11.6).
function buildUnsealToken({
  masterKey,
  signingKey,
  totpSecret,
  salt,
  iss = 'sealed-env-cli',
  iat,
  exp,
  deployId = null,
  opsId,
}) {
  // enterprise_epoch is bound to (totpSecret, salt) per SPEC §9.
  const enterpriseEpoch = hmacSha256(totpSecret, Buffer.concat([salt, EPOCH_INFO]));
  // The legacy JWS unseal-token-key is HKDF(derived_key, ...). We use the
  // signingKey as an additional ingredient to bind team/enterprise scope.
  const derivedKey = scryptDerive(masterKey, salt);
  const tokenKey = hkdfSha256(
    Buffer.concat([derivedKey, signingKey]),
    salt,
    UNSEAL_TOKEN_KEY_INFO,
    32,
  );
  // Construct the JWS header + payload that the legacy verifier would
  // sign. Sig is HMAC over base64url(header)+"."+base64url(payload).
  const header = { alg: 'HS256', typ: 'sealed-env-unseal/v1' };
  const payload = {
    iss,
    iat,
    exp,
    epoch: enterpriseEpoch.toString('base64'),
    deploy_id: deployId,
    ops_id: opsId,
  };
  const hB64 = base64url(Buffer.from(JSON.stringify(header), 'utf8'));
  const pB64 = base64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = Buffer.from(`${hB64}.${pB64}`, 'utf8');
  const sig = hmacSha256(tokenKey, signingInput);
  // Re-wrap into CBOR per §11.6 u-mode. Encoder sorts keys per RFC 8949
  // §4.2.1 → exp, iat, iss, sig, epoch, ops_id, deploy_id.
  return mintToken('u', {
    iss,
    iat,
    exp,
    epoch: payload.epoch, // text string (standard base64 of 32 bytes)
    deploy_id: deployId,
    ops_id: opsId,
    sig,
  });
}

// ---------------------------------------------------------------------------
// Self-checks (run BEFORE writing fixtures)
// ---------------------------------------------------------------------------

function assertEqual(a, b, label) {
  if (Buffer.isBuffer(a) && Buffer.isBuffer(b)) {
    if (!a.equals(b)) {
      throw new Error(`assertion failed: ${label} (bytes differ)`);
    }
    return;
  }
  if (a !== b) throw new Error(`assertion failed: ${label}: ${a} !== ${b}`);
}

function runSelfChecks() {
  // 1. CBOR encoder is deterministic across two calls on equivalent maps.
  const m1 = cborEncode({ m: MASTER_KEY, s: SIGNING_KEY, t: TOTP_SECRET });
  const m2 = cborEncode({ t: TOTP_SECRET, m: MASTER_KEY, s: SIGNING_KEY });
  assertEqual(m1, m2, 'CBOR encoder ignores JS insertion order');

  // 2. Tier B token mint is deterministic across two calls with identical input.
  const t1 = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  const t2 = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  assertEqual(t1, t2, 'Tier B token mint is deterministic');

  // 3. Checksum gate fires for corrupted token.
  const good = mintToken('b', { m: MASTER_KEY });
  const bad = corruptChecksum(good);
  if (good === bad) throw new Error('corruptChecksum did not change the token');
  if (tokenChecksum(bad.split('_')[4]) === bad.split('_')[3]) {
    throw new Error('corruptChecksum produced a still-valid checksum');
  }

  // 4. Canonical key order for Tier B is ek, exp, sig, nonce, vault_id —
  //    verify by decoding the head bytes of the payload.
  const tierB = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  const payloadBytes = Buffer.from(
    tierB.split('_')[4].replace(/-/g, '+').replace(/_/g, '/') +
      '==='.slice((tierB.split('_')[4].length + 3) % 4),
    'base64',
  );
  // First byte is map header 0xa5 (mt 5, 5 entries). Then keys in order.
  assertEqual(payloadBytes[0], 0xa5, 'CBOR map header for 5-entry map');
  // Second byte is the head of first key: tstr-2 ("ek") = 0x62.
  assertEqual(payloadBytes[1], 0x62, 'first key has length 2 (must be "ek")');

  // 5. u-mode token mint is deterministic with fixed inputs (no Date.now()).
  const u1 = buildUnsealToken({
    masterKey: MASTER_KEY,
    signingKey: SIGNING_KEY,
    totpSecret: TOTP_SECRET,
    salt: SALT,
    iat: 1767225600,
    exp: 4102444800,
    deployId: null,
    opsId: 'fixture-u-mode-ops-id-v1',
  });
  const u2 = buildUnsealToken({
    masterKey: MASTER_KEY,
    signingKey: SIGNING_KEY,
    totpSecret: TOTP_SECRET,
    salt: SALT,
    iat: 1767225600,
    exp: 4102444800,
    deployId: null,
    opsId: 'fixture-u-mode-ops-id-v1',
  });
  assertEqual(u1, u2, 'u-mode token mint is deterministic');

  // 6. u-mode canonical key order per §11.6 is exp, iat, iss, sig, epoch,
  //    ops_id, deploy_id. Verify the head bytes of the CBOR payload.
  const uPayloadBytes = Buffer.from(
    u1.split('_')[4].replace(/-/g, '+').replace(/_/g, '/') +
      '==='.slice((u1.split('_')[4].length + 3) % 4),
    'base64',
  );
  // Map of 7 entries (one fewer than 8 → still major-type-5 short-form 0xa7).
  assertEqual(uPayloadBytes[0], 0xa7, 'CBOR map header for 7-entry u-mode payload');
  // First key is "exp" (length 3) → 0x63.
  assertEqual(uPayloadBytes[1], 0x63, 'u-mode first key has length 3 (must be "exp")');
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

const FIXED_PLAINTEXT = 'API_KEY=cross-stack\nDB_URL=postgres://prod\n';
const FIXED_PLAINTEXT_HEX = Buffer.from(FIXED_PLAINTEXT, 'utf8').toString('hex');

function vaultStubBasic() {
  return {
    salt_hex: SALT.toString('hex'),
    master_key_hex: MASTER_KEY.toString('hex'),
    kdf: 'scrypt',
    kdf_params: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    serialized: '<see test-vectors/v1/node-basic.json — same fixed keys + plaintext>',
  };
}
function vaultStubTeam() {
  return {
    ...vaultStubBasic(),
    signing_key_hex: SIGNING_KEY.toString('hex'),
  };
}
function vaultStubEnterprise() {
  return {
    ...vaultStubTeam(),
    totp_secret_hex: TOTP_SECRET.toString('hex'),
  };
}

function basicValid() {
  const token = mintToken('b', { m: MASTER_KEY });
  return {
    name: 'credential-modernization-basic-valid',
    purpose: 'Happy path for §11.6 mode "b": single master key, decrypt OK.',
    spec_section: '§11.6, §11.7',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'decrypt_ok',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
    },
  };
}

function teamValid() {
  const token = mintToken('t', { m: MASTER_KEY, s: SIGNING_KEY });
  return {
    name: 'credential-modernization-team-valid',
    purpose: 'Happy path for §11.6 mode "t": master + signing, decrypt OK.',
    spec_section: '§11.6, §11.7',
    vault: vaultStubTeam(),
    token,
    config_file_contents: null,
    expected: {
      result: 'decrypt_ok',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
    },
  };
}

function enterpriseValid() {
  const token = mintToken('e', { m: MASTER_KEY, s: SIGNING_KEY, t: TOTP_SECRET });
  return {
    name: 'credential-modernization-enterprise-valid',
    purpose: 'Happy path for §11.6 mode "e": Tier A unlock with master+signing+totp.',
    spec_section: '§11.6, §11.7',
    vault: vaultStubEnterprise(),
    token,
    config_file_contents: null,
    expected: {
      result: 'decrypt_ok',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
    },
  };
}

function tierBDeployValid() {
  const token = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  return {
    name: 'credential-modernization-tier-b-deploy-valid',
    purpose: 'Happy path for §12.5-§12.7 Tier B deploy token: vault_id matches, sig verifies, exp future.',
    spec_section: '§12.5, §12.6, §12.7',
    vault: vaultStubBasic(),
    token,
    config_file_contents: JSON.stringify(
      {
        deploy_mode: 'ephemeral',
        deploy_ttl_max_seconds: 60,
        require_totp_on_mint: false,
        allow_long_lived_for_dev: true,
        nonce_state_backend: null,
      },
      null,
      2,
    ),
    expected: {
      result: 'decrypt_ok',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
    },
  };
}

function unsealValid() {
  // u-mode is a non-breaking wire-form re-wrap of the legacy JWS Compact
  // unseal token (SPEC §9 + §11.6). Present in 0.3.0 to bridge legacy
  // verifiers that still parse base64url(header).base64url(payload).sig
  // with the new unified token envelope. Bytes are testable forever:
  // iat/exp/ops_id are fixed so the token doesn't depend on Date.now().
  const token = buildUnsealToken({
    masterKey: MASTER_KEY,
    signingKey: SIGNING_KEY,
    totpSecret: TOTP_SECRET,
    salt: SALT,
    iat: 1767225600, // 2026-01-01T00:00:00Z
    exp: 4102444800, // 2100-01-01T00:00:00Z
    deployId: null,
    opsId: 'fixture-u-mode-ops-id-v1',
  });
  return {
    name: 'credential-modernization-unseal-valid',
    purpose: 'Happy path for §11.6 mode "u": legacy-compat wrap of a JWS unseal token, decodes to the same JWS payload bytes the §9 verifier accepts.',
    spec_section: '§9, §11.6, §11.7',
    vault: vaultStubEnterprise(),
    token,
    config_file_contents: null,
    expected: {
      result: 'decrypt_ok',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
      legacy_compat_note: 'A conformant stack MUST be able to losslessly serialize the CBOR payload back to the JWS Compact wire form documented in §9. The token sig (HMAC over base64url(header)+"."+base64url(payload)) is the EXACT byte sequence a §9 verifier would compute.',
    },
  };
}

function wrongChecksum() {
  const good = mintToken('b', { m: MASTER_KEY });
  const token = corruptChecksum(good);
  return {
    name: 'credential-modernization-wrong-checksum',
    purpose: 'Typo-detection gate per §11.4 fires before any decode/crypto.',
    spec_section: '§11.4, §11.7 step 6',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'reject_pre_decrypt',
      error_class: 'TOKEN_INVALID',
      error_cause: 'checksum-mismatch',
    },
  };
}

function tamperedPayload() {
  const good = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  const token = tamperPayload(good);
  return {
    name: 'credential-modernization-tampered-payload',
    purpose: 'Tier B payload flipped one byte; checksum re-derived so we reach §12.7 step 8 sig verify and reject there.',
    spec_section: '§12.5, §12.7 step 8',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'reject_sig_fail',
      error_class: 'TOKEN_INVALID',
      error_cause: 'sig',
    },
  };
}

function wrongVaultId() {
  const otherSalt = Buffer.alloc(16, 0x99);
  const token = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
    overrideVaultId: vaultId(otherSalt),
  });
  return {
    name: 'credential-modernization-wrong-vault-id',
    purpose: 'Tier B token carries a vault_id that does not match local .env.sealed salt; reject at §12.7 step 6.',
    spec_section: '§12.4, §12.7 step 6',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'reject_vault_mismatch',
      error_class: 'TOKEN_INVALID',
      error_cause: 'vault-mismatch',
    },
  };
}

function expired() {
  const token = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_PAST,
    nonce: TIER_B_NONCE,
  });
  return {
    name: 'credential-modernization-expired',
    purpose: 'Tier B token with exp in 2001; reject at §12.7 step 3 before any sig verify.',
    spec_section: '§12.7 step 3',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'reject_expired',
      error_class: 'TOKEN_EXPIRED',
      error_cause: 'exp-past',
    },
  };
}

function replayAfterNonceSeen() {
  const token = buildTierBToken({
    masterKey: MASTER_KEY,
    salt: SALT,
    exp: EXP_FUTURE,
    nonce: TIER_B_NONCE,
  });
  return {
    name: 'credential-modernization-replay-after-nonce-seen',
    purpose: 'Tier B token presented a second time with nonce_state_backend configured; reject at §12.7 step 7 / §12.8.',
    spec_section: '§12.7 step 7, §12.8',
    vault: vaultStubBasic(),
    token,
    config_file_contents: JSON.stringify(
      {
        deploy_mode: 'ephemeral',
        deploy_ttl_max_seconds: 60,
        require_totp_on_mint: false,
        allow_long_lived_for_dev: true,
        nonce_state_backend: 'redis://fixture-replay-cache:6379',
      },
      null,
      2,
    ),
    expected: {
      result: 'reject_replay',
      error_class: 'TOKEN_INVALID',
      error_cause: 'replay',
      previously_seen_nonces: [TIER_B_NONCE.toString('hex')],
    },
  };
}

function futureFieldsIgnored() {
  // Inject an extra CBOR key. The encoder sorts it per §11.5 — "future_field"
  // is length 12, so it sorts after every key the basic schema defines.
  const token = mintToken('b', {
    m: MASTER_KEY,
    future_field: Buffer.from('reserved-for-0.4.0', 'utf8'),
  });
  return {
    name: 'credential-modernization-future-fields-ignored',
    purpose: 'Unknown CBOR map key is silently ignored per §11.8; mode "b" still parses and decrypts.',
    spec_section: '§11.8',
    vault: vaultStubBasic(),
    token,
    config_file_contents: null,
    expected: {
      result: 'parse_ok_ignore_unknown',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
    },
  };
}

function legacyKeyStillWorks() {
  // No token. The vault is unlocked via the legacy env-var flow:
  // SEALED_ENV_KEY + SEALED_ENV_SIGNING_KEY + SEALED_ENV_TOTP_SECRET.
  return {
    name: 'credential-modernization-legacy-key-still-works',
    purpose: 'Legacy SEALED_ENV_KEY+SEALED_ENV_SIGNING_KEY flow still decrypts per §11.9 with a one-time deprecation warning.',
    spec_section: '§11.9',
    vault: vaultStubEnterprise(),
    token: null,
    legacy_env: {
      SEALED_ENV_KEY: MASTER_KEY.toString('hex'),
      SEALED_ENV_SIGNING_KEY: SIGNING_KEY.toString('hex'),
      SEALED_ENV_TOTP_SECRET: TOTP_SECRET.toString('hex'),
    },
    config_file_contents: null,
    expected: {
      result: 'decrypt_ok_with_warning',
      plaintext_hex: FIXED_PLAINTEXT_HEX,
      warning_substring: 'legacy-credential-format',
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function writeFixture(fixture) {
  const path = join(outDir, `${fixture.name}.json`);
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n');
  return path;
}

function main() {
  runSelfChecks();

  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

  const fixtures = [
    basicValid(),
    teamValid(),
    enterpriseValid(),
    unsealValid(),
    tierBDeployValid(),
    wrongChecksum(),
    tamperedPayload(),
    wrongVaultId(),
    expired(),
    replayAfterNonceSeen(),
    futureFieldsIgnored(),
    legacyKeyStillWorks(),
  ];

  for (const f of fixtures) {
    const p = writeFixture(f);
    console.log('Wrote', p);
  }

  console.log(`\nDone. ${fixtures.length} fixtures written to ${outDir}`);
}

main();
