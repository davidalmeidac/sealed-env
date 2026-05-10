/**
 * Unseal token (compact, signed payload).
 *
 * Spec: SPEC.md §9.
 *
 * Format: usl_<base64url(header)>.<base64url(payload)>.<base64url(signature)>
 *
 * The signature key is the `derived_key` from the file's master_key + salt
 * (NOT the master key directly), so a token cannot be forged from the master
 * key alone — you also need the file's salt. This couples token validity to
 * a specific file generation.
 *
 * Security note (post-alpha.3 hardening): the token payload carries an
 * `enterprise_epoch`, which is HMAC(totpSecret, salt || "epoch-v1") —
 * NOT the TOTP secret itself. The salt binding limits the blast radius
 * of a leaked token to the specific file generation (re-sealing with a
 * new salt invalidates leaked epochs). Earlier alpha versions stored
 * the raw TOTP secret in `payload.totp_secret`, which leaked the secret
 * to anyone who could read a token (CI logs, container env dumps, etc.).
 * Files sealed with alpha ≤ 0.1.0-alpha.3 are NOT compatible with this
 * version — re-seal them with `sealed-env encrypt`.
 */

import { hmacSha256, constantTimeEqual } from '../core/crypto.js';
import { SealedEnvError } from '../core/errors.js';
import {
  MAX_UNSEAL_TOKEN_AGE_SECONDS,
  EPOCH_DERIVE_TAG,
} from '../format/constants.js';
import { decodeBase64Strict } from '../format/parser.js';

const TOKEN_PREFIX = 'usl_';

interface UnsealTokenHeader {
  alg: 'HS256';
  typ: 'sealed-env-unseal/v1';
}

export interface UnsealTokenPayload {
  iss: 'sealed-env-cli';
  iat: number;
  exp: number;
  /**
   * Salt-bound derivative of the operator's TOTP secret:
   *   enterprise_epoch = HMAC-SHA256(totpSecret, salt || "epoch-v1")
   * Carried as base64. The TOTP secret itself NEVER appears in the token.
   */
  epoch: string;
  deploy_id: string | null;
  ops_id: string;
}

export interface BuildTokenInput {
  derivedKey: Buffer;
  /**
   * The operator's TOTP secret. Used here ONLY to derive the
   * salt-bound `enterprise_epoch`; the secret itself never leaves
   * this function and never appears in the produced token.
   */
  totpSecret: Buffer;
  /** The file's salt — required to compute `enterprise_epoch`. */
  salt: Buffer;
  deployId: string | null;
  ttlSeconds?: number;
}

export function buildUnsealToken(input: BuildTokenInput): string {
  const ttl = Math.min(input.ttlSeconds ?? 60, MAX_UNSEAL_TOKEN_AGE_SECONDS);
  if (ttl < 5) {
    throw new SealedEnvError('CONFIG_ERROR', 'unseal token TTL too short (min 5s)');
  }

  const now = Math.floor(Date.now() / 1000);

  // Derive the salt-bound enterprise epoch. This is what goes into
  // the token — the raw TOTP secret never leaves this function.
  const enterpriseEpoch = hmacSha256(
    input.totpSecret,
    Buffer.concat([input.salt, Buffer.from(EPOCH_DERIVE_TAG, 'utf8')]),
  );

  const header: UnsealTokenHeader = {
    alg: 'HS256',
    typ: 'sealed-env-unseal/v1',
  };
  const payload: UnsealTokenPayload = {
    iss: 'sealed-env-cli',
    iat: now,
    exp: now + ttl,
    epoch: enterpriseEpoch.toString('base64'),
    deploy_id: input.deployId,
    ops_id: randomOpsId(),
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const sig = hmacSha256(input.derivedKey, signingInput);
  const sigB64 = base64UrlEncode(sig);

  return `${TOKEN_PREFIX}${headerB64}.${payloadB64}.${sigB64}`;
}

export interface VerifyTokenInput {
  token: string;
  derivedKey: Buffer;
  expectedDeployId: string | null;
  challengeBindEnabled: boolean;
  /** Verifier for replay protection (caller-provided, optional). */
  isOpsIdSeen?: (opsId: string) => boolean;
  markOpsIdSeen?: (opsId: string) => void;
}

export interface VerifyTokenResult {
  /**
   * The salt-bound enterprise epoch carried by the token. Caller must
   * verify this against the file's `epochCommit` before trusting it.
   */
  enterpriseEpoch: Buffer;
  opsId: string;
}

export function verifyUnsealToken(input: VerifyTokenInput): VerifyTokenResult {
  if (!input.token.startsWith(TOKEN_PREFIX)) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token has wrong prefix');
  }
  const stripped = input.token.substring(TOKEN_PREFIX.length);
  const parts = stripped.split('.');
  if (parts.length !== 3) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token malformed');
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  // Verify signature first (don't parse payload until signature checks out —
  // avoids parser oracle on tampered tokens)
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const expectedSig = hmacSha256(input.derivedKey, signingInput);
  let providedSig: Buffer;
  try {
    providedSig = base64UrlDecode(sigB64);
  } catch {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token signature unreadable');
  }
  if (!constantTimeEqual(expectedSig, providedSig)) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token signature invalid');
  }

  // Parse header and payload
  let header: UnsealTokenHeader;
  let payload: UnsealTokenPayload;
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token payload malformed');
  }
  if (header.alg !== 'HS256' || header.typ !== 'sealed-env-unseal/v1') {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token has unexpected header');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    throw new SealedEnvError('TOKEN_EXPIRED', 'unseal token expired');
  }
  if (typeof payload.iat !== 'number' || payload.iat > now + 5) {
    // 5s clock-skew tolerance
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token issued in the future');
  }
  if (payload.exp - payload.iat > MAX_UNSEAL_TOKEN_AGE_SECONDS) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token TTL too long');
  }

  if (input.challengeBindEnabled) {
    if (payload.deploy_id !== input.expectedDeployId) {
      throw new SealedEnvError(
        'DEPLOY_MISMATCH',
        'unseal token bound to a different deploy',
      );
    }
    if (!payload.deploy_id) {
      throw new SealedEnvError('DEPLOY_MISMATCH', 'unseal token missing deploy_id');
    }
  }

  if (input.isOpsIdSeen?.(payload.ops_id)) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token already used (replay)');
  }
  input.markOpsIdSeen?.(payload.ops_id);

  let enterpriseEpoch: Buffer;
  try {
    // SEC-007: strict base64 validation before decode. decodeBase64Strict rejects
    // whitespace, non-base64 chars, and malformed padding — matching Java's
    // Base64.getDecoder() strict behavior. Wraps to TOKEN_INVALID (not DECRYPT_FAILED)
    // because this is a structural token error, not a crypto failure.
    // (See decodeBase64Strict in format/parser.ts; cross-stack symmetry with Java.)
    enterpriseEpoch = decodeBase64Strict(payload.epoch, 'epoch');
  } catch (e) {
    if (e instanceof SealedEnvError) {
      throw new SealedEnvError('TOKEN_INVALID', 'unseal token epoch malformed (SEC-007)');
    }
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token epoch unreadable');
  }
  // HMAC-SHA256 output is always exactly 32 bytes. Any other length
  // means the token is malformed or from a different format version.
  if (enterpriseEpoch.length !== 32) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token epoch wrong length');
  }

  return { enterpriseEpoch, opsId: payload.ops_id };
}

function base64UrlEncode(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(s: string): Buffer {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function randomOpsId(): string {
  // crypto.randomUUID is available in Node 14.17+ — we require Node 20+
  return crypto.randomUUID();
}
