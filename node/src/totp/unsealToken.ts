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
 */

import { hmacSha256, constantTimeEqual } from '../core/crypto.js';
import { SealedEnvError } from '../core/errors.js';
import { MAX_UNSEAL_TOKEN_AGE_SECONDS } from '../format/constants.js';

const TOKEN_PREFIX = 'usl_';

interface UnsealTokenHeader {
  alg: 'HS256';
  typ: 'sealed-env-unseal/v1';
}

export interface UnsealTokenPayload {
  iss: 'sealed-env-cli';
  iat: number;
  exp: number;
  totp_secret: string; // base64
  deploy_id: string | null;
  ops_id: string;
}

export interface BuildTokenInput {
  derivedKey: Buffer;
  totpSecret: Buffer;
  deployId: string | null;
  ttlSeconds?: number;
}

export function buildUnsealToken(input: BuildTokenInput): string {
  const ttl = Math.min(input.ttlSeconds ?? 60, MAX_UNSEAL_TOKEN_AGE_SECONDS);
  if (ttl < 5) {
    throw new SealedEnvError('CONFIG_ERROR', 'unseal token TTL too short (min 5s)');
  }

  const now = Math.floor(Date.now() / 1000);

  const header: UnsealTokenHeader = {
    alg: 'HS256',
    typ: 'sealed-env-unseal/v1',
  };
  const payload: UnsealTokenPayload = {
    iss: 'sealed-env-cli',
    iat: now,
    exp: now + ttl,
    totp_secret: input.totpSecret.toString('base64'),
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
  totpSecret: Buffer;
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

  let totpSecret: Buffer;
  try {
    totpSecret = Buffer.from(payload.totp_secret, 'base64');
  } catch {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token totp_secret unreadable');
  }
  if (totpSecret.length < 16) {
    throw new SealedEnvError('TOKEN_INVALID', 'unseal token totp_secret too short');
  }

  return { totpSecret, opsId: payload.ops_id };
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
