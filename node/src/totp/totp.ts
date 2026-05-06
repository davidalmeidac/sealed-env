/**
 * RFC 6238 TOTP implementation, kept minimal and dependency-free.
 *
 * Why we don't use a third-party TOTP library:
 * - Zero deps is a security feature (no supply-chain risk for our crypto)
 * - The algorithm is simple (HMAC + truncation + decimal encoding)
 * - Most npm TOTP libraries pull large utility tree
 */

import { createHmac } from 'node:crypto';

export interface TotpOptions {
  /** Step size in seconds. Default 30 per RFC 6238 examples. */
  stepSeconds?: number;
  /** Number of digits. Default 6, max 8. */
  digits?: 6 | 7 | 8;
  /** Hash algorithm. RFC 6238 default is SHA-1. */
  algorithm?: 'sha1' | 'sha256' | 'sha512';
}

const DEFAULT_OPTS: Required<TotpOptions> = {
  stepSeconds: 30,
  digits: 6,
  algorithm: 'sha1',
};

/**
 * Generate a TOTP code for the given secret at the given timestamp.
 *
 * @param secret raw secret bytes (≥20 bytes recommended per RFC 4226)
 * @param timestampSeconds Unix timestamp in seconds
 */
export function generateTotp(
  secret: Buffer,
  timestampSeconds: number = Math.floor(Date.now() / 1000),
  opts: TotpOptions = {},
): string {
  const o = { ...DEFAULT_OPTS, ...opts };
  const counter = Math.floor(timestampSeconds / o.stepSeconds);
  return hotp(secret, counter, o.digits, o.algorithm);
}

/**
 * Verify a TOTP code with a small window of skew tolerance (±1 step).
 *
 * Returns true if the code matches the current step or the immediate adjacent
 * steps, to tolerate clock drift.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  timestampSeconds: number = Math.floor(Date.now() / 1000),
  opts: TotpOptions = {},
): boolean {
  const o = { ...DEFAULT_OPTS, ...opts };
  if (!/^\d+$/.test(code)) return false;
  if (code.length !== o.digits) return false;

  const baseCounter = Math.floor(timestampSeconds / o.stepSeconds);
  // ±1 window
  for (const offset of [-1, 0, 1]) {
    const expected = hotp(secret, baseCounter + offset, o.digits, o.algorithm);
    // Constant-time compare on the digit strings
    if (expected.length === code.length && safeStringCompare(expected, code)) {
      return true;
    }
  }
  return false;
}

/**
 * RFC 4226 HOTP — used internally by TOTP.
 */
function hotp(
  secret: Buffer,
  counter: number,
  digits: number,
  algorithm: 'sha1' | 'sha256' | 'sha512',
): string {
  const counterBuf = Buffer.alloc(8);
  // 64-bit big-endian counter
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = createHmac(algorithm, secret).update(counterBuf).digest();

  // Dynamic truncation per RFC 4226
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  const otp = binary % 10 ** digits;
  return otp.toString().padStart(digits, '0');
}

function safeStringCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Build the standard `otpauth://` URI for an authenticator app.
 *
 * @param accountName e.g. "david@example.com"
 * @param issuer e.g. "sealed-env (myproject)"
 * @param secret raw secret bytes
 */
export function buildOtpauthUri(
  accountName: string,
  issuer: string,
  secret: Buffer,
  opts: TotpOptions = {},
): string {
  const o = { ...DEFAULT_OPTS, ...opts };
  const base32 = toBase32(secret);
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(accountName);
  const params = new URLSearchParams({
    secret: base32,
    issuer,
    algorithm: o.algorithm.toUpperCase(),
    digits: String(o.digits),
    period: String(o.stepSeconds),
  });
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?${params.toString()}`;
}

/**
 * RFC 4648 base32 (no padding) — required for otpauth URI secrets.
 */
function toBase32(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}
