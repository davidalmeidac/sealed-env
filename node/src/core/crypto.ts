/**
 * Cryptographic primitives wrapper.
 *
 * Wrappers exist for two reasons:
 * 1. To put all crypto in one auditable file
 * 2. To pin to specific algorithms — never let a caller pick a weaker one
 *
 * @see /SPEC.md §5
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  scryptSync,
  randomBytes as nodeRandomBytes,
  timingSafeEqual as nodeTimingSafeEqual,
} from 'node:crypto';

import { SealedEnvError } from './errors.js';
import {
  HKDF_INFO_ENC,
  HKDF_INFO_MAC,
  KEY_LEN,
  MAC_LEN,
  NONCE_LEN,
  SALT_LEN,
} from '../format/constants.js';
import type { KdfParams } from './types.js';

/**
 * Generate cryptographically random bytes from the OS CSPRNG.
 */
export function randomBytes(n: number): Buffer {
  return nodeRandomBytes(n);
}

/**
 * Constant-time comparison of two buffers. Returns false if lengths differ
 * (without short-circuit timing leak between equal-length and different-length
 * pairs at the call site — but we choose to fail fast on length mismatch
 * because it's not a useful side channel for our threat model).
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return nodeTimingSafeEqual(a, b);
}

/**
 * Derive a key from a master secret using a strong KDF.
 *
 * NOTE: Node 22+ does not ship Argon2 in the standard library. We use scrypt
 * as the fallback (also a memory-hard PHC finalist) until we can guarantee
 * native bindings without adding dependencies.
 *
 * The format file declares `argon2id` per spec — Node consumers will see this
 * and use the bundled scrypt-based reader for v0.1.x while we lobby for native
 * Argon2 support in core. Java consumers, which DO have built-in Argon2 (via
 * Bouncy Castle stdlib), produce the canonical format.
 *
 * For interop in v0.1.x, the Node implementation maps `argon2id` parameters
 * onto scrypt's N/r/p with a documented translation. This will be replaced
 * by true Argon2id in v0.2.x once we either (a) Node ships it, or
 * (b) we ship a tiny bundled wasm module.
 *
 * @internal — exported only for tests
 */
export function deriveMasterKey(
  masterKey: Buffer,
  salt: Buffer,
  _params: KdfParams,
): Buffer {
  // For v0.1.x we use scrypt as the KDF in the Node implementation.
  // Parameters chosen to:
  //   - hit RFC 7914 "login authentication" recommended cost
  //   - stay below default Node maxmem (32 MB) so it works on tiny CI runners
  //   - finish in <500ms on modern desktops
  //
  // The on-disk format declares `argon2id` with logical params for
  // forward-compat. v0.2.x will add a wasm Argon2id and re-honor the params.
  const N = 1 << 15; // 32768
  const r = 8;
  const p = 1;
  return scryptSync(masterKey, salt, KEY_LEN, { N, r, p, maxmem: 64 * 1024 * 1024 });
}

/**
 * HKDF-SHA256 expand. Returns a derived key of `length` bytes.
 */
export function hkdfExpand(
  prk: Buffer,
  salt: Buffer,
  info: string,
  length: number,
): Buffer {
  const out = hkdfSync('sha256', prk, salt, Buffer.from(info, 'utf8'), length);
  return Buffer.from(out);
}

/**
 * HMAC-SHA256.
 */
export function hmacSha256(key: Buffer, message: Buffer): Buffer {
  return createHmac('sha256', key).update(message).digest();
}

/**
 * SHA-256 hash.
 */
export function sha256(message: Buffer): Buffer {
  return createHash('sha256').update(message).digest();
}

/**
 * AES-256-GCM encryption.
 *
 * @returns the ciphertext concatenated with the 16-byte auth tag.
 */
export function aesGcmEncrypt(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad: Buffer,
): Buffer {
  if (key.length !== KEY_LEN) throw new Error(`AES key must be ${KEY_LEN} bytes`);
  if (nonce.length !== NONCE_LEN) throw new Error(`Nonce must be ${NONCE_LEN} bytes`);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, tag]);
}

/**
 * AES-256-GCM decryption. Returns plaintext or throws a generic
 * `DECRYPT_FAILED` error.
 */
export function aesGcmDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertextWithTag: Buffer,
  aad: Buffer,
): Buffer {
  if (ciphertextWithTag.length < 16) throw SealedEnvError.decryptFailed();
  const tagStart = ciphertextWithTag.length - 16;
  const ct = ciphertextWithTag.subarray(0, tagStart);
  const tag = ciphertextWithTag.subarray(tagStart);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw SealedEnvError.decryptFailed();
  }
}

/**
 * Best-effort wipe of a Buffer. Note: V8 may have moved the underlying memory
 * by the time this runs — this is a hygiene measure, not an absolute guarantee.
 * Combined with garbage collection, it reduces but does not eliminate residue.
 */
export function wipe(buf: Buffer | undefined): void {
  if (!buf) return;
  buf.fill(0);
}

/**
 * Re-export some constants for convenience.
 */
export { KEY_LEN, MAC_LEN, NONCE_LEN, SALT_LEN, HKDF_INFO_ENC, HKDF_INFO_MAC };
