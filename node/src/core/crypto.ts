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
 * Derive a 32-byte key from a master secret using the KDF declared in the file.
 *
 * Node 22 stdlib supports scrypt (RFC 7914) natively. It does NOT support
 * Argon2id — files written with `KDF=argon2id` (typically by the Java
 * implementation) cannot be decrypted by Node alone in v0.x and surface a
 * clear `UNSUPPORTED_KDF` error. The Java implementation handles both.
 *
 * @internal — exported only for tests
 */
export function deriveMasterKey(
  masterKey: Buffer,
  salt: Buffer,
  params: KdfParams,
): Buffer {
  if (params.kind === 'scrypt') {
    const { N, r, p } = params.params;
    // maxmem is computed roughly as 128 * N * r * p * 1.1 — give it 4x headroom
    const maxmem = Math.max(64 * 1024 * 1024, 128 * N * r * p * 4);
    return scryptSync(masterKey, salt, KEY_LEN, { N, r, p, maxmem });
  }
  // argon2id — Node 22 stdlib has no implementation. Reject with a clear error
  // so the operator knows to use the Java tool (or wait for v0.2.x wasm).
  throw new SealedEnvError(
    'UNSUPPORTED_KDF',
    'sealed-env: Node 22 stdlib has no Argon2id; this file was sealed by the Java implementation. Use the Java tool to unseal, or wait for sealed-env v0.2.x with bundled Argon2id wasm.',
  );
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
