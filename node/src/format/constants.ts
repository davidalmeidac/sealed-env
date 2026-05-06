/**
 * Constants shared across the format reader/writer.
 */

export const FILE_FORMAT_VERSION = 1 as const;
export const MAGIC_LINE_PREFIX = 'SEALED-ENV-V1' as const;

/** AES-256-GCM nonce length in bytes. */
export const NONCE_LEN = 12;

/** Argon2 salt length in bytes. */
export const SALT_LEN = 16;

/** AES-256 key length in bytes. */
export const KEY_LEN = 32;

/** HMAC-SHA256 output length in bytes. */
export const MAC_LEN = 32;

/** TOTP secret length recommended (20 bytes per RFC 4226). */
export const TOTP_SECRET_LEN = 20;

/** Default KDF parameters. Suitable for desktop hardware in 2026. */
export const DEFAULT_KDF_PARAMS = Object.freeze({
  t: 3,
  m: 65536,
  p: 4,
});

/** Maximum age (seconds) for an unseal token. */
export const MAX_UNSEAL_TOKEN_AGE_SECONDS = 600;

/** HKDF info strings — versioned to allow future format upgrades. */
export const HKDF_INFO_ENC = 'sealed-env:v1:enc';
export const HKDF_INFO_MAC = 'sealed-env:v1:mac';

/** TOTP verifier domain separation tag. */
export const TOTP_VERIFY_TAG = 'verify-v1';
