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

/**
 * Default KDF identifier emitted by the Node writer.
 *
 * Node 22 stdlib does not ship Argon2id, so the Node implementation honestly
 * declares `scrypt` (RFC 7914) — also memory-hard, also a PHC finalist.
 * The Java implementation supports BOTH `scrypt` and `argon2id` via Bouncy
 * Castle, so files written by Node decrypt cleanly there.
 */
export const DEFAULT_KDF = 'scrypt' as const;

/**
 * Default scrypt parameters. Calibrated to:
 *   - hit RFC 7914 "login authentication" recommended cost
 *   - stay under 64 MB so tiny CI runners survive
 *   - finish in <500ms on a modern desktop
 */
export const DEFAULT_SCRYPT_PARAMS = Object.freeze({
  N: 32768,
  r: 8,
  p: 1,
});

/**
 * Default argon2id parameters (used when a future writer honors argon2id —
 * currently consumed only by readers parsing Java-written files).
 */
export const DEFAULT_ARGON2ID_PARAMS = Object.freeze({
  t: 3,
  m: 65536,
  p: 4,
});

/** Maximum age (seconds) for an unseal token. */
export const MAX_UNSEAL_TOKEN_AGE_SECONDS = 600;

/** HKDF info strings — versioned to allow future format upgrades. */
export const HKDF_INFO_ENC = 'sealed-env:v1:enc';
export const HKDF_INFO_MAC = 'sealed-env:v1:mac';

/**
 * Enterprise epoch derivation tag — used at seal/mint time to derive
 * the salt-bound `enterprise_epoch` from the TOTP secret:
 *
 *   enterprise_epoch = HMAC-SHA256(totpSecret, salt || EPOCH_DERIVE_TAG)
 *
 * The salt binding ensures that a leaked epoch (from a leaked token)
 * is only useful against THIS file generation. Re-sealing with a new
 * salt invalidates leaked epochs.
 */
export const EPOCH_DERIVE_TAG = 'epoch-v1';

/**
 * Enterprise epoch commitment tag — used by the file to commit to a
 * specific epoch without revealing it:
 *
 *   epoch_commit = HMAC-SHA256(derivedKey, enterprise_epoch || EPOCH_COMMIT_TAG)
 *
 * The verify side recomputes this from the token's `epoch` field and
 * compares against the file's `EPOCH-COMMIT` field. This commits the
 * file to the operator-side TOTP secret WITHOUT requiring the verifier
 * to ever see the secret itself.
 */
export const EPOCH_COMMIT_TAG = 'epoch-commit-v1';
