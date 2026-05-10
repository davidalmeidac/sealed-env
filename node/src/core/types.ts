/**
 * Core types for sealed-env.
 */

/**
 * Security mode of a sealed file.
 *
 * - `basic`: AES-256-GCM with master key only (dotenvx-equivalent).
 * - `team`: Adds explicit HMAC integrity tag and audit log support.
 * - `enterprise`: Adds TOTP-based unseal token bound to a deploy challenge.
 */
export type Mode = 'basic' | 'team' | 'enterprise';

/**
 * KDF algorithm identifier as written in `.env.sealed`.
 *
 * Both implementations MUST be able to READ both. Node currently WRITES only
 * `scrypt` (Node 22 stdlib has no Argon2id); Java WRITES `argon2id` via
 * Bouncy Castle but accepts both for cross-stack interop.
 */
export type KdfAlgorithm = 'scrypt' | 'argon2id';

/** Argon2id KDF parameters. */
export interface Argon2idParams {
  /** Iterations (Argon2 time cost). */
  t: number;
  /** Memory in KB (Argon2 memory cost). */
  m: number;
  /** Parallelism (Argon2 parallelism cost). */
  p: number;
}

/** scrypt KDF parameters (RFC 7914). */
export interface ScryptParams {
  /** CPU/memory cost — must be a power of two. */
  N: number;
  /** Block size. */
  r: number;
  /** Parallelism. */
  p: number;
}

/**
 * Tagged union over the supported KDF parameter shapes.
 */
export type KdfParams =
  | { kind: 'argon2id'; params: Argon2idParams }
  | { kind: 'scrypt'; params: ScryptParams };

/**
 * Parsed representation of a `.env.sealed` file.
 */
export interface SealedFile {
  version: 1;
  mode: Mode;
  kdf: KdfAlgorithm;
  kdfParams: KdfParams;
  salt: Buffer;
  nonce: Buffer;
  /**
   * Enterprise mode: HMAC-SHA256(derivedKey, enterprise_epoch || "epoch-commit-v1"),
   * where enterprise_epoch = HMAC-SHA256(totpSecret, salt || "epoch-v1").
   *
   * This commits the file to the operator's TOTP secret WITHOUT
   * revealing it. See SPEC.md §9 and src/format/constants.ts for the
   * full derivation.
   */
  epochCommit?: Buffer;
  challengeBind?: 'enabled' | 'disabled';
  aadDigest: Buffer;
  hmac?: Buffer;
  created: string;
  rotated?: string;
  ciphertext: Buffer;
}

/**
 * Options for {@link seal}.
 */
export interface SealOptions {
  /** Plaintext to encrypt. UTF-8 string OR raw Buffer (e.g. for binary configs). */
  plaintext: string | Buffer;
  /** Master key (raw bytes). Recommended ≥32 random bytes. */
  masterKey: Buffer;
  /** Security mode. */
  mode: Mode;
  /** TOTP secret (raw bytes, ≥20 bytes). Required when mode === 'enterprise'. */
  totpSecret?: Buffer;
  /** Signing key for HMAC. Required when mode in {team, enterprise}. */
  signingKey?: Buffer;
  /** Whether enterprise tokens are bound to deploy challenges. Default: true for enterprise. */
  challengeBind?: boolean;
  /** Override scrypt params. Defaults to {N: 131072, r: 8, p: 1}. */
  scryptParams?: Partial<ScryptParams>;
}

/**
 * Options for {@link unseal}.
 */
export interface UnsealOptions {
  /** The parsed sealed file. */
  file: SealedFile;
  /** Master key (raw bytes). */
  masterKey: Buffer;
  /** Signing key. Required when file.mode in {team, enterprise}. */
  signingKey?: Buffer;
  /** Unseal token (string `usl_<base64>...`). Required when file.mode === 'enterprise'. */
  unsealToken?: string;
  /** Current deploy id. Required when challengeBind enabled. */
  deployId?: string;
}

/**
 * Options for {@link loadSealed} (high-level, env-var driven).
 */
export interface LoadSealedOptions {
  /** Path to the sealed file. Default: '.env.sealed' in cwd. */
  path?: string;
  /** Whether to mutate process.env with the loaded values. Default: true. */
  populate?: boolean;
  /** Override env var names if customizing. */
  envVars?: {
    masterKey?: string;
    signingKey?: string;
    unsealToken?: string;
    deployId?: string;
  };
}
