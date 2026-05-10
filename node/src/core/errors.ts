/**
 * Error types for sealed-env.
 *
 * We intentionally use ONE error class with a `code` discriminator instead of
 * a hierarchy. This keeps user code simple — `try/catch (e: SealedEnvError)`
 * and switch on `e.code`.
 *
 * For decryption failures we deliberately collapse multiple internal errors
 * into a single user-facing message to avoid leaking timing or oracle info to
 * attackers probing keys.
 */

export type SealedEnvErrorCode =
  | 'PARSE_ERROR'
  | 'UNSUPPORTED_VERSION'
  | 'UNKNOWN_MODE'
  | 'MISSING_FIELD'
  | 'INVALID_FIELD'
  | 'UNSUPPORTED_KDF'
  | 'MISSING_KEY'
  | 'MISSING_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'DEPLOY_MISMATCH'
  | 'DECRYPT_FAILED'
  | 'CONFIG_ERROR';

/**
 * Optional sub-classification for TOKEN_INVALID errors.
 *
 * Callers that only check `e.code === 'TOKEN_INVALID'` keep working.
 * Callers that need to distinguish replay from expiry etc. can inspect `e.cause`.
 */
export type TokenInvalidCause =
  | 'replay'
  | 'replay-cache-unavailable'
  | 'signature'
  | 'expired'
  | 'malformed-epoch'
  | 'header'
  | 'wrong-prefix'
  | 'malformed';

/**
 * The single error class thrown by this library.
 *
 * Backward-compatible extension: an optional `cause` string is now accepted
 * in the constructor for sub-classification of TOKEN_INVALID errors.
 * Existing callers reading `e.code === 'TOKEN_INVALID'` are unaffected.
 */
export class SealedEnvError extends Error {
  override readonly name = 'SealedEnvError';
  readonly code: SealedEnvErrorCode;
  /**
   * Optional sub-classification. Present on TOKEN_INVALID errors emitted by
   * the replay cache path. Undefined for all other error codes and for
   * TOKEN_INVALID errors that predate 0.2.0.
   */
  override readonly cause?: TokenInvalidCause | string;

  constructor(code: SealedEnvErrorCode, message: string, opts?: { cause?: string }) {
    super(message);
    this.code = code;
    if (opts?.cause !== undefined) {
      // TypeScript knows Error.cause exists on ES2022+; assign directly.
      (this as unknown as { cause: string }).cause = opts.cause;
    }
    // Maintain proper stack trace where available (V8/Node)
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, SealedEnvError);
    }
  }

  /**
   * Build a generic decryption-failure error. Always returns the same message
   * regardless of which step failed, to avoid side-channel leaks.
   */
  static decryptFailed(): SealedEnvError {
    return new SealedEnvError(
      'DECRYPT_FAILED',
      'sealed-env: file is corrupted, tampered, or wrong key',
    );
  }
}
