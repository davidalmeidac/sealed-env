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
 * The single error class thrown by this library.
 */
export class SealedEnvError extends Error {
  override readonly name = 'SealedEnvError';
  readonly code: SealedEnvErrorCode;

  constructor(code: SealedEnvErrorCode, message: string) {
    super(message);
    this.code = code;
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
