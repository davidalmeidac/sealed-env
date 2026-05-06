/**
 * Writer for the `.env.sealed` file format.
 *
 * The output is byte-for-byte deterministic given the same inputs (including
 * salt, nonce, timestamps). This matters for:
 * - Test vector verification (Node ↔ Java cross-check)
 * - Reproducible builds
 * - Diff-friendly review of "did the metadata change vs ciphertext only?"
 *
 * @see /SPEC.md
 */

import type { KdfParams, SealedFile } from '../core/types.js';

/** Render a KDF-PARAMS value in the canonical per-algorithm format. */
function kdfParamsLine(params: KdfParams): string {
  if (params.kind === 'argon2id') {
    const { t, m, p } = params.params;
    return `t=${t},m=${m},p=${p}`;
  }
  const { N, r, p } = params.params;
  return `N=${N},r=${r},p=${p}`;
}

/**
 * Serialize a parsed `SealedFile` back to its UTF-8 textual representation.
 *
 * Note: this serialization assumes all fields have already been validated;
 * this is not a sanitizing function. Callers must construct `SealedFile`
 * objects through the encryption pipeline, not from arbitrary user input.
 */
export function serializeSealedFile(file: SealedFile): string {
  const lines: string[] = [];

  // Magic line
  lines.push(`SEALED-ENV-V${file.version} MODE=${file.mode}`);

  // Metadata in canonical order
  lines.push(`KDF=${file.kdf}`);
  lines.push(`KDF-PARAMS=${kdfParamsLine(file.kdfParams)}`);
  lines.push(`SALT=${file.salt.toString('base64')}`);
  lines.push(`NONCE=${file.nonce.toString('base64')}`);

  if (file.mode === 'enterprise') {
    if (!file.totpVerifier) {
      throw new Error('Internal: enterprise file missing TOTP-VERIFIER');
    }
    lines.push(`TOTP-VERIFIER=${file.totpVerifier.toString('base64')}`);
    lines.push(`CHALLENGE-BIND=${file.challengeBind ?? 'enabled'}`);
  }

  lines.push(`AAD-DIGEST=${file.aadDigest.toString('base64')}`);

  if (file.mode === 'team' || file.mode === 'enterprise') {
    if (!file.hmac) {
      throw new Error(`Internal: ${file.mode} file missing HMAC`);
    }
    lines.push(`HMAC=${file.hmac.toString('base64')}`);
  }

  lines.push(`CREATED=${file.created}`);
  if (file.rotated) {
    lines.push(`ROTATED=${file.rotated}`);
  }

  // Empty separator + body
  lines.push('');
  lines.push(file.ciphertext.toString('base64'));

  // No trailing newline — keeps the file byte-deterministic
  return lines.join('\n');
}

/**
 * Build the canonical AAD (Additional Authenticated Data) for the GCM cipher.
 * This is the magic line + metadata fields EXCLUDING the HMAC line itself,
 * joined by `\n` with no trailing newline.
 *
 * The HMAC is computed over the same bytes (modulo HMAC field exclusion),
 * so the AAD also serves as the message for HMAC.
 */
export function buildAad(file: SealedFile): Buffer {
  const lines: string[] = [];
  lines.push(`SEALED-ENV-V${file.version} MODE=${file.mode}`);
  lines.push(`KDF=${file.kdf}`);
  lines.push(`KDF-PARAMS=${kdfParamsLine(file.kdfParams)}`);
  lines.push(`SALT=${file.salt.toString('base64')}`);
  lines.push(`NONCE=${file.nonce.toString('base64')}`);

  if (file.mode === 'enterprise' && file.totpVerifier) {
    lines.push(`TOTP-VERIFIER=${file.totpVerifier.toString('base64')}`);
    lines.push(`CHALLENGE-BIND=${file.challengeBind ?? 'enabled'}`);
  }

  // AAD-DIGEST is computed AFTER AAD is built, but for the AAD itself we
  // include all bound metadata except the digest and HMAC.
  lines.push(`CREATED=${file.created}`);
  if (file.rotated) {
    lines.push(`ROTATED=${file.rotated}`);
  }
  return Buffer.from(lines.join('\n'), 'utf8');
}
