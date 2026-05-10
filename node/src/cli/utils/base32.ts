/**
 * Shared base32 decoder for sealed-env CLI utilities.
 *
 * Single source of truth — DO NOT add a second copy.
 * All code paths that decode SEALED_ENV_TOTP_SECRET MUST import from here.
 *
 * Algorithm: RFC 4648 base32, alphabet A-Z 2-7 (no padding required;
 * trailing '=' characters are stripped before decoding).
 */

import { SealedEnvError } from '../../core/errors.js';

/**
 * Decode a base32-encoded string into a Buffer.
 *
 * @param s            The base32 string. Lowercase is accepted (uppercased internally).
 *                     Trailing '=' padding is stripped and ignored.
 *                     Whitespace is also stripped.
 * @param varNameForError  The env-var name to include in the error message when
 *                         an invalid character is found. Defaults to `'value'`.
 *
 * @throws {SealedEnvError} code `CONFIG_ERROR` if the string contains a character
 *         outside the RFC 4648 base32 alphabet (A-Z, 2-7).
 */
export function decodeBase32(s: string, varNameForError = 'value'): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of cleaned) {
    const i = alphabet.indexOf(ch);
    if (i < 0) {
      throw new SealedEnvError(
        'CONFIG_ERROR',
        `${varNameForError} contains invalid base32 char "${ch}"`,
      );
    }
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
