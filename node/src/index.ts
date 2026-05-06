/**
 * sealed-env — Encrypted .env files with optional TOTP unsealing.
 *
 * @packageDocumentation
 */

export { seal, unseal, loadSealed } from './core/api.js';
export { SealedEnvError } from './core/errors.js';
export type {
  Mode,
  SealOptions,
  UnsealOptions,
  LoadSealedOptions,
  SealedFile,
} from './core/types.js';
export { FILE_FORMAT_VERSION } from './format/constants.js';
