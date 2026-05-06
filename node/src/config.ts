/**
 * Side-effect import that auto-loads `.env.sealed` into `process.env`.
 *
 * Usage:
 *   import 'sealed-env/config';   // ESM
 *   require('sealed-env/config'); // CJS interop
 *
 * Reads from .env.sealed (or `SEALED_ENV_PATH` if set) using SEALED_ENV_KEY,
 * SEALED_ENV_SIGNING_KEY (team+), SEALED_ENV_UNSEAL_TOKEN (enterprise),
 * SEALED_ENV_DEPLOY_ID (enterprise+challenge-bind).
 *
 * On any error, the process exits with a clear message rather than running
 * with empty secrets. This is intentional — silently degrading to "no env"
 * leads to incidents in production.
 */

import { loadSealed } from './core/api.js';
import { SealedEnvError } from './core/errors.js';

try {
  loadSealed({
    path: process.env['SEALED_ENV_PATH'] ?? '.env.sealed',
    populate: true,
  });
} catch (e) {
  const msg = e instanceof Error ? e.message : String(e);
  const code = e instanceof SealedEnvError ? `[${e.code}]` : '';
  process.stderr.write(`sealed-env: failed to load .env.sealed ${code}\n  ${msg}\n`);
  process.exitCode = 1;
  throw e;
}
