/**
 * `sealed-env doctor [<file.env.sealed>]` — non-destructive diagnostic.
 *
 * Validates the local sealed-env setup WITHOUT printing any secret
 * values. Designed to be safe to paste into a CI log or a Slack thread
 * when debugging "why isn't this decrypting?" — the output is a series
 * of pass/fail lines with redacted fingerprints, never plaintext.
 *
 *   $ sealed-env doctor .env.sealed
 *   sealed-env 0.1.0-alpha.4 — diagnostic report
 *
 *   [✓] sealed file found              .env.sealed (366 B)
 *   [✓] file parses as V1              mode=enterprise, kdf=scrypt
 *   [✓] SEALED_ENV_KEY set             32 bytes (sha256: 7c8a..b3d1)
 *   [✓] SEALED_ENV_SIGNING_KEY set     32 bytes (sha256: 9d2e..ff04)
 *   [✓] SEALED_ENV_TOTP_SECRET set     20 bytes (sha256: 1aa3..c7e5)
 *   [✓] file integrity (HMAC)          OK
 *   [✓] decrypt roundtrip              OK (4 keys recovered)
 *
 *   All checks passed. Setup looks healthy.
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { existsSync, statSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

import { unseal } from '../../core/api.js';
import { parseSealedFile } from '../../format/parser.js';
import { SealedEnvError } from '../../core/errors.js';

interface CheckResult {
  ok: boolean;
  label: string;
  detail: string;
}

export function doctorCommand(argv: string[]): void {
  const filePath = argv[0];
  const checks: CheckResult[] = [];

  process.stdout.write('sealed-env diagnostic report\n\n');

  // Section 1: env vars (always relevant)
  checks.push(checkEnv('SEALED_ENV_KEY', { required: true, minBytes: 32 }));
  checks.push(checkEnv('SEALED_ENV_SIGNING_KEY', { required: false, minBytes: 32 }));
  checks.push(checkEnv('SEALED_ENV_TOTP_SECRET', { required: false, minBytes: 16 }));
  checks.push(checkEnv('SEALED_ENV_UNSEAL_TOKEN', { required: false }));
  checks.push(checkEnv('SEALED_ENV_DEPLOY_ID', { required: false }));

  // Section 2: file checks (only if a file was provided)
  if (filePath) {
    if (!existsSync(filePath)) {
      checks.push({ ok: false, label: 'sealed file found', detail: `not found: ${filePath}` });
    } else {
      const stat = statSync(filePath);
      checks.push({
        ok: true,
        label: 'sealed file found',
        detail: `${filePath} (${stat.size} B)`,
      });

      try {
        const text = readFileSync(resolve(filePath), 'utf8');
        const file = parseSealedFile(text);
        checks.push({
          ok: true,
          label: 'file parses as V1',
          detail: `mode=${file.mode}, kdf=${file.kdf}`,
        });

        // Roundtrip — only attempt if we have everything we need.
        try {
          const masterKey = readKey('SEALED_ENV_KEY');
          const signingKey =
            file.mode === 'team' || file.mode === 'enterprise'
              ? readKey('SEALED_ENV_SIGNING_KEY')
              : undefined;
          const unsealOpts: Parameters<typeof unseal>[0] = {
            file,
            masterKey,
          };
          if (signingKey) unsealOpts.signingKey = signingKey;
          if (file.mode === 'enterprise') {
            const tok = process.env['SEALED_ENV_UNSEAL_TOKEN'];
            const did = process.env['SEALED_ENV_DEPLOY_ID'];
            if (tok) unsealOpts.unsealToken = tok;
            if (did) unsealOpts.deployId = did;
          }
          const plaintext = unseal(unsealOpts);
          const numKeys = plaintext
            .toString('utf8')
            .split('\n')
            .filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l)).length;
          checks.push({
            ok: true,
            label: 'decrypt roundtrip',
            detail: `OK (${numKeys} key${numKeys === 1 ? '' : 's'} recovered)`,
          });
        } catch (e) {
          checks.push({
            ok: false,
            label: 'decrypt roundtrip',
            detail: e instanceof SealedEnvError ? `[${e.code}] ${e.message.split('\n')[0]}` : 'failed',
          });
        }
      } catch (e) {
        checks.push({
          ok: false,
          label: 'file parses as V1',
          detail: e instanceof Error ? e.message.split('\n')[0]! : 'parse error',
        });
      }
    }
  }

  // Render the report
  const longest = Math.max(...checks.map((c) => c.label.length));
  for (const c of checks) {
    const mark = c.ok ? '✓' : '✗';
    process.stdout.write(`  [${mark}] ${c.label.padEnd(longest)}  ${c.detail}\n`);
  }
  process.stdout.write('\n');

  const failed = checks.filter((c) => !c.ok);
  if (failed.length === 0) {
    process.stdout.write('All checks passed. Setup looks healthy.\n');
  } else {
    process.stdout.write(
      `${failed.length} check${failed.length === 1 ? '' : 's'} failed. ` +
        'Address the items marked ✗ above.\n',
    );
    process.exitCode = 1;
  }
}

/**
 * Validate an env var without printing its value. Reports byte length
 * and a SHA-256 fingerprint (first 4 + last 4 hex chars) — enough to
 * tell if two machines have the same key, useless to anyone observing
 * the log.
 */
function checkEnv(
  name: string,
  opts: { required: boolean; minBytes?: number },
): CheckResult {
  const v = process.env[name];
  if (!v) {
    return {
      ok: !opts.required,
      label: `${name} set`,
      detail: opts.required ? 'missing (required)' : 'not set (optional)',
    };
  }
  let buf: Buffer;
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
    buf = Buffer.from(v, 'hex');
  } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) {
    buf = Buffer.from(v, 'base64');
  } else {
    buf = Buffer.from(v, 'utf8');
  }

  if (opts.minBytes && buf.length < opts.minBytes) {
    return {
      ok: false,
      label: `${name} set`,
      detail: `${buf.length} bytes (need ≥${opts.minBytes})`,
    };
  }
  const fp = createHash('sha256').update(buf).digest('hex');
  const shortFp = `${fp.substring(0, 4)}..${fp.substring(60)}`;
  return {
    ok: true,
    label: `${name} set`,
    detail: `${buf.length} bytes (sha256: ${shortFp})`,
  };
}

function readKey(varName: string): Buffer {
  const v = process.env[varName];
  if (!v) throw new SealedEnvError('MISSING_KEY', `${varName} is required`);
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return Buffer.from(v, 'base64');
  throw new SealedEnvError('CONFIG_ERROR', `${varName} must be hex or base64`);
}
