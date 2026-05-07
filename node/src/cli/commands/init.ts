/**
 * `sealed-env init` — bootstrap a project for sealed-env.
 *
 * Outcomes:
 * - Generates a 32-byte master key (printed to stdout, also written to
 *   .env.local for local dev convenience).
 * - For team/enterprise mode: generates an additional signing key.
 * - For enterprise mode: generates a TOTP secret and prints an `otpauth://`
 *   URI plus a textual base32 fallback.
 * - Prints next-steps instructions.
 *
 * The init command does NOT create the .env.sealed file itself — `encrypt`
 * does that. This separation lets users review their generated keys before
 * committing crypto.
 */

import { writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

import { randomBytes } from '../../core/crypto.js';
import { SealedEnvError } from '../../core/errors.js';
import { buildOtpauthUri } from '../../totp/totp.js';
import type { Mode } from '../../core/types.js';
import { parseFlags } from '../utils/flags.js';

export function initCommand(argv: string[]): void {
  const { values } = parseFlags(argv, {
    mode: { type: 'string', default: 'basic' },
    dir: { type: 'string', default: '.' },
    issuer: { type: 'string', default: '' },
  });

  const mode = values.mode as Mode;
  if (mode !== 'basic' && mode !== 'team' && mode !== 'enterprise') {
    throw new SealedEnvError('CONFIG_ERROR', `unknown mode "${mode}"`);
  }
  const dir = resolve(values.dir as string);
  const issuer = (values.issuer as string) || `sealed-env (${process.cwd().split(/[\\/]/).pop() ?? 'project'})`;

  const masterKey = randomBytes(32);
  const masterKeyHex = masterKey.toString('hex');

  let signingKeyHex: string | undefined;
  if (mode === 'team' || mode === 'enterprise') {
    const signingKey = randomBytes(32);
    signingKeyHex = signingKey.toString('hex');
  }

  let totpBase32: string | undefined;
  let otpauthUri: string | undefined;
  if (mode === 'enterprise') {
    const totpSecret = randomBytes(20);
    totpBase32 = toBase32(totpSecret);
    otpauthUri = buildOtpauthUri(
      `${process.env['USER'] ?? 'operator'}@sealed-env`,
      issuer,
      totpSecret,
    );
  }

  // Write to .env.local for local dev (gitignored)
  const envLocalPath = resolve(dir, '.env.local');
  const banner = '# sealed-env keys — DO NOT COMMIT THIS FILE.';
  const lines: string[] = [banner, `SEALED_ENV_KEY=${masterKeyHex}`];
  if (signingKeyHex) lines.push(`SEALED_ENV_SIGNING_KEY=${signingKeyHex}`);
  if (totpBase32) {
    // Inline comments after the value confuse the dotenv parser used
    // by auto-load (it would treat the comment as part of the value).
    // Put the explanation on its own line above instead.
    lines.push('# SEALED_ENV_TOTP_SECRET is base32 — paste into your authenticator app.');
    lines.push(`SEALED_ENV_TOTP_SECRET=${totpBase32}`);
  }
  const envLocalContent = lines.join('\n') + '\n';

  if (existsSync(envLocalPath)) {
    appendFileSync(envLocalPath, '\n' + envLocalContent);
  } else {
    writeFileSync(envLocalPath, envLocalContent, { mode: 0o600 });
  }

  // Ensure .env.local is gitignored
  ensureGitignore(dir, ['.env.local', '.env']);

  // Print summary
  process.stdout.write(
    [
      '',
      `✓ sealed-env initialized in ${dir} (mode: ${mode})`,
      '',
      'Generated keys:',
      `  SEALED_ENV_KEY=${masterKeyHex}`,
      ...(signingKeyHex ? [`  SEALED_ENV_SIGNING_KEY=${signingKeyHex}`] : []),
      ...(totpBase32 ? [`  TOTP secret (base32): ${totpBase32}`] : []),
      '',
      `Saved to ${envLocalPath} (gitignored).`,
      '',
      ...(otpauthUri
        ? [
            'Scan this QR with your authenticator app (Google Authenticator,',
            'Authy, 1Password, Bitwarden, etc.):',
            '',
            renderQr(otpauthUri),
            'If the QR does not render correctly in your terminal, paste this',
            'URI or the base32 secret above into your authenticator manually:',
            `  ${otpauthUri}`,
            '',
          ]
        : []),
      'Next steps:',
      '  1. Create a .env file with your secrets (it will be gitignored)',
      '  2. Run: sealed-env encrypt .env',
      '  3. Commit .env.sealed (NOT .env or .env.local)',
      '',
      'You do NOT need to export these variables in your shell — every',
      'sealed-env command auto-loads SEALED_ENV_* from .env.local in the',
      'current directory. Just stay in this folder and run the commands.',
      '',
      '(To opt out of auto-loading, set SEALED_ENV_NO_AUTOLOAD=1.)',
      '',
      ...(mode === 'enterprise'
        ? [
            'For production deploys (enterprise mode):',
            '  - Set SEALED_ENV_KEY in your CI secrets',
            '  - Set SEALED_ENV_SIGNING_KEY in your CI secrets',
            '  - For each deploy: run `sealed-env unseal --totp <code>`',
            '    and pass the resulting token as SEALED_ENV_UNSEAL_TOKEN',
            '',
          ]
        : []),
    ].join('\n'),
  );
}

function ensureGitignore(dir: string, entries: string[]): void {
  const path = resolve(dir, '.gitignore');
  let existing = '';
  if (existsSync(path)) {
    try {
      existing = require('node:fs').readFileSync(path, 'utf8');
    } catch {
      /* ignore */
    }
  }
  // Treat the .gitignore as a list of trimmed lines and check membership
  // by string comparison. The previous implementation built a regex from
  // the entry name and only escaped `.`, missing every other metachar
  // (CodeQL: "Incomplete string escaping"). String-set lookup is also
  // simpler and zero-surface.
  const existingLines = new Set(
    existing.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
  );
  const additions = entries.filter((entry) => !existingLines.has(entry));
  if (additions.length === 0) return;
  const block = '\n# Added by sealed-env\n' + additions.join('\n') + '\n';
  appendFileSync(path, block);
}

/**
 * Render an otpauth:// URI as a Unicode-block QR code suitable for
 * pasting into a terminal. Uses error-correction level "M" (the
 * default) which keeps the QR small enough for typical TOTP URIs while
 * still being scannable. The `small: true` option uses half-block
 * characters so each QR module is a single character cell instead of
 * two, which helps it fit in standard 80-column terminals.
 *
 * The `qrcode-terminal` import is lazy: it lives off the hot path
 * (only `init --mode enterprise` ever needs it). This keeps the core
 * cryptographic flows — seal, unseal, decrypt, get, set, edit, diff —
 * free of any third-party require/import. If the library ever becomes
 * unavailable for any reason, the rest of the CLI continues to work;
 * we just print the URI textually and tell the user to paste it.
 */
function renderQr(uri: string): string {
  try {
    const requireFn = createRequire(import.meta.url);
    const qrcode = requireFn('qrcode-terminal') as {
      generate: (s: string, opts: { small: boolean }, cb: (out: string) => void) => void;
    };
    let out = '';
    qrcode.generate(uri, { small: true }, (rendered: string) => {
      out = rendered;
    });
    return out;
  } catch {
    return '(could not render QR — paste the URI below into your authenticator)';
  }
}

function toBase32(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}
