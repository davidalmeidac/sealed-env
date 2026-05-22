/**
 * Secret-detection patterns for sealed-env.
 *
 * Canonical spec: /SECRET-PATTERNS.md
 * Gitleaks config: /.gitleaks/sealed-env.toml
 * Test corpus: /tests/secret-patterns/{positive,negative}/
 *
 * If you change a regex here, you MUST also update the spec, the
 * gitleaks config, and the validator at /scripts/validate-secret-patterns.mjs.
 * A CI gate detects drift between these four sources.
 */

export interface SecretPattern {
  /** Stable identifier (e.g. "SE-T1"). Used in scan output. */
  id: string;
  /** Short human label, shown next to the file:line in scan output. */
  label: string;
  /**
   * Long-form description. Used by `sealed-env scan --explain <ID>` and
   * any future JSON output for tooling integration.
   */
  description: string;
  /**
   * The match regex. Stays in sync with SECRET-PATTERNS.md.
   *
   * Note for maintainers: keep the `g` flag OFF here. The scanner
   * clones the regex per line with `g` set, so accidental statefulness
   * in this module can't cause cross-line bleed.
   */
  regex: RegExp;
  /** Severity tag — informational, currently unused by the CLI. */
  severity: 'critical' | 'high' | 'medium';
}

export const PATTERNS: readonly SecretPattern[] = [
  {
    id: 'SE-T1',
    label: 'credential token',
    description:
      'sealed-env credential token (sealed_env_<mode>_<cksum>_<payload>). ' +
      'Carries master key (basic), master+signing keys (team), or ' +
      'master+signing+TOTP (enterprise, pre-CVE-2026-45091).',
    regex: /sealed_env_[btued]_[0-9a-fA-F]{4}_[A-Za-z0-9_-]{20,500}/,
    severity: 'critical',
  },
  {
    id: 'SE-T2',
    label: 'unseal token',
    description:
      'sealed-env unseal token (usl_<header>.<payload>.<sig>). HS256 JWS, ' +
      'TOTP-bound via salt-bound HMAC. Single-use within TTL.',
    regex:
      /usl_[A-Za-z0-9_-]{40,200}\.[A-Za-z0-9_-]{40,400}\.[A-Za-z0-9_-]{40,100}/,
    severity: 'high',
  },
  {
    id: 'SE-K1',
    label: 'master key',
    description:
      'SEALED_ENV_KEY — 32-byte master key in hex. Sufficient on its own ' +
      'to decrypt any file sealed in basic mode.',
    regex:
      /SEALED_ENV_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?/,
    severity: 'critical',
  },
  {
    id: 'SE-K2',
    label: 'signing key',
    description:
      'SEALED_ENV_SIGNING_KEY — 32-byte HMAC signing key (team/enterprise ' +
      'modes). Combined with a leaked master key, allows tampering.',
    regex:
      /SEALED_ENV_SIGNING_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?/,
    severity: 'high',
  },
  {
    id: 'SE-K3',
    label: 'TOTP secret',
    description:
      'SEALED_ENV_TOTP_SECRET — base32-encoded second factor for enterprise ' +
      'mode. Combined with a leaked master key, defeats 2FA entirely.',
    regex:
      /SEALED_ENV_TOTP_SECRET\s*[=:]\s*["']?([A-Z2-7]{16,64}={0,6})(?![A-Z2-7])["']?/,
    severity: 'critical',
  },
  {
    id: 'SE-K3-URI',
    label: 'TOTP otpauth URI',
    description:
      'otpauth:// URI carrying the TOTP secret. Easily leaked through QR-render ' +
      'screenshots, dev notes, and shared docs.',
    regex: /otpauth:\/\/totp\/[^?\s]*\?[^"\s]*secret=([A-Z2-7]{16,64}={0,6})/,
    severity: 'critical',
  },
];

/**
 * Lookup a pattern by ID. Throws if the ID isn't known — callers
 * should only use IDs that came from {@link PATTERNS}.
 */
export function getPattern(id: string): SecretPattern {
  const p = PATTERNS.find((p) => p.id === id);
  if (!p) {
    throw new Error(`unknown secret-pattern id: ${id}`);
  }
  return p;
}
