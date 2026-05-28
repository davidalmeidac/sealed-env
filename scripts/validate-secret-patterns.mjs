#!/usr/bin/env node
/**
 * validate-secret-patterns.mjs
 *
 * Walks tests/secret-patterns/{positive,negative}/, applies the 6
 * regex patterns documented in SECRET-PATTERNS.md, and asserts:
 *
 *   - Every non-comment, non-blank line in positive/ MUST match at
 *     least one pattern.
 *   - No line in negative/ may match any pattern.
 *
 * Exits 0 on success, 1 on any failure. CI-friendly.
 *
 * The patterns here are intentionally duplicated from the gitleaks
 * config (and SECRET-PATTERNS.md) so this validator stays self-contained
 * and runs without external dependencies. If you change a regex, you
 * MUST change it in all three places — there is a CI gate that
 * detects drift (see .github/workflows/secret-patterns.yml).
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(__filename, '..', '..');

// -----------------------------------------------------------------
// PATTERNS — keep in sync with SECRET-PATTERNS.md + .gitleaks/sealed-env.toml
// -----------------------------------------------------------------
const PATTERNS = [
  {
    id: 'SE-T1',
    description: 'sealed-env credential token',
    regex: /sealed_env_[btued]_[0-9a-fA-F]{4}_[A-Za-z0-9_-]{20,500}/,
  },
  {
    id: 'SE-T2',
    description: 'sealed-env unseal token',
    regex: /usl_[A-Za-z0-9_-]{40,200}\.[A-Za-z0-9_-]{40,400}\.[A-Za-z0-9_-]{40,100}/,
  },
  {
    id: 'SE-K1',
    description: 'sealed-env master key',
    // Accept both .env (KEY=value) and YAML (KEY: value) syntaxes.
    // Negative lookahead `(?![0-9a-fA-F])` rejects strings longer than 64 hex
    // (typically typos or pasted-wrong values, not real keys).
    regex: /SEALED_ENV_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?/,
  },
  {
    id: 'SE-K2',
    description: 'sealed-env signing key',
    regex: /SEALED_ENV_SIGNING_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])["']?/,
  },
  {
    id: 'SE-K3',
    description: 'sealed-env TOTP secret',
    regex: /SEALED_ENV_TOTP_SECRET\s*[=:]\s*["']?([A-Z2-7]{16,64}={0,6})(?![A-Z2-7])["']?/,
  },
  {
    id: 'SE-K3-URI',
    description: 'otpauth:// URI carrying TOTP secret',
    regex: /otpauth:\/\/totp\/[^?\s]*\?[^"\s]*secret=([A-Z2-7]{16,64}={0,6})/,
  },
  {
    id: 'SE-K4',
    description: 'PyPI API token (external)',
    regex: /pypi-[A-Za-z0-9_-]{60,500}/,
  },
];

// -----------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------
function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.txt')) out.push(full);
  }
  return out;
}

function readLines(path) {
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((line, idx) => ({ line, lineNo: idx + 1, raw: line }))
    .filter(({ line }) => {
      const t = line.trim();
      // skip blank lines and full-line comments only;
      // KEEP lines with trailing `#` comments since they may contain the secret first
      if (t === '' || t.startsWith('#')) return false;
      return true;
    });
}

function matchesAny(line) {
  for (const p of PATTERNS) {
    if (p.regex.test(line)) return p;
  }
  return null;
}

// -----------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------
const positiveDir = join(REPO_ROOT, 'tests', 'secret-patterns', 'positive');
const negativeDir = join(REPO_ROOT, 'tests', 'secret-patterns', 'negative');

let failures = 0;
let positiveChecked = 0;
let negativeChecked = 0;

// --- POSITIVE ---
console.log('▶ Positive corpus (every line must match)');
for (const file of walk(positiveDir)) {
  const rel = file.replace(REPO_ROOT + '/', '').replace(/\\/g, '/');
  for (const { line, lineNo } of readLines(file)) {
    positiveChecked++;
    const hit = matchesAny(line);
    if (!hit) {
      failures++;
      console.log(`  ✖ ${rel}:${lineNo} — NO PATTERN MATCHED`);
      console.log(`     ${line.slice(0, 120)}${line.length > 120 ? '…' : ''}`);
    }
  }
}
console.log(`  checked ${positiveChecked} positive lines`);

// --- NEGATIVE ---
console.log('▶ Negative corpus (no line may match)');
for (const file of walk(negativeDir)) {
  const rel = file.replace(REPO_ROOT + '/', '').replace(/\\/g, '/');
  for (const { line, lineNo } of readLines(file)) {
    negativeChecked++;
    const hit = matchesAny(line);
    if (hit) {
      failures++;
      console.log(`  ✖ ${rel}:${lineNo} — UNEXPECTED MATCH (${hit.id})`);
      console.log(`     ${line.slice(0, 120)}${line.length > 120 ? '…' : ''}`);
    }
  }
}
console.log(`  checked ${negativeChecked} negative lines`);

// --- REPORT ---
console.log('');
if (failures === 0) {
  console.log(`✔ All ${positiveChecked + negativeChecked} cases passed`);
  console.log(`  recall on positives: 100%`);
  console.log(`  precision on negatives: 100%`);
  process.exit(0);
} else {
  console.log(`✖ ${failures} failure(s) — see above`);
  process.exit(1);
}
