#!/usr/bin/env node
/**
 * Lint .github/workflows/*.yml — every `uses:` line MUST pin to a
 * 40-char commit SHA, with an optional trailing comment.
 *
 * Exit codes:
 *   0  all uses: lines pinned (or no non-local uses: lines found)
 *   1  one or more lines fail the pin regex (prints file:line:offender to stderr)
 *   2  unexpected error (e.g. workflows dir missing)
 *
 * Environment:
 *   LINT_WORKFLOWS_DIR  override the directory to lint (default: .github/workflows)
 *                       useful for unit tests pointing at fixture dirs
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const WORKFLOWS_DIR = process.env.LINT_WORKFLOWS_DIR ?? '.github/workflows';

// Matches a ref ending with @<40-hex-chars> — tested against the extracted
// ref value after stripping quotes, not the raw line.
const PIN_RE = /@[a-f0-9]{40}$/;

// Matches a uses: line (list-item form or map-value form, quoted or unquoted).
// Group 1: optional open quote, Group 2: the reference value, Group 3: trailing comment
const USES_RE = /^\s*-?\s*uses:\s*(['"]?)([^'";\s#]+)\1(\s*#.*)?$/;

let failed = 0;

try {
  const dir = resolve(WORKFLOWS_DIR);
  const files = readdirSync(dir).filter(
    (f) => f.endsWith('.yml') || f.endsWith('.yaml'),
  );

  for (const f of files) {
    const filePath = join(dir, f);
    const lines = readFileSync(filePath, 'utf8').split(/\r?\n/);

    lines.forEach((line, idx) => {
      const m = line.match(USES_RE);
      if (!m) return;

      const ref = m[2];
      // Local actions (./.github/actions/...) and docker images are not
      // pinnable by commit SHA — skip them.
      if (ref.startsWith('./') || ref.startsWith('docker://')) return;

      // Test the extracted ref value (not the raw line) to handle quoted forms
      // like uses: 'org/repo@<sha>' where a closing quote follows the SHA.
      if (!PIN_RE.test(ref)) {
        process.stderr.write(
          `${filePath}:${idx + 1}: not pinned to 40-char SHA: ${line.trim()}\n`,
        );
        failed++;
      }
    });
  }
} catch (err) {
  process.stderr.write(`lint-workflows: ${err.message}\n`);
  process.exit(2);
}

process.exit(failed > 0 ? 1 : 0);
