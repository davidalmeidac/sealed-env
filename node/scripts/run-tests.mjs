/**
 * Cross-platform test runner.
 *
 * Why this exists: `node --test` only auto-discovers test files in
 * directories starting with Node 21. Node 20 (still in our CI matrix)
 * needs explicit file paths. Shell glob expansion isn't portable
 * either — Windows cmd doesn't expand `**`, and quoting the glob in
 * package.json prevents bash from expanding it.
 *
 * Solution: walk dist/tests/ recursively, collect every *.test.js,
 * and spawn `node --test` with the explicit list.
 */

import { readdirSync, statSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const testsDir = resolve(here, '..', 'dist', 'tests');

function* findTestFiles(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      yield* findTestFiles(full);
    } else if (name.endsWith('.test.js')) {
      yield full;
    }
  }
}

const files = [...findTestFiles(testsDir)].sort();

if (files.length === 0) {
  console.error(
    `No test files found in ${testsDir}. Run \`npm run test:compile\` first.`,
  );
  process.exit(1);
}

const child = spawn(
  process.execPath,
  ['--test', '--test-reporter=spec', ...files],
  { stdio: 'inherit' },
);
child.on('exit', (code) => process.exit(code ?? 1));
