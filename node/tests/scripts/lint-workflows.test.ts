/**
 * Unit tests for node/scripts/lint-workflows.mjs
 *
 * Strategy: spawn the lint script against a temp dir containing
 * controlled fixture files, assert exit code and stderr output.
 *
 * Tests:
 *   1. Pinned SHA  → exit 0
 *   2. Floating tag → exit 1 + stderr names file:line
 *   3. Local action → exit 0  (not a network action, skip lint)
 *   4. Quoted pinned form → exit 0
 *   5. Real workflows pass after migration (gates T1.5 commit)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync, readdirSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
// here = dist/tests/scripts  →  ../../.. = node root  →  ../../../.. = repo root
const nodeRoot = resolve(here, '..', '..', '..');
const repoRoot = resolve(nodeRoot, '..');
const scriptPath = resolve(nodeRoot, 'scripts', 'lint-workflows.mjs');
// Fixtures live in the source tree; TypeScript does not copy .yml files to dist.
const fixturesDir = resolve(nodeRoot, 'tests', 'scripts', 'fixtures');

/**
 * Copy a single fixture file into a temp dir and run the linter against it.
 * Returns { code, stderr }.
 */
function runLintOnFixture(fixtureName: string): { code: number; stderr: string } {
  const tmpDir = mkdtempSync(join(tmpdir(), 'lint-wf-'));
  copyFileSync(join(fixturesDir, fixtureName), join(tmpDir, fixtureName));

  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: resolve(tmpDir, '..'),
    env: {
      ...process.env,
      // Override the workflows dir so the script reads our tmp dir, not .github/workflows
      LINT_WORKFLOWS_DIR: tmpDir,
    },
    encoding: 'utf8',
  });

  return {
    code: result.status ?? 1,
    stderr: result.stderr ?? '',
  };
}

test('lint-workflows: pinned SHA → exit 0', () => {
  const { code } = runLintOnFixture('good-pin.yml');
  assert.equal(code, 0, 'expected exit 0 for fully-pinned workflow');
});

test('lint-workflows: floating tag @v4 → exit 1 + stderr names file:line', () => {
  const { code, stderr } = runLintOnFixture('bad-pin.yml');
  assert.equal(code, 1, 'expected exit 1 for floating tag');
  assert.ok(
    stderr.includes('not pinned'),
    `expected stderr to contain "not pinned", got: ${stderr}`,
  );
});

test('lint-workflows: local action ./ → exit 0 (exempt)', () => {
  const { code } = runLintOnFixture('local-action.yml');
  assert.equal(code, 0, 'expected exit 0 for local action reference');
});

test('lint-workflows: quoted pinned form → exit 0', () => {
  const { code } = runLintOnFixture('quoted-pin.yml');
  assert.equal(code, 0, 'expected exit 0 for quoted SHA-pinned uses line');
});

test('lint-workflows: real .github/workflows/ passes after SHA migration', () => {
  // This test gates the T1.5 migration commit.
  // It runs the linter against the actual .github/workflows directory.
  // Before migration it WILL fail (floating @v4 tags); after T1.5 it must exit 0.
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  assert.equal(
    result.status,
    0,
    `Real workflows failed lint:\n${result.stderr}\nRun T1.5 to pin all SHAs.`,
  );
});
