/**
 * SEC-002 CI benchmark: seal() with N=131072 must complete in [200ms, 2000ms]
 * on the GitHub Actions Linux runner.
 *
 * LINUX ONLY — skipped on macOS and Windows to avoid flaky results on
 * containers with different CPU budgets.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { seal } from '../../src/core/api.js';

test(
  'scrypt seal() with N=131072 defaults completes in [200ms, 2000ms] (Linux only)',
  { skip: process.platform !== 'linux' ? 'Linux-only benchmark' : false },
  () => {
    const masterKey = randomBytes(32);
    const samples: number[] = [];

    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      seal({ plaintext: `X=${i}\n`, masterKey, mode: 'basic' });
      samples.push(performance.now() - t0);
    }

    samples.sort((a, b) => a - b);
    const median = samples[2]!;

    assert.ok(
      median >= 200,
      `median ${median.toFixed(1)}ms < 200ms — scrypt params likely drifted weak`,
    );
    assert.ok(
      median <= 2000,
      `median ${median.toFixed(1)}ms > 2000ms — runner too slow or params too strong`,
    );
  },
);
