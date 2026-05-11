/**
 * TOTP rate-limit helper for `sealed-env unseal` (SEC-009).
 *
 * Persists a per-master-key attempt counter at:
 *   ~/.sealed-env-state/unseal-attempts/<sha256(masterKey)[0..16] hex>
 *
 * Mode 0o600 (owner read/write only). Written atomically via writeSealedFile.
 *
 * Rules:
 *  - 5 failed TOTP attempts within a 300-second window → 300-second lockout.
 *  - Successful unseal resets the counter (file deleted).
 *  - Expired lockout: the next failure starts a fresh window (attempts = 1).
 *  - Missing or corrupt file → fresh state (0 attempts, no lockout).
 *
 * The fingerprint (sha256[0..16] hex) MUST NEVER appear in any log output,
 * error message, or stderr. This module does not log the fingerprint.
 */

import fs from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import { sha256 } from '../../core/crypto.js';
import { writeSealedFile } from './io.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WINDOW_MS = 300_000;   // 5-minute sliding window
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 300_000;  // 5-minute lockout after threshold

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AttemptState {
  attempts: number;
  firstFailureAt: number;      // epoch ms; 0 when no failures in current window
  lockedUntil: number | null;  // epoch ms; null when not locked
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

function stateDir(): string {
  return join(homedir(), '.sealed-env-state', 'unseal-attempts');
}

function fingerprint(masterKey: Buffer): string {
  return sha256(masterKey).subarray(0, 16).toString('hex');
}

function pathFor(masterKey: Buffer): string {
  return join(stateDir(), fingerprint(masterKey));
}

// ---------------------------------------------------------------------------
// State serialisation helpers
// ---------------------------------------------------------------------------

function freshState(): AttemptState {
  return { attempts: 0, firstFailureAt: 0, lockedUntil: null };
}

function parseState(raw: unknown): AttemptState {
  if (typeof raw !== 'object' || raw === null) return freshState();
  const r = raw as Record<string, unknown>;

  const attempts =
    typeof r['attempts'] === 'number' ? r['attempts'] : 0;

  const firstFailureAt =
    typeof r['firstFailureAt'] === 'string' && r['firstFailureAt']
      ? Date.parse(r['firstFailureAt'] as string)
      : 0;

  const lockedUntilRaw = r['lockedUntil'];
  const lockedUntil =
    typeof lockedUntilRaw === 'string' && lockedUntilRaw
      ? Date.parse(lockedUntilRaw)
      : null;

  return {
    attempts: Number.isFinite(attempts) ? attempts : 0,
    firstFailureAt: Number.isFinite(firstFailureAt) ? firstFailureAt : 0,
    lockedUntil:
      lockedUntil !== null && Number.isFinite(lockedUntil) ? lockedUntil : null,
  };
}

function serialise(state: AttemptState): string {
  return JSON.stringify({
    attempts: state.attempts,
    firstFailureAt: state.firstFailureAt
      ? new Date(state.firstFailureAt).toISOString()
      : new Date(0).toISOString(),
    lockedUntil: state.lockedUntil
      ? new Date(state.lockedUntil).toISOString()
      : null,
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Read the attempt state for the given master key.
 * Returns fresh state (0 attempts) on ENOENT, EACCES, or JSON parse error.
 */
export function getAttemptState(masterKey: Buffer): AttemptState {
  const p = pathFor(masterKey);
  if (!fs.existsSync(p)) return freshState();
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8')) as unknown;
    return parseState(raw);
  } catch {
    // Corruption, permission error, or invalid JSON → fresh state.
    // NEVER block a legitimate operator due to a bad counter file.
    return freshState();
  }
}

/**
 * Returns true if the state reflects an active lockout (lockedUntil > now).
 * A lockedUntil in the past is treated as unlocked.
 */
export function isLocked(state: AttemptState): boolean {
  return state.lockedUntil !== null && state.lockedUntil > Date.now();
}

/**
 * Record a failed TOTP attempt for the given master key.
 * Creates or updates the counter file atomically (mode 0o600).
 * Returns the updated state.
 */
export function recordFailedAttempt(masterKey: Buffer): AttemptState {
  // Ensure parent directory exists with mode 0o700.
  fs.mkdirSync(stateDir(), { recursive: true, mode: 0o700 });

  const now = Date.now();
  const cur = getAttemptState(masterKey);

  let { attempts, firstFailureAt, lockedUntil } = cur;

  // Expired lockout → treat as fresh window.
  if (lockedUntil !== null && lockedUntil <= now) {
    attempts = 0;
    firstFailureAt = 0;
    lockedUntil = null;
  }

  // Window roll-over: no prior failure in window, or the window has elapsed.
  if (firstFailureAt === 0 || now - firstFailureAt > WINDOW_MS) {
    attempts = 1;
    firstFailureAt = now;
  } else {
    attempts += 1;
  }

  if (attempts >= MAX_ATTEMPTS) {
    lockedUntil = now + LOCKOUT_MS;
  }

  const next: AttemptState = { attempts, firstFailureAt, lockedUntil };

  // Atomic write via the existing SEC-003 helper (temp + fsync + rename), mode 0o600.
  writeSealedFile(pathFor(masterKey), serialise(next));

  return next;
}

/**
 * Delete the counter file for the given master key.
 * Called on successful unseal to reset the attempt window.
 * Tolerates ENOENT (file may not exist on first success).
 */
export function resetAttempts(masterKey: Buffer): void {
  try {
    fs.rmSync(pathFor(masterKey), { force: true });
  } catch {
    // Ignore any error — the important thing is the file is gone or never existed.
  }
}
