/**
 * Replay cache for unseal token ops_id tracking (SEC-006).
 *
 * Wired into api.ts unseal() by default. Callers can inject a custom
 * implementation (e.g. Redis-backed) or pass null to opt out.
 *
 * Design notes:
 * - Interface is sync-only in 0.2.0. unseal() is sync; changing it to async
 *   is a breaking change deferred to 0.3.0. Custom async backings must wrap
 *   themselves in a sync-friendly facade.
 * - InProcessReplayCache is NOT re-exported from the package's public surface
 *   (D-8). Only the ReplayCache interface is public.
 * - Soft cap of 10 000 uses insertion-order eviction (Map is insertion-ordered
 *   per spec in V8). No periodic timer — avoids unref'd handles in test runners.
 */

/**
 * Interface for ops_id replay protection.
 *
 * Implement this interface to provide a custom replay cache backend
 * (e.g. Redis, Memcached, shared database). Only the ReplayCache interface
 * is part of the public API — InProcessReplayCache is package-internal.
 */
export interface ReplayCache {
  /**
   * Return true if opsId has been seen within its TTL window.
   * Must be synchronous in 0.2.0.
   */
  isOpsIdSeen(opsId: string): boolean;

  /**
   * Record opsId as seen with its absolute expiry (seconds since epoch).
   * Throwing from this method signals a backend outage — the caller will
   * fail closed (TOKEN_INVALID, cause: replay-cache-unavailable).
   * Must be synchronous in 0.2.0.
   */
  markOpsIdSeen(opsId: string, expiresAtEpochSec: number): void;
}

const SOFT_CAP = 10_000;

/**
 * Default in-process replay cache backed by a Map (insertion-ordered).
 *
 * NOT exported from the public package surface. Power users who need to
 * extend or decorate this class should implement ReplayCache directly.
 *
 * Thread-safety: single-threaded Node process — no locking needed.
 * Cap: evicts the oldest-inserted entry when size exceeds SOFT_CAP.
 * GC: expired entries are lazily evicted on isOpsIdSeen reads.
 */
export class InProcessReplayCache implements ReplayCache {
  private readonly entries = new Map<string, number>(); // opsId → expiresAtEpochSec

  isOpsIdSeen(opsId: string): boolean {
    const exp = this.entries.get(opsId);
    if (exp === undefined) return false;
    if (exp * 1000 <= Date.now()) {
      this.entries.delete(opsId); // expired — treat as unseen, GC inline
      return false;
    }
    return true;
  }

  markOpsIdSeen(opsId: string, expiresAtEpochSec: number): void {
    this.entries.set(opsId, expiresAtEpochSec);
    // Soft cap: evict oldest entry when over limit. Map iteration is insertion-ordered.
    if (this.entries.size > SOFT_CAP) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) {
        this.entries.delete(oldest);
      }
    }
  }
}
