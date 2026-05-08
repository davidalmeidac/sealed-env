/**
 * HTTP health-check polling. Used by `deploy` (local and `--remote`)
 * after the deploy command exits, to verify the new build is actually
 * answering before the operator declares success.
 *
 * Uses Node's built-in fetch (Node 20+ has it without flags).
 *
 * Polling cadence: 1s between attempts. Each attempt has a 2-second
 * connect/read timeout, so a hung server doesn't burn the whole budget
 * on a single request.
 */

/**
 * Poll an HTTP endpoint until it returns 2xx or the timeout elapses.
 * Returns true if a 2xx was seen, false on timeout.
 *
 * Network errors during the polling window are treated as "not ready
 * yet" and retried — a deploy in flight will refuse connections for a
 * few seconds, that's normal.
 */
export async function pollHealth(url: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return true;
    } catch {
      /* swallow, keep retrying — server may not be up yet */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}
