/**
 * Indicators of Compromise (IOCs) for Shai-Hulud and its variants.
 *
 * This module is the runtime mirror of `threat-research/analysis/ioc-table.md`
 * — when that document changes, this module must be updated.
 *
 * Sources (canonical citations):
 *   - Datadog Security Labs, "Shai-Hulud Goes Open Source" (2026-05-13)
 *   - StepSecurity, "Mini Shai-Hulud Is Back" (2026-05-19)
 *   - Snyk, TanStack + AntV campaign analyses (2026-05)
 *   - Socket.dev, TanStack postmortem (2026-05)
 *   - Upwind, "Shai-Hulud: Here We Go Again" (2026-05)
 *   - Mondoo, "When Worm Source Code Goes Open Source" (2026-05)
 *
 * All entries are exact-match where possible (specific version pins).
 * For pattern-based detection (file shapes, script names), the matching
 * lives in scanner.ts — this module only carries the data.
 */

/**
 * Known-malicious npm packages and the exact versions confirmed by
 * public researcher publications. We do NOT include ranges (e.g. "any
 * 0.x") — those false-positive on legitimate older versions of the
 * same packages.
 */
export interface CompromisedPackage {
  /** Exact npm package name. */
  name: string;
  /** Versions confirmed malicious by research. Exact strings only. */
  versions: readonly string[];
  /** Campaign label for the operator's awareness. */
  campaign: string;
  /** Researcher citation URL — included in finding output. */
  citation: string;
}

export const COMPROMISED_PACKAGES: readonly CompromisedPackage[] = [
  {
    name: '@tanstack/react-router',
    versions: ['1.169.5', '1.169.8'],
    campaign: 'Mini Shai-Hulud TanStack (May 11, 2026)',
    citation: 'https://snyk.io/blog/tanstack-npm-packages-compromised/',
  },
  {
    name: '@tanstack/router-core',
    versions: ['1.169.5', '1.169.8'],
    campaign: 'Mini Shai-Hulud TanStack (May 11, 2026)',
    citation: 'https://snyk.io/blog/tanstack-npm-packages-compromised/',
  },
  {
    name: '@opensearch-project/opensearch',
    versions: ['3.6.2'],
    campaign: 'Mini Shai-Hulud TanStack (May 11, 2026)',
    citation: 'https://snyk.io/blog/tanstack-npm-packages-compromised/',
  },
  {
    name: '@mistralai/mistralai',
    versions: ['2.2.3', '2.2.4'],
    campaign: 'Mini Shai-Hulud TanStack (May 11, 2026)',
    citation: 'https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html',
  },
  {
    name: 'chalk-tempalte', // typosquat of chalk-template
    versions: ['*'], // all versions of the typosquat are malicious
    campaign: 'Shai-Hulud clone typosquat (May 14, 2026)',
    citation:
      'https://mondoo.com/blog/shai-hulud-clones-arrive-when-worm-source-code-goes-open-source',
  },
  // NOTE: The AntV campaign published 639 malicious versions across
  // 323 packages on May 19 in a 22-minute burst. Listing every
  // affected version here is impractical; the time-bounded heuristic
  // is "any @antv/* version published between 2026-05-19T01:39Z and
  // 2026-05-19T02:18Z UTC". For static IOC checking we list a few
  // confirmed high-impact ones; the full list is best consulted via
  // Snyk's vuln DB (security.snyk.io/antv-supply-chain-compromise-may-2026).
];

/**
 * File names that should NEVER appear at the root of an npm package's
 * installed `node_modules/<pkg>/` directory. These are loader files
 * the Shai-Hulud framework drops into the tarball.
 */
export const SUSPICIOUS_PACKAGE_ROOT_FILES: readonly string[] = [
  'router_init.js',
  'tanstack_runner.js',
  'opensearch_init.js',
  'setup.mjs',
  'config.mjs', // when at package root and not part of normal package shape
];

/**
 * `package.json` `scripts.*install*` patterns considered suspicious.
 * Any script value containing these strings warrants manual inspection.
 * This is intentionally NARROW — broad patterns (e.g. "node ") would
 * false-positive on legitimate postinstall hooks.
 */
export const SUSPICIOUS_INSTALL_SCRIPT_SUBSTRINGS: readonly string[] = [
  'setup.mjs',
  'router_init.js',
  'tanstack_runner.js',
  'opensearch_init.js',
];

/**
 * Persistence-marker filename substrings (case-insensitive match).
 * These overlap with the doctor command's persistenceMarkers check
 * but are duplicated here so `hunt-shai-hulud` can run standalone
 * without invoking the full doctor flow.
 */
export const PERSISTENCE_NAME_SUBSTRINGS: readonly string[] = [
  'gh-token-monitor',
  'pgsql-monitor',
  'pg-monitor',
  'token-monitor',
];

/**
 * Network indicators. We do NOT actively probe these — they're listed
 * only for the finding output so the operator knows what to grep for
 * in their firewall/DNS logs.
 */
export const NETWORK_IOCS: readonly { indicator: string; type: string; context: string }[] = [
  { indicator: 'git-tanstack.com', type: 'domain', context: 'Primary C2 exfiltration (HTTPS)' },
  { indicator: '83.142.209.194', type: 'IPv4', context: 'C2 infrastructure' },
  { indicator: 'filev2.getsession.org', type: 'domain', context: 'Session-protocol CDN exfil' },
  { indicator: 'seed1.getsession.org', type: 'domain', context: 'Session pinned-cert host' },
  { indicator: 'api.masscan.cloud', type: 'domain', context: 'Secondary direct C2' },
];
