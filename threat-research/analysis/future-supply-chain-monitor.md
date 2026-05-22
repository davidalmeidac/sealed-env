# Future idea — Supply-Chain Monitor Bot

> **Status**: design / brainstorm only. Not committed to a release.
> Recorded here so the idea doesn't evaporate.

> **Origin**: David's idea (2026-05-22 evening) after the Shai-Hulud
> defense work. The hypothesis: a lightweight bot that watches npm,
> Maven Central, and PyPI for packages matching Shai-Hulud-class
> signatures, publishes a community IOC feed, and `sealed-env`
> consumes that feed at install time to warn the operator.

---

## Problem statement

Existing supply-chain security tools (Socket.dev, Snyk Advisor,
Phylum, Aikido, StepSecurity, npm built-in detection) operate as
**commercial SaaS** or with significant free-tier limits. They are
broad and excellent, but:

- They require an account / login / telemetry
- They lock the most useful detail behind paywalls
- They focus on npm; cross-ecosystem (Maven Central, PyPI) coverage
  is uneven
- Detection of **Shai-Hulud-specific signatures** is a side feature,
  not a focus — these vendors prioritize breadth

A sealed-env user who shipped enterprise mode + keychain push has
done their homework on credential handling. But the **next** malicious
package they `npm install` will still execute its postinstall before
sealed-env even loads. The defensive gap is **at install-time, before
sealed-env runs at all**.

Filling that gap requires either:

1. A list of known-bad packages to compare against
2. A heuristic to detect bad packages on the fly
3. Both

This document scopes option (1) as a small, open, community-maintainable
project that sealed-env can consume.

---

## What we are NOT building

To stay honest about scope:

- **Not** a general-purpose npm malware scanner — Socket already does
  this well
- **Not** a runtime sandbox — Phylum and others do this
- **Not** a replacement for `npm audit` — that's npm's job and they
  do it
- **Not** a commercial product — no paywall, no SaaS, no auth layer

What we ARE building is **a curated IOC feed**, narrow in scope but
high in signal, that `sealed-env scan --check-feed` consumes.

---

## Architecture sketch

```
                                  ┌──────────────────────────────┐
                                  │  GitHub Pages JSON feed       │
                                  │  iocs.sealed-env.dev/         │
                                  │    npm.json                   │
                                  │    maven.json                 │
                                  │    pypi.json                  │
                                  └──────────────┬───────────────┘
                                                 │
                            ┌────────────────────┼────────────────────┐
                            │                    │                    │
                            ▼                    ▼                    ▼
                  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
                  │ sealed-env scan │  │ sealed-env      │  │ Any third-party │
                  │ --check-feed    │  │ install hook    │  │ tool that wants │
                  │ (CLI / CI gate) │  │ (advisory only) │  │ to consume      │
                  └─────────────────┘  └─────────────────┘  └─────────────────┘
                                                 ▲
                                                 │ generates
                            ┌────────────────────┴────────────────────┐
                            │                                         │
              ┌─────────────────────┐                   ┌─────────────────────┐
              │  Detector workers   │                   │  Human triage       │
              │  (GitHub Actions    │                   │  (David + future    │
              │   cron, hourly)     │                   │   collaborators)    │
              │                     │                   │                     │
              │  Signature checks:  │                   │  Approve / reject   │
              │  - +3 patch bump    │                   │  each candidate     │
              │  - optionalDeps     │                   │  IOC before it      │
              │    pointing to      │                   │  reaches the feed   │
              │    github: forks    │                   │                     │
              │  - *_init.js at     │                   │  All decisions      │
              │    pkg root         │                   │  recorded as PRs    │
              │  - bun runtime in   │                   │  on the feed repo   │
              │    declared deps    │                   │                     │
              │  - sudden 5x size   │                   │                     │
              │    increase        │                   │                     │
              │  - publish via OIDC │                   │                     │
              │    by author who    │                   │                     │
              │    never did before │                   │                     │
              └─────────────────────┘                   └─────────────────────┘
                            ▲                                         ▲
                            │ polls                                   │ informs
                            │                                         │
              ┌─────────────────────┐                   ┌─────────────────────┐
              │  Registry APIs       │                   │  Researcher reports │
              │  - registry.npmjs.org│                   │  (Datadog, Snyk,    │
              │  - search.maven.org  │                   │   Socket, Upwind…)  │
              │  - pypi.org/pypi/    │                   │  Manual paste into  │
              └─────────────────────┘                   │  GitHub issues      │
                                                        └─────────────────────┘
```

---

## Signatures the bot can detect (initial set)

These are the Shai-Hulud-specific patterns documented across Datadog,
StepSecurity, Upwind, Snyk, Socket, Aikido, Phoenix Security. None of
them is sufficient alone; combining 2-3 signals raises a candidate
to human triage.

### npm signatures

| Signature | Detection | Source |
|---|---|---|
| **Version jump exactly +3 patch** | Compare published versions: `1.169.5 → 1.169.8` | Upwind, Phoenix |
| **`optionalDependencies` referencing `github:` URL with commit SHA** | Parse new release `package.json` | StepSecurity, Snyk |
| **`router_init.js` / `*_init.js` at package root (outside `dist/`)** | Inspect tarball file list | Datadog, StepSecurity |
| **Sudden ≥5× package size increase between versions** | Compare tarball sizes | Aikido |
| **`bun` declared as engine/dependency where it wasn't before** | Diff `package.json` | StepSecurity |
| **`preinstall` script added between versions** | Diff `scripts.*install*` | Datadog |
| **Publish via OIDC from a publisher who never used OIDC before** | npm provenance metadata | Inferred from CVE-2026-45321 chain |
| **Description contains "Shai-Hulud"** | Plain string match in package metadata | Datadog |

### Maven Central signatures (lower volume, easier to monitor)

| Signature | Detection |
|---|---|
| New artifact published under a `groupId` that previously had no activity for ≥6 months | Compare release timestamps |
| Artifact size jumps ≥5× between versions | Compare jar sizes |
| New `META-INF/services/*` entries claiming to override well-known JDK APIs | Inspect jar contents |

### PyPI signatures

| Signature | Detection |
|---|---|
| `setup.py` containing `exec()` or `eval()` of network-fetched content | Parse setup script |
| Package name typo-distance ≤2 from a top-1000 package | Levenshtein vs top-N list |
| New release within 24h of a typo-target's release | Time-correlate |

---

## Feed format (proposed)

JSON over HTTPS. Versioned schema. Cacheable.

```json
{
  "schema": "sealed-env-ioc/v1",
  "ecosystem": "npm",
  "generated_at": "2026-05-22T20:00:00Z",
  "next_update_at": "2026-05-22T21:00:00Z",
  "entries": [
    {
      "id": "se-ioc-npm-001",
      "package": "@tanstack/react-router",
      "version": "1.169.5",
      "status": "confirmed_malicious",
      "first_seen_at": "2026-05-11T14:23:00Z",
      "signatures_triggered": ["router_init_at_root", "github_commit_optional_dep"],
      "researcher_citations": [
        "https://snyk.io/blog/tanstack-npm-packages-compromised/",
        "https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
      ],
      "cve": "CVE-2026-45321",
      "advice": "Pin to 1.169.4 or earlier, or 1.169.9 if maintainer has patched."
    },
    {
      "id": "se-ioc-npm-002",
      "package": "chalk-tempalte",
      "version": "*",
      "status": "confirmed_malicious",
      "first_seen_at": "2026-05-14T08:11:00Z",
      "signatures_triggered": ["typosquat", "preinstall_added"],
      "researcher_citations": [
        "https://mondoo.com/blog/shai-hulud-clones-arrive-when-worm-source-code-goes-open-source"
      ],
      "cve": null,
      "advice": "Typosquat of chalk-template. Never install."
    }
  ]
}
```

Same shape for `maven.json` and `pypi.json`. Each ecosystem gets its
own file so consumers don't pay download cost for ecosystems they
don't use.

---

## sealed-env integration

```bash
# CI gate: fail the build if a current dep matches the feed
sealed-env scan --check-feed --feed=https://iocs.sealed-env.dev/npm.json

# Pre-commit hook: same as above + check staged files
sealed-env scan --check-feed --staged

# Just print findings, don't fail
sealed-env scan --check-feed --json
```

`--check-feed` semantics:
- Parses `package-lock.json` / `pom.xml` / `requirements.txt`
- Cross-references each installed (name, version) against the feed
- Reports findings with `pattern_id: "feed:<ioc-id>"` in the same JSON
  schema as the existing `sealed-env scan` output
- Cache the feed locally for 1 hour (configurable) to avoid hammering
  the IOC server

---

## Phases (if/when we build this)

### Phase 0 — Decide if anyone wants it (1 week of asking)

Before writing a line of code: post the idea on dev.to, /r/netsec,
hackernews. Ask if anyone would actually USE a free, open-source,
narrow-scope IOC feed for Shai-Hulud variants. If 20 people say yes,
build Phase 1. If nobody cares, fold the idea into `shai-hulud-defense.md`
and move on.

### Phase 1 — Manual feed, no bot (4-6 hours)

Just a GitHub repo with `npm.json` / `maven.json` / `pypi.json` that
David and any future contributors update manually based on researcher
reports. No bot at all. This proves the format works, lets sealed-env
implement `--check-feed`, and gives a foundation for automation.

### Phase 2 — Detection bot, narrow signatures (2-3 weeks)

GitHub Action cron that runs hourly. Polls npm registry for new
releases. Runs the 8 signatures listed above. Any package triggering
≥2 signatures opens an issue on the feed repo with the candidate IOC
prefilled. Human triages, merges, the JSON updates.

### Phase 3 — Cross-ecosystem coverage (4-6 weeks)

Same approach but for Maven Central + PyPI. These have lower volume
and weirder APIs, so the bot needs separate workers per ecosystem.

### Phase 4 — Community contributions (open-ended)

Once the format and triage process are stable, accept PRs from
researchers who paste findings from their own analyses. Possibly
federate with other community feeds (OSS Insight, OSV.dev, GitHub
Advisory Database).

---

## Open questions

1. **Naming**: `iocs.sealed-env.dev`? Or a more neutral name so it
   doesn't look like a sealed-env-exclusive thing? Maybe
   `supply-chain-iocs.org` or hosted under an OpenSSF subdomain?

2. **Governance**: solo project under David's GitHub forever, or
   structured as OpenSSF working group from day 1?

3. **Trust model**: how do we prove the feed itself isn't tampered
   with? Sign the JSON with sigstore? Mirror the feed in multiple
   places?

4. **False-positive policy**: what's the appeal process if a
   maintainer disagrees with their package being flagged? "Mark as
   reviewed safe" mechanism?

5. **Legal**: hosting a list of "malicious packages" might have legal
   exposure if a flag is wrong. Need a DMCA-style takedown process +
   liability disclaimer.

6. **Resource cost**: GitHub Pages is free. GitHub Actions cron is
   free up to limits. Polling npm at 1 request/minute is ~43k req/day
   — within their rate limits but worth verifying. PyPI and Maven
   Central also have rate limits.

7. **Adoption metric**: 100 weekly fetches of the JSON = real usage.
   Below that, fold it into a less ambitious form.

---

## Why this might NOT be worth building (devil's advocate)

- **Socket already does this**, with a much better team and better
  signal. We'd be competing on "free + open-source" alone.
- **GitHub Advisory Database** is the canonical place for malicious
  package advisories. Maybe better to contribute upstream than build
  parallel infrastructure.
- **The maintenance burden** of a feed is real. If David goes on
  vacation for 2 weeks and a new Shai-Hulud variant lands, the feed
  is stale and harmful (false sense of security).
- **Detection lag**: by the time we publish an IOC, Socket and Snyk
  have already published theirs. We'd be a slower second source.

The honest counter-argument: even Socket and Snyk **disagree with each
other** about borderline cases. A third independent voice — open,
auditable, narrow-scope — is genuinely useful for cross-referencing.
And the "alimentación de sealed-env" angle is unique: sealed-env users
get integrated install-time warnings without configuring a separate
tool.

---

## What needs to exist first

Before any of this:

1. **Trusted publishing migration** (P2.1 in `improvement-roadmap.md`)
   — sealed-env itself needs to be unforgeable before we tell users
   to trust our feed
2. **Provenance verification documented** (P1.6 — done in 0.2.1)
3. **`sealed-env scan` JSON schema stable** — already shipped in 0.2.1
   as `sealed-env-scan/v1`; the feed format extends this
4. **At least 50 downloads/week of sealed-env from real human users**,
   not bots — otherwise we'd be building infrastructure for nobody

The third bullet is the real gate. Build a project that 1,000 people
use first, THEN add the feed. Backwards order = wasted effort.

---

## Conclusion (provisional)

This is a real idea with real value, in a crowded but not saturated
market. **Don't build it now.** Park it here. Revisit in 6 months
once sealed-env adoption is measurable. If by then a similar tool has
emerged organically from the OSS community, fold our contributions
into that. If not, Phase 1 is a one-weekend project.

The signatures table at the top of this doc is the actual deliverable
of this brainstorm: it's a concrete checklist of what to detect, and
sealed-env's own `sealed-env doctor` could implement 2-3 of them
locally (e.g., warn if `package-lock.json` contains an
`optionalDependencies` referencing a `github:` commit SHA) even
without building the feed.
