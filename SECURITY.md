# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `sealed-env`, **please do not open a
public issue**. Email **david.almeida@cun.edu.co** with:

- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Your suggested fix, if any

You will receive an acknowledgment within **48 hours** and a status update within
**5 business days**.

If the vulnerability is confirmed, we will:

1. Coordinate a fix with you
2. Issue a CVE if appropriate
3. Release a patched version
4. Credit you in the release notes (unless you prefer to remain anonymous)

## Supported versions

| Version | Status |
|---------|--------|
| 0.1.x   | ✅ supported |
| < 0.1.0 | not released |

We commit to back-porting fixes to the latest minor version of every supported
release line.

## Threat model

We publish our [full threat model](THREAT_MODEL.md). It explicitly enumerates:

- Attacks we defend against (with citations to real-world incidents)
- Attacks we **do not** defend against (with rationale)

We treat the threat model as part of the API contract. Changes that weaken
guarantees require a major version bump and a security advisory.

## Cryptographic agility and rotation

The file format is versioned (`SEALED-ENV-V1`). Future cryptographic changes
will be introduced through `V2`, `V3`, etc. Old readers gracefully refuse newer
files (no silent downgrade).

Master key rotation is supported via `sealed-env rotate`. We recommend rotating:

- After any suspected leak (immediate, with key revocation)
- Annually as a routine hygiene practice
- After major team membership changes

## Disclosure policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

- 90 days from initial report to public disclosure (default)
- Shorter if the vulnerability is being actively exploited
- Longer if a patch is unusually complex (with reporter agreement)

## Out-of-scope

The following are NOT considered vulnerabilities in `sealed-env`:

- Operator's machine compromise (we cannot defend against host-level malware)
- Master key written to a public place (operator error)
- Successful brute force given a weak master key (use a strong key)
- Vulnerabilities in upstream dependencies of consumer applications (report to them)
- Side-channel attacks specific to the JVM, Node, or hardware (out of our scope)

## Hall of fame

Researchers who report valid vulnerabilities will be listed here, with their
permission, after a fix ships:

_Empty so far. Be the first._
