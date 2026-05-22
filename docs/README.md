# sealed-env documentation

Welcome. The docs are organized so you can read them in order, or jump to
the page you need.

## Reading order

1. [Overview](./01-overview.md) — what `sealed-env` is and isn't
2. [Threat model](./02-threat-model.md) — which 2024-2026 attacks it defends against
3. [Quick start: Node](./03-quickstart-node.md)
4. [Quick start: Java + Spring Boot](./04-quickstart-java.md)
5. [Enterprise mode](./05-enterprise-mode.md) — TOTP + deploy challenge
6. [File format anatomy](./06-format-anatomy.md) — what's inside `.env.sealed`
7. [Operational guide](./07-operational-guide.md) — for sysadmins, managers, and founders (no code)
8. [CI/CD + cloud recipes](./08-cicd-recipes.md) — GitHub Actions, GitLab, Bitbucket, CircleCI, Jenkins, Azure, AWS, GCP, Vercel, Railway, Docker, Kubernetes…
9. [Project lifecycle](./09-lifecycle.md) — init → onboarding → deploy as one narrative
10. [Decrypt strategies](./10-decrypt-strategies.md) — host-side vs in-process trade-off, `deploy --remote` spec

## Operations & incident response

- [Incident response playbook](./incident-response.md) — what to do if you
  suspect a host compromise. Read the **deadman switch warning** at the
  top before doing anything else. Order matters.

## Reference

- [Format specification (`SPEC.md`)](../SPEC.md) — the canonical wire format
- [Threat model (extended `THREAT_MODEL.md`)](../THREAT_MODEL.md)
- [Secret patterns (`SECRET-PATTERNS.md`)](../SECRET-PATTERNS.md) — canonical
  regex spec for every sensitive string sealed-env emits or consumes,
  for integration with gitleaks / trufflehog / GitHub Secret Scanning
- [Security policy](../SECURITY.md) — how to report vulnerabilities
- [Brand assets](../assets/README.md) — Roman sigillum and how to use it

## Threat research

Forward-looking defensive analysis that lives outside the canonical docs
because it's research, not specification:

- [Shai-Hulud defensive analysis](../threat-research/analysis/shai-hulud-defense.md)
  — module-by-module mapping of the leaked Shai-Hulud framework's TTPs
  to sealed-env's current defenses, with honest gap analysis
- [IOC table](../threat-research/analysis/ioc-table.md) — consolidated
  indicators from Datadog, StepSecurity, Upwind, Mondoo, Akamai
- [Improvement roadmap](../threat-research/analysis/improvement-roadmap.md)
  — prioritized hardening proposals for 0.2.2 and 0.3.0
- [Future: supply-chain IOC feed bot](../threat-research/analysis/future-supply-chain-monitor.md)
  — design brainstorm for a community-maintained malicious-package feed
- [Sandbox setup](../threat-research/README.md) — Docker isolation for
  static malware analysis (no execution)

## Diagrams

All diagrams in these docs are **plain ASCII**, rendered inside fenced
code blocks. They display correctly in GitHub, in any terminal, in `cat`
and `less`, and inside `git diff` — no JavaScript renderer required.

This is intentional: a security tool's docs should remain legible even
when the rendering layer is unavailable or untrusted.
