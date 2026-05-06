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

## Reference

- [Format specification (`SPEC.md`)](../SPEC.md) — the canonical wire format
- [Threat model (extended `THREAT_MODEL.md`)](../THREAT_MODEL.md)
- [Security policy](../SECURITY.md) — how to report vulnerabilities
- [Brand assets](../assets/README.md) — Roman sigillum and how to use it

## Diagrams

All diagrams in these docs are **plain ASCII**, rendered inside fenced
code blocks. They display correctly in GitHub, in any terminal, in `cat`
and `less`, and inside `git diff` — no JavaScript renderer required.

This is intentional: a security tool's docs should remain legible even
when the rendering layer is unavailable or untrusted.
