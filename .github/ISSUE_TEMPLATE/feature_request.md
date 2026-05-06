---
name: Feature request
about: Suggest a capability or improvement. Read CONTRIBUTING.md before filing major changes.
title: "feat: <short description>"
labels: ["enhancement", "needs-triage"]
assignees: ["davidalmeidac"]
---

## The problem

<!-- What real-world use case does this enable? Concrete is better than abstract. -->

## Proposal

<!-- What you'd like sealed-env to do. -->

## Alternatives considered

<!-- Other approaches you've thought of, including current workarounds, and
     why they're insufficient. -->

## Scope

Check all that apply:

- [ ] **Pure addition** — new optional API or feature, doesn't change existing behavior.
- [ ] **Modifies the public API** — existing callers may need to update.
- [ ] **Touches the wire format (.env.sealed v1 spec)** — see `SPEC.md`.
- [ ] **Touches cryptographic primitives or key derivation** — see CONTRIBUTING.md §"Crypto changes".
- [ ] **Touches the threat model** — see `THREAT_MODEL.md`.
- [ ] **Affects only Node, only Java, or both implementations** — specify:

## Context

- **Implementation(s) affected**: Node / Java / both
- **Mode(s) affected**: basic / team / enterprise / all
- **Stack you'd consume this from**: <e.g. Spring Boot 3.3, Express, NestJS, Quarkus...>

## What this is not

<!-- A short list of out-of-scope items so the discussion stays focused. -->

## Are you willing to contribute the implementation?

- [ ] Yes, I can submit a PR if the design is approved.
- [ ] Yes, but I'd need guidance on `<area>`.
- [ ] No, I'm requesting that the maintainer or community implement it.
