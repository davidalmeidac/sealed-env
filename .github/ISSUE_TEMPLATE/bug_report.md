---
name: Bug report
about: Something is broken or behaves unexpectedly. (For SECURITY issues — read SECURITY.md, do NOT file here.)
title: "bug: <short description>"
labels: ["bug", "needs-triage"]
assignees: ["davidalmeidac"]
---

> **⚠️ Security note**: if this bug has security implications (key recovery,
> bypass of integrity checks, oracle-style information leaks, etc.) — STOP
> and read [SECURITY.md](../../SECURITY.md). Public issues for security
> bugs help attackers, not the project.

## Summary

<!-- One paragraph: what happens, what you expected. -->

## Environment

- **Implementation**: Node / Java
- **Package version**:
  - npm `sealed-env`: `<version>` (e.g. `0.1.0-alpha.1`)
  - or Maven `io.github.davidalmeidac:sealed-env-core`: `<version>`
  - or Maven `io.github.davidalmeidac:sealed-env-spring-boot-starter`: `<version>`
- **Mode**: `basic` / `team` / `enterprise`
- **OS**: <e.g. Ubuntu 24.04 / macOS 15.2 / Windows 11>
- **Runtime**: Node `<version>` / JDK `<vendor + version>`
- **Spring Boot version** (if applicable):

## Minimal reproduction

<!-- The smallest code/CLI invocation that triggers the bug. Ideally <30 lines. -->

```js
// or .java, or shell commands
```

## Expected behavior

<!-- What should happen. -->

## Actual behavior

<!-- What does happen. Include the FULL error message and stack trace. -->

```
<paste here>
```

## Have you checked?

- [ ] I am running a current version (`>=0.1.0-alpha.1`).
- [ ] I read the relevant doc page in `/docs/`.
- [ ] My `.env.sealed` file is not corrupt (a fresh re-seal works).
- [ ] This is **not** a security-sensitive bug (otherwise: see SECURITY.md).

## Additional context

<!-- Logs, screenshots, related issues, anything else useful. -->
