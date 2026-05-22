# Threat Research — Static Malware Analysis Sandbox

This directory contains the **methodology, environment, and analysis notes**
for sealed-env's threat research program. Right now (May 2026), the active
investigation is the leaked Shai-Hulud framework published by TeamPCP on
2026-05-12.

> ⚠️ **WE NEVER COMMIT MALWARE SAMPLES TO THIS REPO.**
> The `samples/` directory is gitignored. Researchers download samples
> directly into the sandbox container at analysis time; they are discarded
> when the container exits.

---

## Why static analysis only

This sandbox is for **static** analysis: reading source code, tracing
control flow on paper, computing hashes, deobfuscating strings. We never
execute the malware. Static analysis is sufficient to:

- Identify which files the malware reads from disk
- Trace credential exfiltration paths
- Map encryption / obfuscation routines
- Extract IOCs (C2 domains, hardcoded strings, embedded keys)
- Cross-reference findings with published research

Dynamic analysis (running the malware in a sandbox) is **out of scope for
this directory**. Dynamic analysis carries operational risks that require
a different environment (network sinkhole, kernel-level monitoring, etc.)
and a different threat model (operator + reviewer agreement, legal review).

---

## Threat model of this sandbox

We isolate against these specific risks:

| Risk | Mitigation |
|---|---|
| Accidental execution exfiltrates credentials from host | Docker `--network=none` — no socket, no DNS, no HTTP |
| Malware writes to host filesystem | Read-only volume mount; `tmpfs` for /tmp |
| Researcher accidentally runs `bun install` / `npm install` | Container has Bun and Node REMOVED; only static tools |
| Source files persist after analysis ends | Container is `--rm`; samples in tmpfs |
| Kernel exploit escapes container | Host already runs Docker in Hyper-V VM (Windows) — double isolation |

What we don't defend against (acceptable risks for static analysis):

- Reading the static source code from outside the container (it's text;
  reading text is safe by definition).
- Visual / cognitive risks (you might learn an attack technique). Inherent
  to research; mitigated by responsible disclosure norms.

---

## Setup

### Prerequisites
- Docker Desktop running on Windows (already installed for sealed-env dev)
- ~500 MB free disk for the sandbox image

### Build the sandbox image (one-time)

```bash
cd threat-research
docker build -f Dockerfile.sandbox -t sealed-env-research .
```

### Enter the sandbox

```bash
# Spawn a new container, mount the analysis dir read-write,
# and DROP every network capability.
docker run --rm -it \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,size=512m \
  --tmpfs /workspace:rw,size=512m \
  -v "$(pwd)/analysis:/host-analysis:rw" \
  -v "$(pwd)/notes:/host-notes:rw" \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  sealed-env-research
```

You land in `/workspace`. Download samples here. They disappear when you
`exit` because `/workspace` is tmpfs.

### Verify isolation

Inside the container, these should all FAIL:

```bash
curl https://example.com         # → curl not installed; if it were, network=none kills it
ping 8.8.8.8                     # → no network namespace
which bun                        # → not installed
which node                       # → not installed
ls / | grep -i secret            # → host secrets not mounted
```

These should WORK:

```bash
bat --help                       # syntax-highlighted cat
rg --help                        # ripgrep
fd --help                        # find replacement
sha256sum --help                 # for IOC verification
strings --help                   # extract printable strings from binaries
xxd --help                       # hex dump
```

---

## Workflow

1. **Identify a sample to analyze.** Use the IOC table at
   `analysis/ioc-table.md` to pick a known artifact (e.g.
   `tanstack_runner.js` with hash `2ec78d556d...`).

2. **Acquire the sample.** Inside the container (which has no network), you
   can't download. Instead:
   - Either download to the HOST first, then copy in:
     `docker cp tanstack_runner.js <container_id>:/workspace/`
   - Or copy from a host directory you mount read-only at run time
   - **Verify the hash matches expected** before any analysis

3. **Analyze.** Use the static tools. Document findings in
   `notes/<sample-name>.md`. Never run the sample.

4. **Persist findings.** Anything in `/host-analysis` and `/host-notes`
   stays on the host. Everything in `/workspace` and `/tmp` is wiped.

5. **Exit.** `exit` or `Ctrl+D`. Container is auto-removed (`--rm`).

---

## Layout

```
threat-research/
├── README.md                  ← this file
├── .gitignore                 ← excludes samples/ aggressively
├── Dockerfile.sandbox         ← the analysis container image
├── analysis/                  ← committed: shared notes, IOC tables, diagrams
│   └── ioc-table.md
├── notes/                     ← committed: per-sample writeups
│   └── shai-hulud-overview.md
└── samples/                   ← gitignored: where you put downloaded artifacts
```

---

## Legal & ethical notes

- **Purpose**: defensive research only. We publish findings to harden
  sealed-env and the broader ecosystem. We do not publish working malware
  samples, we do not test on third-party systems, we do not deploy any
  derived code.
- **Source acquisition**: we download samples only from researcher-curated
  archives (Datadog, Phylum, SnykResearch, etc.) — NOT from active C2 or
  from the TeamPCP-controlled GitHub forks. The leaked code is MIT-licensed
  by the attacker, but the moral test is "would a responsible journalist
  publish this?"
- **No execution**: ever. If you find yourself typing `bun run` or `node`,
  STOP. Save your work and start over with a fresh container.
