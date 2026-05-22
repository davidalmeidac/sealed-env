#!/usr/bin/env bash
# Welcome banner for the sealed-env-research sandbox.
# Sourced by ~/.bashrc on every interactive shell.

cat <<'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  sealed-env-research sandbox — STATIC ANALYSIS ONLY              ║
║                                                                  ║
║  Allowed:    bat, rg, fd, sha256sum, strings, xxd, file, jq      ║
║  Forbidden:  bun, node, npm, python, curl, wget, anything that   ║
║              executes downloaded code or initiates network IO.   ║
║                                                                  ║
║  /workspace      tmpfs — wiped on exit                           ║
║  /host-analysis  rw mount — persists to host                     ║
║  /host-notes     rw mount — persists to host                     ║
║                                                                  ║
║  Network is DISABLED at the docker run level (--network=none).   ║
║  If you find yourself typing `bun run` or `node`, STOP.          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF

# Make the prompt visually distinctive so you don't confuse this shell
# with a host shell.
export PS1='\[\e[1;31m\][research]\[\e[0m\] \w \$ '

# Convenience aliases. None of these add execution capability — they
# just make static reads ergonomic.
alias ll='ls -la --color=auto'
alias h='sha256sum'
alias view='bat --paging=always --plain'
alias grepc='rg --color=always'

# Refuse to invoke runtimes even if somehow installed later.
alias bun='echo "[research] bun is disabled in this sandbox. Static analysis only." >&2; false'
alias node='echo "[research] node is disabled in this sandbox. Static analysis only." >&2; false'
alias npm='echo "[research] npm is disabled in this sandbox. Static analysis only." >&2; false'
alias python='echo "[research] python is disabled in this sandbox. Static analysis only." >&2; false'
alias python3='echo "[research] python3 is disabled in this sandbox. Static analysis only." >&2; false'
