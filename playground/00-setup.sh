#!/usr/bin/env bash
# Verifies prerequisites and creates a sample .env file for the rest of
# the playground scripts to use.
set -euo pipefail

cd "$(dirname "$0")"

# ANSI helpers (work in Git Bash, Linux, macOS terminals)
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m!\033[0m %s\n' "$*"; }
fail()  { printf '\033[31m✗\033[0m %s\n' "$*"; exit 1; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

bold "[ Step 0 ] Setup & prerequisite checks"
hr

# 1. Are we run from the playground directory?
if [ ! -f "README.md" ] || ! grep -q "sealed-env playground" README.md; then
  fail "Run this script from the playground/ directory."
fi

# 2. Is Node available?
if ! command -v node >/dev/null 2>&1; then
  fail "Node not found in PATH. Install Node 20 or 22."
fi
NODE_VERSION=$(node --version)
ok "Node available: $NODE_VERSION"

# 3. Is the sealed-env CLI built?
CLI="../node/dist/cli/index.js"
if [ ! -f "$CLI" ]; then
  warn "CLI not built yet. Building now..."
  ( cd ../node && npm install --silent && npm run build )
fi
if [ ! -f "$CLI" ]; then
  fail "CLI still missing after build. Check ../node/ for errors."
fi
ok "CLI present: $CLI"

# 4. Is openssl available?
if ! command -v openssl >/dev/null 2>&1; then
  fail "openssl not found. Required for key generation."
fi
ok "openssl available: $(openssl version | head -c 40)"

# 5. Create the output directory and the sample .env file
mkdir -p out
cat > out/.env <<'EOF'
# Sample .env for the sealed-env playground.
# These are placeholder values — never use real secrets in this file.

DATABASE_URL=postgresql://demo-user:demo-pass@localhost:5432/demo
API_KEY=demo-12345-not-a-real-key
JWT_SECRET=this-is-only-for-the-demo
LOG_LEVEL=info
FEATURE_FLAG_NEW_BILLING=false
EOF
ok "Sample .env created at out/.env"

hr
echo
bold "Ready. Run the scripts in order:"
echo "  ./01-basic.sh"
echo "  ./02-team.sh"
echo "  ./03-enterprise.sh"
echo "  ./04-tampering.sh"
echo "  ./05-cross-stack.sh   # optional, requires Java"
