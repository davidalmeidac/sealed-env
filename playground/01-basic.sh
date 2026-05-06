#!/usr/bin/env bash
# Mode: BASIC — AES-256-GCM with master key only.
# Threat model: protects against backup leaks, accidental git pushes,
# heap dumps. Does NOT protect against an attacker who has both the
# file AND the master key.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
note()  { printf '\033[36m›\033[0m %s\n' "$*"; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

CLI="node ../node/dist/cli/index.js"

bold "[ Mode 1 ] basic — AES-256-GCM, master key only"
hr

# ── 1. Generate a master key
note "Generating a 32-byte master key with openssl..."
MASTER_KEY=$(openssl rand -hex 32)
echo "    SEALED_ENV_KEY = ${MASTER_KEY:0:16}... (32 bytes hex, truncated)"

# ── 2. Seal the file
note "Encrypting out/.env with mode=basic..."
SEALED_ENV_KEY=$MASTER_KEY $CLI encrypt out/.env --out out/basic.sealed --mode basic
ok "Sealed file: out/basic.sealed"

# ── 3. Show the sealed file structure
hr
note "What the sealed file looks like (first 8 lines):"
echo
sed -n '1,8p' out/basic.sealed
echo "  <ciphertext line follows...>"
hr

# ── 4. Demonstrate decryption with the right key
note "Decrypting with the correct master key..."
SEALED_ENV_KEY=$MASTER_KEY $CLI decrypt out/basic.sealed > out/.env.basic.decrypted
ok "Decrypted to out/.env.basic.decrypted"

# Compare original vs decrypted (should be byte-identical)
if diff -q out/.env out/.env.basic.decrypted >/dev/null; then
  ok "Roundtrip verified: decrypted file is byte-identical to original."
else
  printf '\033[31m✗\033[0m Roundtrip FAILED — files differ.\n'
  exit 1
fi

# ── 5. Demonstrate failure with the wrong key
hr
note "Now trying to decrypt with a DIFFERENT master key (should fail)..."
WRONG_KEY=$(openssl rand -hex 32)
if SEALED_ENV_KEY=$WRONG_KEY $CLI decrypt out/basic.sealed >/dev/null 2>&1; then
  printf '\033[31m✗\033[0m Decryption with wrong key SUCCEEDED — this should never happen.\n'
  exit 1
else
  ok "Decryption with wrong key correctly REJECTED."
  note "Error message is generic ('corrupted, tampered, or wrong key') — intentional, to avoid oracle leaks."
fi

hr
echo
bold "Mode basic complete."
echo "  Encrypted file: out/basic.sealed"
echo "  Threat model: confidentiality from anyone who lacks the master key."
echo "  Limitation: if both the file AND the key leak together, the vault opens."
echo
echo "Next: ./02-team.sh — adds HMAC integrity with a separate signing key."
