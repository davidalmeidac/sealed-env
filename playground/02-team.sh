#!/usr/bin/env bash
# Mode: TEAM — basic + HMAC-SHA256 integrity tag with a separate signing key.
# Threat model: detects tampering even by someone who has the master key.
# The HMAC key is derived from a SEPARATE signing secret.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
note()  { printf '\033[36m›\033[0m %s\n' "$*"; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

CLI="node ../node/dist/cli/index.js"

bold "[ Mode 2 ] team — basic + HMAC integrity (separate signing key)"
hr

# ── 1. Generate two keys: master (for encryption) + signing (for HMAC)
note "Generating master key + INDEPENDENT signing key..."
MASTER_KEY=$(openssl rand -hex 32)
SIGNING_KEY=$(openssl rand -hex 32)
echo "    SEALED_ENV_KEY         = ${MASTER_KEY:0:16}..."
echo "    SEALED_ENV_SIGNING_KEY = ${SIGNING_KEY:0:16}..."
note "Key separation matters: an attacker with master_key alone cannot tamper."

# ── 2. Seal in team mode
note "Encrypting out/.env with mode=team..."
SEALED_ENV_KEY=$MASTER_KEY \
SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI encrypt out/.env --out out/team.sealed --mode team
ok "Sealed file: out/team.sealed"

# ── 3. Show the sealed file structure (note the new HMAC line)
hr
note "Notice the new HMAC= line in the metadata:"
echo
sed -n '1,9p' out/team.sealed
echo "  <ciphertext line follows...>"
hr

# ── 4. Successful roundtrip with both keys
note "Decrypting with BOTH keys present..."
SEALED_ENV_KEY=$MASTER_KEY \
SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI decrypt out/team.sealed > out/.env.team.decrypted
ok "Decrypted successfully."

if diff -q out/.env out/.env.team.decrypted >/dev/null; then
  ok "Roundtrip verified: byte-identical to original."
else
  printf '\033[31m✗\033[0m Roundtrip FAILED — files differ.\n'
  exit 1
fi

# ── 5. Demonstrate failure WITHOUT the signing key (attacker has master_key only)
hr
note "Trying to decrypt with master key but NO signing key (mid-attack scenario)..."
if SEALED_ENV_KEY=$MASTER_KEY $CLI decrypt out/team.sealed >/dev/null 2>&1; then
  printf '\033[31m✗\033[0m Decryption succeeded without signing key — this should never happen.\n'
  exit 1
else
  ok "Decryption REJECTED — HMAC verification fails first, before AES even tries."
  note "This is the value of mode=team: master key alone is not enough."
fi

# ── 6. Demonstrate failure with WRONG signing key (forged HMAC scenario)
hr
note "Trying to decrypt with master key + a DIFFERENT signing key..."
WRONG_SIGNING=$(openssl rand -hex 32)
if SEALED_ENV_KEY=$MASTER_KEY \
   SEALED_ENV_SIGNING_KEY=$WRONG_SIGNING \
   $CLI decrypt out/team.sealed >/dev/null 2>&1; then
  printf '\033[31m✗\033[0m Decryption succeeded with wrong signing key.\n'
  exit 1
else
  ok "Decryption REJECTED — HMAC mismatch."
fi

hr
echo
bold "Mode team complete."
echo "  Encrypted file: out/team.sealed"
echo "  Threat model: integrity + confidentiality, key separation."
echo "  Limitation: still vulnerable if BOTH master key AND signing key leak."
echo
echo "Next: ./03-enterprise.sh — adds short-lived TOTP unseal token + deploy challenge."
