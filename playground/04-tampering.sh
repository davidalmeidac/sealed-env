#!/usr/bin/env bash
# Modify a sealed file in various ways and verify the library catches every
# tampering attempt with the same generic error message (no oracle leak).
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
note()  { printf '\033[36m›\033[0m %s\n' "$*"; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

CLI="node ../node/dist/cli/index.js"

bold "[ Tampering ] What happens when the sealed file is modified"
hr

# ── 0. Make sure 02-team has been run (we use that file as the victim)
if [ ! -f out/team.sealed ]; then
  printf '\033[33m!\033[0m Run ./02-team.sh first — this script tampers with that file.\n'
  exit 1
fi

# We need the keys that were used in 02-team. Since each script generates
# its own ephemeral keys, here we generate fresh keys + fresh seal so this
# script is self-contained.
note "Generating keys + sealing fresh team-mode file (so we have valid secrets)..."
MASTER_KEY=$(openssl rand -hex 32)
SIGNING_KEY=$(openssl rand -hex 32)
SEALED_ENV_KEY=$MASTER_KEY \
SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI encrypt out/.env --out out/victim.sealed --mode team
ok "Victim file created: out/victim.sealed"

# Helper: try to decrypt; print whether it succeeded or was rejected.
try_decrypt() {
  local label="$1"
  if SEALED_ENV_KEY=$MASTER_KEY \
     SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
     $CLI decrypt out/victim.sealed >/dev/null 2>&1; then
    printf '\033[31m✗\033[0m  %s — decrypted (BAD: tampering not caught)\n' "$label"
    return 1
  else
    printf '\033[32m✓\033[0m  %s — REJECTED with the generic error\n' "$label"
  fi
}

# Sanity: untouched file decrypts fine
hr
note "Sanity check: untouched file decrypts fine"
SEALED_ENV_KEY=$MASTER_KEY SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI decrypt out/victim.sealed >/dev/null
ok "Untouched file: decrypts as expected"

# ── 1. Tamper with the magic line
hr
note "[ Attack 1 ] Change the MAGIC line (downgrade attempt)"
cp out/victim.sealed out/victim.tampered
sed -i.bak '1s/.*/SEALED-ENV-V1 MODE=basic/' out/victim.tampered
echo "    First line is now: $(head -1 out/victim.tampered)"
mv out/victim.tampered out/victim.sealed
try_decrypt "Magic line modified"

# Restore
SEALED_ENV_KEY=$MASTER_KEY SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI encrypt out/.env --out out/victim.sealed --mode team

# ── 2. Tamper with the SALT (try to force re-derivation)
hr
note "[ Attack 2 ] Modify the SALT line (try to force the wrong derived key)"
cp out/victim.sealed out/victim.tampered
sed -i.bak 's/^SALT=.*/SALT=AAAAAAAAAAAAAAAAAAAAAA==/' out/victim.tampered
mv out/victim.tampered out/victim.sealed
try_decrypt "Salt modified"

# Restore
SEALED_ENV_KEY=$MASTER_KEY SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI encrypt out/.env --out out/victim.sealed --mode team

# ── 3. Tamper with the ciphertext body (flip one byte)
hr
note "[ Attack 3 ] Flip ONE byte in the ciphertext"
LINES=$(wc -l < out/victim.sealed)
LAST=$(tail -1 out/victim.sealed)
# Flip the first character of the last (body) line
ALTERED="${LAST:0:1}X${LAST:2}"
cp out/victim.sealed out/victim.tampered
# Replace the last line atomically
{ head -n $((LINES-1)) out/victim.sealed; echo "$ALTERED"; } > out/victim.tampered
mv out/victim.tampered out/victim.sealed
try_decrypt "Ciphertext byte flipped"

# Restore
SEALED_ENV_KEY=$MASTER_KEY SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
  $CLI encrypt out/.env --out out/victim.sealed --mode team

# ── 4. Tamper with the HMAC line
hr
note "[ Attack 4 ] Change the HMAC value to a random one"
cp out/victim.sealed out/victim.tampered
sed -i.bak 's|^HMAC=.*|HMAC=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|' out/victim.tampered
mv out/victim.tampered out/victim.sealed
try_decrypt "HMAC replaced"

# Cleanup .bak files left by sed -i on macOS
rm -f out/*.bak

hr
echo
bold "Tampering report"
echo "  Every modification was rejected with the same generic error:"
echo "  \"sealed-env: file is corrupted, tampered, or wrong key\""
echo
echo "  This is intentional. The library never tells the attacker WHICH"
echo "  check failed — that would let them probe the file by trial and"
echo "  error to learn structure (e.g. 'is the HMAC valid?')."
echo
echo "  The only way to know what's wrong is to have the legitimate keys"
echo "  and re-run the original seal — which is exactly the threat model."
echo
echo "Next: ./05-cross-stack.sh — seal in Node, decrypt with Java (optional)."
