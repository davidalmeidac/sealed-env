#!/usr/bin/env bash
# Mode: ENTERPRISE — team + TOTP-bound unseal token + deploy challenge.
# Threat model: even if all three keys leak, an attacker cannot decrypt
# without a fresh TOTP code from the operator AND the right deploy ID.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p out

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
note()  { printf '\033[36m›\033[0m %s\n' "$*"; }
hr()    { printf '\033[90m─%.0s\033[0m' {1..72}; printf '\n'; }

CLI="node ../node/dist/cli/index.js"

bold "[ Mode 3 ] enterprise — TOTP unseal token + deploy challenge"
hr

# ── 1. Generate three secrets:
#       master_key    (encryption)
#       signing_key   (HMAC integrity)
#       totp_secret   (the OTP shared between operator's authenticator app and the file)
note "Generating master + signing + TOTP secrets..."
MASTER_KEY=$(openssl rand -hex 32)
SIGNING_KEY=$(openssl rand -hex 32)
# TOTP secret is base32 (RFC 6238 convention used by all authenticator apps).
# 20 bytes raw -> 32 chars base32. We generate 20 random bytes and encode.
TOTP_SECRET_HEX=$(openssl rand -hex 20)
# Convert hex -> base32 manually so we don't depend on `base32` being installed.
TOTP_SECRET_B32=$(python -c "import base64,sys; print(base64.b32encode(bytes.fromhex(sys.argv[1])).decode().rstrip('='))" "$TOTP_SECRET_HEX")

echo "    SEALED_ENV_KEY          = ${MASTER_KEY:0:16}..."
echo "    SEALED_ENV_SIGNING_KEY  = ${SIGNING_KEY:0:16}..."
echo "    SEALED_ENV_TOTP_SECRET  = ${TOTP_SECRET_B32:0:16}... (base32)"
note "In real use, the TOTP secret is loaded into the operator's authenticator (e.g. Aegis, Authy)."

# ── 2. Seal in enterprise mode
DEPLOY_ID="commit-abc123"
note "Encrypting out/.env with mode=enterprise (deploy_id=$DEPLOY_ID)..."
SEALED_ENV_KEY=$MASTER_KEY \
SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
SEALED_ENV_TOTP_SECRET=$TOTP_SECRET_B32 \
  $CLI encrypt out/.env --out out/enterprise.sealed --mode enterprise
ok "Sealed file: out/enterprise.sealed"

# ── 3. Show the new metadata fields (TOTP-VERIFIER, CHALLENGE-BIND)
hr
note "Notice TOTP-VERIFIER and CHALLENGE-BIND lines:"
echo
sed -n '1,10p' out/enterprise.sealed
echo "  <ciphertext line follows...>"
hr

# ── 4. Operator generates an unseal token using the current TOTP code
note "Computing the current TOTP code from the secret (RFC 6238)..."
# Using oathtool would be cleanest, but we don't want to require it.
# We compute TOTP in Python since python is already a soft dep above.
CURRENT_TOTP=$(python <<PY
import base64, hmac, hashlib, struct, time, sys
secret = base64.b32decode("${TOTP_SECRET_B32}" + "=" * (-len("${TOTP_SECRET_B32}") % 8))
counter = int(time.time() // 30)
mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = mac[-1] & 0x0f
trunc = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff
print(f"{trunc % 10**6:06d}")
PY
)
echo "    Current TOTP code: $CURRENT_TOTP"
note "In production, this code comes from your authenticator app on your phone."

# ── 5. Build the unseal token via the CLI's `unseal` command
# We need to pass the SAME salt used by the file, otherwise the token
# is signed with a different derived key than the one used at decrypt
# time. (The CLI default is a zero-salt sentinel; for end-to-end this
# isn't enough.)
note "Extracting the salt from the sealed file (so the token derives the same key)..."
SALT_B64=$(grep '^SALT=' out/enterprise.sealed | cut -d= -f2-)
SALT_HEX=$(python -c "import base64,sys; print(base64.b64decode(sys.argv[1]).hex())" "$SALT_B64")
echo "    Salt (hex): $SALT_HEX"

note "Generating unseal token (binds to deploy_id=$DEPLOY_ID, expires in 60 seconds)..."
TOKEN=$(SEALED_ENV_KEY=$MASTER_KEY \
        SEALED_ENV_TOTP_SECRET=$TOTP_SECRET_B32 \
        $CLI unseal --totp "$CURRENT_TOTP" --deploy-id "$DEPLOY_ID" --ttl 60 --salt "$SALT_HEX" \
        | grep -E '^usl_' | head -1)

if [ -z "${TOKEN:-}" ]; then
  printf '\033[31m✗\033[0m Failed to capture unseal token from CLI output.\n'
  exit 1
fi
echo "    Token: ${TOKEN:0:50}... (compact JWS, 60s TTL)"
ok "Token built and bound to deploy_id=$DEPLOY_ID."

# ── 6. Successful decryption with the right token + matching deploy_id
hr
note "Decrypting with the token + matching deploy_id..."
SEALED_ENV_KEY=$MASTER_KEY \
SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
SEALED_ENV_UNSEAL_TOKEN=$TOKEN \
SEALED_ENV_DEPLOY_ID=$DEPLOY_ID \
  $CLI decrypt out/enterprise.sealed > out/.env.enterprise.decrypted
ok "Decrypted successfully."

if diff -q out/.env out/.env.enterprise.decrypted >/dev/null; then
  ok "Roundtrip verified."
else
  printf '\033[31m✗\033[0m Roundtrip FAILED.\n'
  exit 1
fi

# ── 7. Failure: wrong deploy_id (replay attack against another deploy)
hr
note "Now simulating a REPLAY: same token, but trying against a DIFFERENT deploy_id..."
if SEALED_ENV_KEY=$MASTER_KEY \
   SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
   SEALED_ENV_UNSEAL_TOKEN=$TOKEN \
   SEALED_ENV_DEPLOY_ID="different-commit-xyz999" \
   $CLI decrypt out/enterprise.sealed >/dev/null 2>&1; then
  printf '\033[31m✗\033[0m Replay attack succeeded — should have failed.\n'
  exit 1
else
  ok "Replay REJECTED — token is bound to its original deploy_id."
  note "This is the defense against tj-actions / GhostAction style attacks."
fi

# ── 8. Failure: missing token (master + signing key still not enough)
hr
note "Trying without an unseal token (attacker has master + signing keys)..."
if SEALED_ENV_KEY=$MASTER_KEY \
   SEALED_ENV_SIGNING_KEY=$SIGNING_KEY \
   $CLI decrypt out/enterprise.sealed >/dev/null 2>&1; then
  printf '\033[31m✗\033[0m Decryption succeeded without token.\n'
  exit 1
else
  ok "Decryption REJECTED — enterprise mode requires a fresh unseal token."
fi

hr
echo
bold "Mode enterprise complete."
echo "  Encrypted file: out/enterprise.sealed"
echo "  Threat model: even master + signing keys are insufficient at runtime."
echo "                Attacker needs a fresh TOTP code AND the right deploy_id."
echo "                Unseal tokens are bound to commit SHA — replay impossible."
echo
echo "Next: ./04-tampering.sh — modify the sealed file and watch decryption fail."
