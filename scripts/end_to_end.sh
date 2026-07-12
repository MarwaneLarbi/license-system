#!/usr/bin/env bash
# end_to_end.sh — Full offline license exchange demonstration.
#
# ZERO code changes required.  All key material flows through JSON files
# and CLI flags only.
#
# Prerequisites: build the project first (see README.md).
# Override binary paths via env vars if needed:
#   LICENSE_CLIENT=./build/client/license-client
#   LICENSE_SERVER=./build/server/license-server
#
# What this script demonstrates:
#   VENDOR SIDE
#     0. license-server init-keys   → creates keystore + server_pubkeys.json
#   CUSTOMER SIDE
#     1. license-client generate-request --config server_pubkeys.json
#                                        → outputs encrypted request blob
#   VENDOR SIDE
#     2. license-server generate-license --blob <blob>
#                                        → outputs signed license token
#   CUSTOMER SIDE
#     3. license-client activate --config server_pubkeys.json <token>
#     4. license-client verify   --config server_pubkeys.json <product_id>
#     5. license-client deactivate <product_id>   (optional cleanup)

set -euo pipefail

LICENSE_CLIENT="${LICENSE_CLIENT:-./build/client/license-client}"
LICENSE_SERVER="${LICENSE_SERVER:-./build/server/license-server}"

KEYSTORE_FILE="$(mktemp /tmp/demo_keystore.XXXXXX.json)"
PUBKEYS_FILE="$(mktemp  /tmp/demo_server_pubkeys.XXXXXX.json)"
PASSPHRASE="demo-passphrase-NOT-for-production"
PRODUCT_ID="myapp-pro"
CUSTOMER_HINT="Demo Customer <demo@example.com>"

cleanup() {
    rm -f "$KEYSTORE_FILE" "$PUBKEYS_FILE"
    "$LICENSE_CLIENT" deactivate "$PRODUCT_ID" 2>/dev/null || true
}
trap cleanup EXIT

sep() { echo; echo "──────────────────────────────────────────────────────────"; echo; }

echo "========================================================"
echo " Offline License Key Management System — End-to-End Demo"
echo "========================================================"

# ── STEP 0: Vendor initialises server keys ────────────────────────────────────
sep
echo "[STEP 0] VENDOR: Generate server keystore + client public-key config"
echo "         Keystore:           $KEYSTORE_FILE"
echo "         server_pubkeys.json: $PUBKEYS_FILE"
echo

"$LICENSE_SERVER" init-keys \
    --keystore  "$KEYSTORE_FILE" \
    --pub-out   "$PUBKEYS_FILE" \
    --passphrase "$PASSPHRASE"

echo
echo "Contents of server_pubkeys.json (distribute this file to customers):"
cat "$PUBKEYS_FILE"
echo

# ── STEP 1: Customer generates a license request ──────────────────────────────
sep
echo "[STEP 1] CUSTOMER: Generate encrypted license request"
echo "         Using server_pubkeys.json for request encryption."
echo

# Capture blob via --json for reliable parsing in a script.
REQUEST_JSON=$("$LICENSE_CLIENT" \
    --config "$PUBKEYS_FILE" \
    --json \
    generate-request "$PRODUCT_ID" "$CUSTOMER_HINT")

echo "Request result (JSON):"
echo "$REQUEST_JSON" | python3 -m json.tool 2>/dev/null || echo "$REQUEST_JSON"
echo

BLOB=$(echo "$REQUEST_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['blob'])")
echo "Blob (first 60 chars): ${BLOB:0:60}..."
echo "→ Customer emails this blob to the vendor."

# ── STEP 2: Vendor generates a signed license ─────────────────────────────────
sep
echo "[STEP 2] VENDOR: Issue signed license token"
echo "         Features: basic,advanced  |  Validity: 365 days  |  Max activations: 1"
echo

LICENSE_JSON=$("$LICENSE_SERVER" generate-license \
    --keystore        "$KEYSTORE_FILE" \
    --passphrase      "$PASSPHRASE" \
    --blob            "$BLOB" \
    --product         "$PRODUCT_ID" \
    --features        "basic,advanced" \
    --days            365 \
    --max-activations 1 \
    --json)

echo "License result (JSON):"
echo "$LICENSE_JSON" | python3 -m json.tool 2>/dev/null || echo "$LICENSE_JSON"
echo

TOKEN=$(echo "$LICENSE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token (first 60 chars): ${TOKEN:0:60}..."
echo "→ Vendor emails this token back to the customer."

# ── STEP 3: Customer activates ────────────────────────────────────────────────
sep
echo "[STEP 3] CUSTOMER: Activate license"
echo

"$LICENSE_CLIENT" \
    --config "$PUBKEYS_FILE" \
    --json \
    activate "$TOKEN" | python3 -m json.tool 2>/dev/null

# ── STEP 4: Customer verifies at startup ──────────────────────────────────────
sep
echo "[STEP 4] CUSTOMER: Verify license (startup check)"
echo

"$LICENSE_CLIENT" \
    --config "$PUBKEYS_FILE" \
    --json \
    verify "$PRODUCT_ID" | python3 -m json.tool 2>/dev/null

# ── STEP 5: Deactivate ────────────────────────────────────────────────────────
sep
echo "[STEP 5] CUSTOMER: Deactivate license (cleanup)"
echo

"$LICENSE_CLIENT" --json deactivate "$PRODUCT_ID" | python3 -m json.tool 2>/dev/null

# ── Fingerprint diagnostic ────────────────────────────────────────────────────
sep
echo "[BONUS] DIAGNOSTIC: Hardware fingerprint for this machine"
echo

"$LICENSE_CLIENT" --json fingerprint | python3 -m json.tool 2>/dev/null

sep
echo "Demo complete!"
echo
echo "Key points:"
echo "  • server_pubkeys.json is the ONLY file distributed to customers."
echo "  • The keystore (+ passphrase) never leaves the vendor machine."
echo "  • No source code changes are ever needed to issue or rotate keys."
echo
echo "Key rotation:"
echo "  1. license-server init-keys --keystore new_keystore.json --pub-out new_pubkeys.json"
echo "  2. Distribute new_pubkeys.json to customers."
echo "  3. Re-issue licenses with the new keystore."
echo "  4. Old licenses (signed with old key) become invalid automatically."
echo
echo "Revocation:"
echo "  • Short-lived licenses (90 days recommended): just don't re-issue."
echo "  • Immediate: rotate keys (step above) — all old tokens rejected."
