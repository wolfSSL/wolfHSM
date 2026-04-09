#!/bin/sh
# test/test_pkcs11_e2e.sh
#
# End-to-end smoke test: wh_server_uds daemon + pkcs11-tool.
#
# Usage:
#   ./test/test_pkcs11_e2e.sh [<path-to-wh_server_uds>]
#
# Requires:
#   pkcs11-tool  (opensc package)
#   p11-kit-client.so  (libp11-kit-dev package)
#
# Exit 0 on success; non-zero on any failure.

set -e

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

DAEMON=${1:-"$REPO_ROOT/examples/posix/wh_server_uds/Build/wh_server_uds"}
SOCK=/tmp/wolfhsm-pkcs11-e2e-$$.sock
P11KIT_MOD=/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so

SO_PIN=87654321
USER_PIN=12345678

# ── Helpers ──────────────────────────────────────────────────────────────────

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "PASS: $*"; }

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$SOCK"
}
trap cleanup EXIT

# ── Preconditions ─────────────────────────────────────────────────────────────

[ -x "$DAEMON" ]       || fail "daemon not found at $DAEMON (run 'make' in examples/posix/wh_server_uds/)"
[ -x "$(command -v pkcs11-tool)" ] || fail "pkcs11-tool not found (install opensc)"
[ -f "$P11KIT_MOD" ]   || fail "p11-kit-client.so not found at $P11KIT_MOD (install libp11-kit-dev)"

# ── Start daemon ──────────────────────────────────────────────────────────────

WH_UDS_PATH=$SOCK "$DAEMON" 2>/dev/null &
DAEMON_PID=$!

# Wait up to 4 seconds for the socket to appear
i=0
while [ $i -lt 20 ]; do
    [ -S "$SOCK" ] && break
    sleep 0.2
    i=$((i + 1))
done
[ -S "$SOCK" ] || fail "daemon did not create socket at $SOCK within 4s"

export P11_KIT_SERVER_ADDRESS="unix:path=$SOCK"

# ── Test 1: list-slots ────────────────────────────────────────────────────────

output=$(pkcs11-tool --module "$P11KIT_MOD" --list-slots 2>&1)
echo "$output" | grep -q "wolfPKCS11" || fail "list-slots: wolfPKCS11 token not found in output"
ok "list-slots"

# ── Test 2: init-token ────────────────────────────────────────────────────────

# wolfPKCS11 starts with the token in a fresh (unset SO PIN) state.
# C_InitToken (--init-token) uses the slot ID, not the pkcs11-tool list index.
# wolfPKCS11 exposes slot ID 1 (0x1), so pass --slot 1.
pkcs11-tool --module "$P11KIT_MOD" \
    --init-token --slot 1 --label "wolfHSM-e2e-test" \
    --so-pin "$SO_PIN" 2>&1 \
    | grep -q "successfully initialized" \
    || fail "init-token failed"
ok "init-token"

# ── Test 3: init-pin ─────────────────────────────────────────────────────────

pkcs11-tool --module "$P11KIT_MOD" \
    --init-pin --login --login-type so --so-pin "$SO_PIN" \
    --new-pin "$USER_PIN" 2>&1 \
    | grep -q "successfully initialized" \
    || fail "init-pin failed"
ok "init-pin"

# ── Test 4: EC key pair generation ───────────────────────────────────────────

pkcs11-tool --module "$P11KIT_MOD" \
    --keypairgen --key-type EC:prime256v1 \
    --label "e2e-ec-key" --id 01 --pin "$USER_PIN" 2>&1 \
    | grep -q "Key pair generated" \
    || fail "EC keypairgen failed"
ok "EC keypairgen (prime256v1)"

# ── Test 5: RSA key pair generation ──────────────────────────────────────────

pkcs11-tool --module "$P11KIT_MOD" \
    --keypairgen --key-type RSA:2048 \
    --label "e2e-rsa-key" --id 02 --pin "$USER_PIN" 2>&1 \
    | grep -q "Key pair generated" \
    || fail "RSA keypairgen failed"
ok "RSA keypairgen (2048-bit)"

# ── Test 6: list-objects ─────────────────────────────────────────────────────

objects=$(pkcs11-tool --module "$P11KIT_MOD" --list-objects --pin "$USER_PIN" 2>&1)
echo "$objects" | grep -q "e2e-ec-key"  || fail "list-objects: EC key not found"
echo "$objects" | grep -q "e2e-rsa-key" || fail "list-objects: RSA key not found"
ok "list-objects (EC + RSA present)"

# ── Test 7: generate-random ──────────────────────────────────────────────────

rand=$(pkcs11-tool --module "$P11KIT_MOD" --generate-random 16 2>/dev/null | xxd -p | tr -d '\n')
[ ${#rand} -eq 32 ] || fail "generate-random: expected 32 hex chars, got ${#rand}"
ok "generate-random (16 bytes)"

# ── All tests passed ──────────────────────────────────────────────────────────

echo ""
echo "All PKCS#11 e2e tests PASSED"
