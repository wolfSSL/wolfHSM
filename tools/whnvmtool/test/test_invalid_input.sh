#!/bin/sh
#
# Negative tests for whnvmtool. Each case runs the tool on an invalid config
# or key file and requires a nonzero exit plus an error message, stopping at
# the first unexpected result.
#
# Usage: test_invalid_input.sh [path-to-whnvmtool]

set -u

TOOL=${1:-./whnvmtool}

if [ ! -x "$TOOL" ]; then
    echo "FAIL: tool not found: $TOOL"
    exit 1
fi

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# 16-byte key file for valid entries, 15-byte for the SHE size check case,
# 65536-byte (one over the 16-bit cap) for the object size cap case
head -c 16 /dev/zero > "$TMP/key16.bin"
head -c 15 /dev/zero > "$TMP/key15.bin"
head -c 65536 /dev/zero > "$TMP/big.bin"

# Runs the tool on config $2. $1 is "pass" (require exit 0) or "fail"
# (require nonzero exit and an error message on stderr).
run_case() {
    expect=$1
    cfg=$2
    desc=$3

    rm -f "$TMP/img.bin"
    if "$TOOL" --image="$TMP/img.bin" "$cfg" >"$TMP/out.log" 2>"$TMP/err.log"
    then
        rc=0
    else
        rc=$?
    fi

    if [ "$expect" = "pass" ]; then
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: $desc: expected exit 0, got $rc"
            cat "$TMP/err.log"
            exit 1
        fi
    else
        if [ "$rc" -eq 0 ]; then
            echo "FAIL: $desc: expected nonzero exit"
            exit 1
        fi
        if ! grep -q "Error" "$TMP/err.log"; then
            echo "FAIL: $desc: exited $rc without an error message"
            cat "$TMP/err.log"
            exit 1
        fi
    fi
    echo "PASS: $desc"
}

# Sanity check that a valid config succeeds, so the failures below come from
# the bad value and not the setup
{
    echo "key 1 1 0 0 \"k\" $TMP/key16.bin"
    echo "she 0 1 0 0 $TMP/key16.bin"
} > "$TMP/cfg"
run_case pass "$TMP/cfg" "valid config accepted"

echo "key 16 1 0 0 \"k\" $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "key clientId 16 rejected (max 15)"

echo "key 1 0x100 0 0 \"k\" $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "key keyId 0x100 rejected (max 0xFF)"

echo "key 1 0 0 0 \"k\" $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "key keyId 0 rejected (min 1)"

echo "obj 0 0 0 \"o\" $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "obj id 0 rejected (min 1)"

echo "obj 1 0 0 \"o\" $TMP/big.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "65536-byte data file rejected (max 65535)"

echo "she 16 1 0 0 $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "she clientId 16 rejected (max 15)"

echo "she 0 16 0 0 $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "she slot 16 rejected (max 15)"

echo "she 0 14 0 0 $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "she slot 14 (RAM_KEY) rejected (volatile)"

echo "she 0 1 0x10000000 0 $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "she counter 0x10000000 rejected (max 0x0FFFFFFF)"

echo "she 0 1 0 0x20 $TMP/key16.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "she flags 0x20 rejected (max 0x1F)"

echo "she 0 1 0 0 $TMP/key15.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "15-byte SHE key file rejected"

echo "she 0 1 0 0 $TMP/missing.bin" > "$TMP/cfg"
run_case fail "$TMP/cfg" "missing key file fails the run"

{
    echo "she 0 1 0 0 $TMP/key15.bin"
    echo "she 0 2 0 0 $TMP/key16.bin"
} > "$TMP/cfg"
run_case fail "$TMP/cfg" "bad entry fails the run despite valid entries after it"

echo "All whnvmtool negative tests passed"
