#!/bin/bash
# gen_wolfboot_test_data.sh
#
# Generates test data for wolfBoot image manager verification tests.
# Creates:
#   1. RSA4096 signing key pair
#   2. Root CA -> Intermediate -> Leaf certificate chain (RSA4096)
#   3. 16KB dummy firmware payload
#   4. Signed wolfBoot images (standard and cert-chain variants)
#   5. C header with all artifacts as byte arrays
#
# Requires:
#   - wolfBoot keygen and sign tools
#   - sim-gen-dummy-chain.sh script
#   - openssl
#
# Usage: ./gen_wolfboot_test_data.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$(dirname "$SCRIPT_DIR")"
WOLFHSM_DIR="$(dirname "$TEST_DIR")"
WOLFBOOT_DIR="${WOLFBOOT_DIR:-$(realpath "$WOLFHSM_DIR/../wolfBoot")}"

KEYGEN="$WOLFBOOT_DIR/tools/keytools/keygen"
SIGN="$WOLFBOOT_DIR/tools/keytools/sign"
CHAIN_SCRIPT="$WOLFBOOT_DIR/tools/scripts/sim-gen-dummy-chain.sh"

OUTPUT_DIR="$TEST_DIR/gen"
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

HEADER_SIZE=1024
FIRMWARE_SIZE=16384

echo "=== wolfBoot Test Data Generator ==="
echo "wolfBoot dir: $WOLFBOOT_DIR"
echo "Output dir:   $OUTPUT_DIR"
echo "Work dir:     $WORK_DIR"
echo ""

# Verify tools exist
for tool in "$KEYGEN" "$SIGN" "$CHAIN_SCRIPT"; do
    if [ ! -f "$tool" ]; then
        echo "ERROR: Required tool not found: $tool"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

#############################
# 1. Generate RSA4096 key
#############################
echo "=== Generating RSA4096 signing key ==="
cd "$WORK_DIR"
mkdir -p src
"$KEYGEN" --rsa4096 -g signing_key.der
# keygen outputs signing_key.der (private) and keystore.der
# It also creates a src/keystore.c file with the public key

# The keygen tool outputs the private key as signing_key.der
# and also creates signing_key_pub.der
if [ ! -f signing_key.der ]; then
    echo "ERROR: keygen did not produce signing_key.der"
    ls -la "$WORK_DIR"
    exit 1
fi

# Convert private key to PEM for openssl/chain-gen use
openssl rsa -inform DER -in signing_key.der -out signing_key.pem 2>/dev/null

# Extract public key DER from private key
openssl rsa -inform DER -in signing_key.der -outform DER -pubout -out pubkey.der 2>/dev/null

echo "  Signing key generated."

#############################
# 2. Generate dummy firmware
#############################
echo "=== Generating dummy firmware ==="
dd if=/dev/urandom of="$WORK_DIR/firmware.bin" bs=1 count=$FIRMWARE_SIZE 2>/dev/null
echo "  Created ${FIRMWARE_SIZE}-byte firmware payload."

#############################
# 3. Sign firmware (standard wolfBoot header)
#############################
echo "=== Signing firmware (standard RSA4096+SHA256) ==="
"$SIGN" --rsa4096 --sha256 \
    "$WORK_DIR/firmware.bin" \
    "$WORK_DIR/signing_key.der" \
    1  # version number

# sign tool outputs firmware_v1_signed.bin which contains header + payload
SIGNED_IMG="$WORK_DIR/firmware_v1_signed.bin"
if [ ! -f "$SIGNED_IMG" ]; then
    echo "ERROR: sign tool did not produce expected output"
    ls -la "$WORK_DIR"
    exit 1
fi

# Extract header and verify sizes
SIGNED_SIZE=$(stat -c%s "$SIGNED_IMG" 2>/dev/null || stat -f%z "$SIGNED_IMG")
EXPECTED_SIZE=$((HEADER_SIZE + FIRMWARE_SIZE))
echo "  Signed image size: $SIGNED_SIZE (expected: $EXPECTED_SIZE)"

# Extract header (first HEADER_SIZE bytes) and payload (rest)
dd if="$SIGNED_IMG" of="$WORK_DIR/wolfboot_header.bin" bs=1 count=$HEADER_SIZE 2>/dev/null
dd if="$SIGNED_IMG" of="$WORK_DIR/wolfboot_payload.bin" bs=1 skip=$HEADER_SIZE 2>/dev/null

echo "  Header: ${HEADER_SIZE} bytes, Payload: $(stat -c%s "$WORK_DIR/wolfboot_payload.bin" 2>/dev/null || stat -f%z "$WORK_DIR/wolfboot_payload.bin") bytes"

#############################
# 4. Generate cert chain
#############################
echo "=== Generating RSA4096 certificate chain ==="
"$CHAIN_SCRIPT" \
    --algo rsa4096 \
    --leaf "$WORK_DIR/signing_key.pem" \
    --outdir "$WORK_DIR/chain"

echo "  Certificate chain generated."

#############################
# 5. Sign firmware with cert chain
#############################
echo "=== Signing firmware with cert chain ==="

# Build raw cert chain (intermediate + leaf DER certs concatenated)
CERT_CHAIN_FILE="$WORK_DIR/chain/raw-chain.der"
if [ ! -f "$CERT_CHAIN_FILE" ]; then
    echo "ERROR: Certificate chain file not found"
    exit 1
fi

# Sign with --cert-chain option
"$SIGN" --rsa4096 --sha256 \
    --cert-chain "$CERT_CHAIN_FILE" \
    "$WORK_DIR/firmware.bin" \
    "$WORK_DIR/signing_key.der" \
    2  # version number

SIGNED_CERT_IMG="$WORK_DIR/firmware_v2_signed.bin"
if [ ! -f "$SIGNED_CERT_IMG" ]; then
    echo "ERROR: sign tool with cert chain did not produce expected output"
    ls -la "$WORK_DIR"
    exit 1
fi

# The cert chain header may be larger than standard. Figure out the actual
# header size by reading the image size field and computing.
CERT_SIGNED_SIZE=$(stat -c%s "$SIGNED_CERT_IMG" 2>/dev/null || stat -f%z "$SIGNED_CERT_IMG")
CERT_HDR_SIZE=$((CERT_SIGNED_SIZE - FIRMWARE_SIZE))
echo "  Cert chain signed image size: $CERT_SIGNED_SIZE"
echo "  Cert chain header size: $CERT_HDR_SIZE"

# Extract cert chain header and payload
dd if="$SIGNED_CERT_IMG" of="$WORK_DIR/wolfboot_cert_header.bin" bs=1 count=$CERT_HDR_SIZE 2>/dev/null
dd if="$SIGNED_CERT_IMG" of="$WORK_DIR/wolfboot_cert_payload.bin" bs=1 skip=$CERT_HDR_SIZE 2>/dev/null

#############################
# 6. Generate C header file
#############################
echo "=== Generating C header file ==="

HEADER_FILE="$OUTPUT_DIR/wh_test_wolfboot_img_data.h"

cat > "$HEADER_FILE" << 'HEADER_TOP'
/*
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * test/gen/wh_test_wolfboot_img_data.h
 *
 * Auto-generated wolfBoot test data for image manager verification tests.
 * Generated by test/scripts/gen_wolfboot_test_data.sh
 *
 * DO NOT EDIT MANUALLY.
 */

#ifndef WH_TEST_WOLFBOOT_IMG_DATA_H
#define WH_TEST_WOLFBOOT_IMG_DATA_H

#include <stdint.h>
#include <stddef.h>

HEADER_TOP

# Helper function to convert binary to C array
bin_to_c_array() {
    local infile=$1
    local varname=$2
    local description=$3

    echo "/* $description */" >> "$HEADER_FILE"
    echo "static const uint8_t ${varname}[] __attribute__((aligned(4))) = {" \
        >> "$HEADER_FILE"
    xxd -i < "$infile" >> "$HEADER_FILE"
    echo "};" >> "$HEADER_FILE"
    echo "" >> "$HEADER_FILE"
}

# Standard wolfBoot header (RSA4096+SHA256, no cert chain)
bin_to_c_array "$WORK_DIR/wolfboot_header.bin" \
    "wolfboot_test_header" \
    "wolfBoot signed header (RSA4096+SHA256, ${HEADER_SIZE} bytes)"

# Firmware payload
bin_to_c_array "$WORK_DIR/wolfboot_payload.bin" \
    "wolfboot_test_firmware" \
    "Dummy firmware payload (${FIRMWARE_SIZE} bytes)"

# RSA4096 public key (DER format)
bin_to_c_array "$WORK_DIR/pubkey.der" \
    "wolfboot_test_pubkey_der" \
    "RSA4096 signing public key (DER format)"

# Cert chain wolfBoot header
bin_to_c_array "$WORK_DIR/wolfboot_cert_header.bin" \
    "wolfboot_test_cert_chain_header" \
    "wolfBoot signed header with cert chain (RSA4096+SHA256, ${CERT_HDR_SIZE} bytes)"

# Root CA certificate (DER format)
bin_to_c_array "$WORK_DIR/chain/root-cert.der" \
    "wolfboot_test_root_ca_cert_der" \
    "Root CA certificate (DER format, RSA4096)"

# Close header guard
echo "#endif /* WH_TEST_WOLFBOOT_IMG_DATA_H */" >> "$HEADER_FILE"

echo ""
echo "=== Generation Complete ==="
echo "Output: $HEADER_FILE"
echo "File size: $(stat -c%s "$HEADER_FILE" 2>/dev/null || stat -f%z "$HEADER_FILE") bytes"
