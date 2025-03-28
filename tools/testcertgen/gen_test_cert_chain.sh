#!/bin/bash
# Certificate Chain Generation Script with Dual Chains
# Creates two distinct certificate chains (A and B), each with their own root, intermediate, and leaf
# Outputs both PEM and DER formats, plus C arrays for embedding

set -e  # Exit on any error

# Configuration for Chain A
ROOT_A_SUBJECT="/C=US/ST=California/L=San Francisco/O=ChainA Organization/OU=Root CA/CN=ChainA Root CA"
INTERMEDIATE_A_SUBJECT="/C=US/ST=California/L=San Francisco/O=ChainA Organization/OU=Intermediate CA/CN=ChainA Intermediate CA"
LEAF_A_SUBJECT="/C=US/ST=California/L=San Francisco/O=ChainA Organization/OU=Services/CN=service-a.example.com"

# Configuration for Chain B
ROOT_B_SUBJECT="/C=US/ST=California/L=San Jose/O=ChainB Organization/OU=Root CA/CN=ChainB Root CA"
INTERMEDIATE_B_SUBJECT="/C=US/ST=California/L=San Jose/O=ChainB Organization/OU=Intermediate CA/CN=ChainB Intermediate CA"
LEAF_B_SUBJECT="/C=US/ST=California/L=San Jose/O=ChainB Organization/OU=Services/CN=service-b.example.com"

# Create directory structure
echo "Creating directory structure..."
mkdir -p ca/{root_a,intermediate_a,leaf_a,root_b,intermediate_b,leaf_b}/{private,certs}/{pem,der}

##################
# GENERATE CHAIN A
##################
echo "Generating Chain A..."

# Step 1A: Generate Root A key and certificate
echo "Generating Root CA for Chain A..."
openssl genrsa -out ca/root_a/private/pem/root_a.key 4096

# Create PEM format root certificate
openssl req -new -x509 -days 3650 -sha256 \
    -key ca/root_a/private/pem/root_a.key \
    -out ca/root_a/certs/pem/root_a.crt \
    -subj "$ROOT_A_SUBJECT" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

# Convert root key and certificate to DER format
openssl rsa -in ca/root_a/private/pem/root_a.key -outform DER -out ca/root_a/private/der/root_a.key
openssl x509 -in ca/root_a/certs/pem/root_a.crt -outform DER -out ca/root_a/certs/der/root_a.crt

# Step 2A: Generate Intermediate A key and CSR
echo "Generating Intermediate CA for Chain A..."
openssl genrsa -out ca/intermediate_a/private/pem/intermediate_a.key 2048

openssl req -new -sha256 \
    -key ca/intermediate_a/private/pem/intermediate_a.key \
    -out ca/intermediate_a/intermediate_a.csr \
    -subj "$INTERMEDIATE_A_SUBJECT"

# Step 3A: Sign Intermediate A certificate with Root A
openssl x509 -req -days 1825 -sha256 \
    -in ca/intermediate_a/intermediate_a.csr \
    -out ca/intermediate_a/certs/pem/intermediate_a.crt \
    -CA ca/root_a/certs/pem/root_a.crt \
    -CAkey ca/root_a/private/pem/root_a.key \
    -CAcreateserial \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature")

# Convert intermediate key and certificate to DER format
openssl rsa -in ca/intermediate_a/private/pem/intermediate_a.key -outform DER -out ca/intermediate_a/private/der/intermediate_a.key
openssl x509 -in ca/intermediate_a/certs/pem/intermediate_a.crt -outform DER -out ca/intermediate_a/certs/der/intermediate_a.crt

# Step 4A: Generate Leaf A key and CSR
echo "Generating Leaf Certificate for Chain A..."
openssl genrsa -out ca/leaf_a/private/pem/leaf_a.key 2048

openssl req -new -sha256 \
    -key ca/leaf_a/private/pem/leaf_a.key \
    -out ca/leaf_a/leaf_a.csr \
    -subj "$LEAF_A_SUBJECT"

# Step 5A: Sign Leaf A certificate with Intermediate A
openssl x509 -req -days 365 -sha256 \
    -in ca/leaf_a/leaf_a.csr \
    -out ca/leaf_a/certs/pem/leaf_a.crt \
    -CA ca/intermediate_a/certs/pem/intermediate_a.crt \
    -CAkey ca/intermediate_a/private/pem/intermediate_a.key \
    -CAcreateserial \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Convert leaf key and certificate to DER format
openssl rsa -in ca/leaf_a/private/pem/leaf_a.key -outform DER -out ca/leaf_a/private/der/leaf_a.key
openssl x509 -in ca/leaf_a/certs/pem/leaf_a.crt -outform DER -out ca/leaf_a/certs/der/leaf_a.crt

# Step 6A: Create certificate chains in PEM format for Chain A
echo "Creating certificate chains for Chain A..."
cat ca/leaf_a/certs/pem/leaf_a.crt ca/intermediate_a/certs/pem/intermediate_a.crt > ca/leaf_a/certs/pem/chain_a.crt
cat ca/leaf_a/certs/pem/leaf_a.crt ca/intermediate_a/certs/pem/intermediate_a.crt ca/root_a/certs/pem/root_a.crt > ca/leaf_a/certs/pem/fullchain_a.crt

# Create raw DER format certificate chain for Chain A
cat ca/intermediate_a/certs/der/intermediate_a.crt ca/leaf_a/certs/der/leaf_a.crt > ca/leaf_a/certs/der/raw_chain_a.der

# Create PKCS#7 bundle for Chain A
openssl crl2pkcs7 -nocrl \
    -certfile ca/leaf_a/certs/pem/leaf_a.crt \
    -certfile ca/intermediate_a/certs/pem/intermediate_a.crt \
    -outform DER -out ca/leaf_a/certs/der/chain_a.p7b

##################
# GENERATE CHAIN B
##################
echo "Generating Chain B..."

# Step 1B: Generate Root B key and certificate
echo "Generating Root CA for Chain B..."
openssl genrsa -out ca/root_b/private/pem/root_b.key 4096

# Create PEM format root certificate
openssl req -new -x509 -days 3650 -sha256 \
    -key ca/root_b/private/pem/root_b.key \
    -out ca/root_b/certs/pem/root_b.crt \
    -subj "$ROOT_B_SUBJECT" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

# Convert root key and certificate to DER format
openssl rsa -in ca/root_b/private/pem/root_b.key -outform DER -out ca/root_b/private/der/root_b.key
openssl x509 -in ca/root_b/certs/pem/root_b.crt -outform DER -out ca/root_b/certs/der/root_b.crt

# Step 2B: Generate Intermediate B key and CSR
echo "Generating Intermediate CA for Chain B..."
openssl genrsa -out ca/intermediate_b/private/pem/intermediate_b.key 2048

openssl req -new -sha256 \
    -key ca/intermediate_b/private/pem/intermediate_b.key \
    -out ca/intermediate_b/intermediate_b.csr \
    -subj "$INTERMEDIATE_B_SUBJECT"

# Step 3B: Sign Intermediate B certificate with Root B
openssl x509 -req -days 1825 -sha256 \
    -in ca/intermediate_b/intermediate_b.csr \
    -out ca/intermediate_b/certs/pem/intermediate_b.crt \
    -CA ca/root_b/certs/pem/root_b.crt \
    -CAkey ca/root_b/private/pem/root_b.key \
    -CAcreateserial \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature")

# Convert intermediate key and certificate to DER format
openssl rsa -in ca/intermediate_b/private/pem/intermediate_b.key -outform DER -out ca/intermediate_b/private/der/intermediate_b.key
openssl x509 -in ca/intermediate_b/certs/pem/intermediate_b.crt -outform DER -out ca/intermediate_b/certs/der/intermediate_b.crt

# Step 4B: Generate Leaf B key and CSR
echo "Generating Leaf Certificate for Chain B..."
openssl genrsa -out ca/leaf_b/private/pem/leaf_b.key 2048

openssl req -new -sha256 \
    -key ca/leaf_b/private/pem/leaf_b.key \
    -out ca/leaf_b/leaf_b.csr \
    -subj "$LEAF_B_SUBJECT"

# Step 5B: Sign Leaf B certificate with Intermediate B
openssl x509 -req -days 365 -sha256 \
    -in ca/leaf_b/leaf_b.csr \
    -out ca/leaf_b/certs/pem/leaf_b.crt \
    -CA ca/intermediate_b/certs/pem/intermediate_b.crt \
    -CAkey ca/intermediate_b/private/pem/intermediate_b.key \
    -CAcreateserial \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Convert leaf key and certificate to DER format
openssl rsa -in ca/leaf_b/private/pem/leaf_b.key -outform DER -out ca/leaf_b/private/der/leaf_b.key
openssl x509 -in ca/leaf_b/certs/pem/leaf_b.crt -outform DER -out ca/leaf_b/certs/der/leaf_b.crt

# Step 6B: Create certificate chains in PEM format for Chain B
echo "Creating certificate chains for Chain B..."
cat ca/leaf_b/certs/pem/leaf_b.crt ca/intermediate_b/certs/pem/intermediate_b.crt > ca/leaf_b/certs/pem/chain_b.crt
cat ca/leaf_b/certs/pem/leaf_b.crt ca/intermediate_b/certs/pem/intermediate_b.crt ca/root_b/certs/pem/root_b.crt > ca/leaf_b/certs/pem/fullchain_b.crt

# Create raw DER format certificate chain for Chain B
cat ca/intermediate_b/certs/der/intermediate_b.crt ca/leaf_b/certs/der/leaf_b.crt > ca/leaf_b/certs/der/raw_chain_b.der

# Create PKCS#7 bundle for Chain B
openssl crl2pkcs7 -nocrl \
    -certfile ca/leaf_b/certs/pem/leaf_b.crt \
    -certfile ca/intermediate_b/certs/pem/intermediate_b.crt \
    -outform DER -out ca/leaf_b/certs/der/chain_b.p7b

##################################
# GENERATE C ARRAYS FOR EMBEDDING
##################################
echo "Generating C arrays for embedding in programs..."

# Create a directory for C header files
mkdir -p ca/c_headers

# Create a single header file for all certificates
HEADER_FILE="ca/c_headers/gen_certificates.h"

# Initialize the header file with header guards and includes
cat > "${HEADER_FILE}" << 'EOT'
/*
 * Certificate arrays for embedded SSL/TLS applications
 * Generated by OpenSSL dual certificate chain script
 */

#ifndef GEN_CERTIFICATES_H
#define GEN_CERTIFICATES_H

#include <stddef.h>

EOT

# Function to append a certificate array to the header file
append_cert_array() {
    local infile=$1
    local arrayname=$2
    local description=$3

    echo "/* ${description} */" >> "${HEADER_FILE}"
    echo "const unsigned char ${arrayname}[] = {" >> "${HEADER_FILE}"

    # Use xxd instead of hexdump for more reliable output
    xxd -i < "${infile}" | grep -v "unsigned char" | grep -v "unsigned int" | \
        sed 's/  0x/0x/g' >> "${HEADER_FILE}"

    echo "};" >> "${HEADER_FILE}"
    echo "const size_t ${arrayname}_len = sizeof(${arrayname});" >> "${HEADER_FILE}"
    echo "" >> "${HEADER_FILE}"
}

### Add Chain A certificates to the header file
echo "/* Chain A Certificates */" >> "${HEADER_FILE}"
append_cert_array "ca/root_a/certs/der/root_a.crt" "ROOT_A_CERT" "Chain A - Root CA Certificate (DER format)"
append_cert_array "ca/intermediate_a/certs/der/intermediate_a.crt" "INTERMEDIATE_A_CERT" "Chain A - Intermediate CA Certificate (DER format)"
append_cert_array "ca/leaf_a/certs/der/leaf_a.crt" "LEAF_A_CERT" "Chain A - Leaf/Server Certificate (DER format)"
append_cert_array "ca/leaf_a/certs/der/raw_chain_a.der" "RAW_CERT_CHAIN_A" "Chain A - Raw Certificate Chain (Intermediate+Leaf) (DER format)"
append_cert_array "ca/leaf_a/certs/der/chain_a.p7b" "CERT_CHAIN_A_P7B" "Chain A - Certificate Chain - PKCS#7 bundle (DER format)"

### Add Chain B certificates to the header file
echo "/* Chain B Certificates */" >> "${HEADER_FILE}"
append_cert_array "ca/root_b/certs/der/root_b.crt" "ROOT_B_CERT" "Chain B - Root CA Certificate (DER format)"
append_cert_array "ca/intermediate_b/certs/der/intermediate_b.crt" "INTERMEDIATE_B_CERT" "Chain B - Intermediate CA Certificate (DER format)"
append_cert_array "ca/leaf_b/certs/der/leaf_b.crt" "LEAF_B_CERT" "Chain B - Leaf/Server Certificate (DER format)"
append_cert_array "ca/leaf_b/certs/der/raw_chain_b.der" "RAW_CERT_CHAIN_B" "Chain B - Raw Certificate Chain (Intermediate+Leaf) (DER format)"
append_cert_array "ca/leaf_b/certs/der/chain_b.p7b" "CERT_CHAIN_B_P7B" "Chain B - Certificate Chain - PKCS#7 bundle (DER format)"

# Close the header guard
echo "#endif /* GEN_CERTIFICATES_H */" >> "${HEADER_FILE}"

echo "Generated C header file with all certificate arrays: ${HEADER_FILE}"

# Display verification information
echo ""
echo "=== Certificate Chain Generation Complete ==="
echo ""

# Verify Chain A
echo "=== Verifying Chain A ==="
echo "Verifying intermediate certificate against root:"
openssl verify -CAfile ca/root_a/certs/pem/root_a.crt ca/intermediate_a/certs/pem/intermediate_a.crt

echo ""
echo "Verifying leaf certificate against intermediate and root:"
openssl verify -CAfile ca/root_a/certs/pem/root_a.crt -untrusted ca/intermediate_a/certs/pem/intermediate_a.crt ca/leaf_a/certs/pem/leaf_a.crt

# Verify Chain B
echo ""
echo "=== Verifying Chain B ==="
echo "Verifying intermediate certificate against root:"
openssl verify -CAfile ca/root_b/certs/pem/root_b.crt ca/intermediate_b/certs/pem/intermediate_b.crt

echo ""
echo "Verifying leaf certificate against intermediate and root:"
openssl verify -CAfile ca/root_b/certs/pem/root_b.crt -untrusted ca/intermediate_b/certs/pem/intermediate_b.crt ca/leaf_b/certs/pem/leaf_b.crt

# Display generated files summary
echo ""
echo "=== Generated Files Summary ==="
echo ""
echo "Chain A:"
echo "  PEM Format:"
echo "    Root CA certificate:        ca/root_a/certs/pem/root_a.crt"
echo "    Intermediate certificate:   ca/intermediate_a/certs/pem/intermediate_a.crt"
echo "    Leaf certificate:           ca/leaf_a/certs/pem/leaf_a.crt"
echo "    Chain (leaf+intermediate):  ca/leaf_a/certs/pem/chain_a.crt"
echo "    Full chain:                 ca/leaf_a/certs/pem/fullchain_a.crt"
echo ""
echo "  DER Format:"
echo "    Root CA certificate:        ca/root_a/certs/der/root_a.crt"
echo "    Intermediate certificate:   ca/intermediate_a/certs/der/intermediate_a.crt"
echo "    Leaf certificate:           ca/leaf_a/certs/der/leaf_a.crt"
echo "    Raw chain:                  ca/leaf_a/certs/der/raw_chain_a.der"
echo "    PKCS#7 bundle:              ca/leaf_a/certs/der/chain_a.p7b"
echo ""
echo "Chain B:"
echo "  PEM Format:"
echo "    Root CA certificate:        ca/root_b/certs/pem/root_b.crt"
echo "    Intermediate certificate:   ca/intermediate_b/certs/pem/intermediate_b.crt"
echo "    Leaf certificate:           ca/leaf_b/certs/pem/leaf_b.crt"
echo "    Chain (leaf+intermediate):  ca/leaf_b/certs/pem/chain_b.crt"
echo "    Full chain:                 ca/leaf_b/certs/pem/fullchain_b.crt"
echo ""
echo "  DER Format:"
echo "    Root CA certificate:        ca/root_b/certs/der/root_b.crt"
echo "    Intermediate certificate:   ca/intermediate_b/certs/der/intermediate_b.crt"
echo "    Leaf certificate:           ca/leaf_b/certs/der/leaf_b.crt"
echo "    Raw chain:                  ca/leaf_b/certs/der/raw_chain_b.der"
echo "    PKCS#7 bundle:              ca/leaf_b/certs/der/chain_b.p7b"
echo ""
echo "C Header file:"
echo "  Certificate arrays:           ca/c_headers/gen_certificates.h"

# Clean up temporary files
rm -f ca/intermediate_a/intermediate_a.csr ca/leaf_a/leaf_a.csr ca/root_a/root_a.srl ca/intermediate_a/intermediate_a.srl
rm -f ca/intermediate_b/intermediate_b.csr ca/leaf_b/leaf_b.csr ca/root_b/root_b.srl ca/intermediate_b/intermediate_b.srl

# copy the generated header file to the test directory for use by wolfHSM tests
cp ca/c_headers/gen_certificates.h ../../test/wh_test_cert_data.h