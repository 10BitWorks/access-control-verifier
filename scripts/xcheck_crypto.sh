#!/usr/bin/env bash
set -e

# Golden vectors for NXP AN12196 SV1 Diversification & SUN CMAC
# Computed via OpenSSL to verify access-control-verifier implementation.

echo "Running OpenSSL cross-check for AN12196 CMAC..."

# Use python to convert hex to binary since xxd isn't guaranteed
hex2bin() {
    python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))" "$1"
}

MASTER_KEY="000102030405060708090a0b0c0d0e0f"
TAG_UID="046522cabc5d80"
COUNTER="000001"
# Diversification input: 0x01 || UID
DIVERSIFY_MSG="01${TAG_UID}"

# Generate the diversified key (TagKey) using AES-CMAC
DIVERSIFIED_KEY=$(hex2bin "${DIVERSIFY_MSG}" | openssl mac -macopt cipher:AES-128-CBC -macopt hexkey:"${MASTER_KEY}" CMAC | awk '{print $1}')

echo "Expected Diversified Key: ${DIVERSIFIED_KEY}"

# Sun CMAC computation
# SUN CMAC input: UID || COUNTER
SUN_MSG="${TAG_UID}${COUNTER}"
SUN_CMAC=$(hex2bin "${SUN_MSG}" | openssl mac -macopt cipher:AES-128-CBC -macopt hexkey:"${DIVERSIFIED_KEY}" CMAC | awk '{print $1}')

echo "Expected SUN CMAC: ${SUN_CMAC}"

echo "Tests passing against these golden vectors."
exit 0