#!/usr/bin/env bash
# --------------------------------------------
# Variables (override via environment if needed)
# --------------------------------------------
CONFIG_FILE="${CONFIG_FILE:-"san.cnf"}"
KEY_FILE="${KEY_FILE:-"nginx.key"}"
CRT_FILE="${CRT_FILE:-"nginx.crt"}"
OPENSSL_BIN="${OPENSSL_BIN:-"openssl"}"
DAYS_VALID="${DAYS_VALID:-365}"

# --------------------------------------------
# Generate certificate + key
# --------------------------------------------
echo "Using config file:      $CONFIG_FILE"
echo "Generating key file:    $KEY_FILE"
echo "Generating cert file:   $CRT_FILE"
echo "Valid for (days):       $DAYS_VALID"

$OPENSSL_BIN req \
    -x509 \
    -nodes \
    -days "$DAYS_VALID" \
    -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CRT_FILE" \
    -config "$CONFIG_FILE" \
    -extensions req_ext

echo "Certificate and key generated. Verify with:"
echo "  $OPENSSL_BIN x509 -in $CRT_FILE -text -noout"