#!/bin/bash
# Configurable variables
# CA settings
CA_KEY="ca.key"
CA_CERT="ca.crt"
CA_DAYS=3650
CA_SUBJECT="/CN=MyDockerCA"

# Server certificate settings
SERVER_KEY="keycloak.local.com.key"
SERVER_CSR="keycloak.local.com.csr"
SERVER_CERT="keycloak.local.com.crt"
SERVER_DAYS=365
SERVER_SUBJECT="/CN=keycloak.local.com"

# Output directory for generated files
OUTPUT_DIR="certs"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "=== Generating CA key ==="
openssl genrsa -out "$OUTPUT_DIR/$CA_KEY" 4096

echo "=== Generating CA certificate ==="
openssl req -x509 -new -nodes -key "$OUTPUT_DIR/$CA_KEY" \
    -sha256 -days $CA_DAYS -out "$OUTPUT_DIR/$CA_CERT" \
    -subj "$CA_SUBJECT"

echo "=== Generating server key ==="
openssl genrsa -out "$OUTPUT_DIR/$SERVER_KEY" 2048

echo "=== Generating server CSR ==="
openssl req -new -key "$OUTPUT_DIR/$SERVER_KEY" \
    -out "$OUTPUT_DIR/$SERVER_CSR" -subj "$SERVER_SUBJECT"

echo "=== Signing server certificate with CA ==="
openssl x509 -req -in "$OUTPUT_DIR/$SERVER_CSR" \
    -CA "$OUTPUT_DIR/$CA_CERT" -CAkey "$OUTPUT_DIR/$CA_KEY" \
    -CAcreateserial -out "$OUTPUT_DIR/$SERVER_CERT" \
    -days $SERVER_DAYS -sha256

echo "=== Cleaning up temporary files ==="
rm "$OUTPUT_DIR/$SERVER_CSR"
rm "$OUTPUT_DIR/$CA_CERT.srl"

echo "Certificates generated in the '$OUTPUT_DIR' directory:"
echo "  CA Certificate: $OUTPUT_DIR/$CA_CERT"
echo "  Server Key:      $OUTPUT_DIR/$SERVER_KEY"
echo "  Server Cert:     $OUTPUT_DIR/$SERVER_CERT"
