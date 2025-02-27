#!/bin/bash
set -e

CERT_DIR="certs/client"
mkdir -p ${CERT_DIR}

# Generate RSA private key
openssl genrsa -out ${CERT_DIR}/temp.key 2048

# Convert to PKCS8 format (required by lua-http)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
    -in ${CERT_DIR}/temp.key \
    -out ${CERT_DIR}/lua_http_server.pkcs8.key

# Generate CSR configuration
cat > ${CERT_DIR}/openssl.cnf << EOL
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = DE
ST = NRW
L = Bonn
O = Test
CN = pkce-client.local.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = pkce-client.local.com
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOL

# Generate certificate
openssl req -new -x509 -sha256 -key ${CERT_DIR}/temp.key \
    -out ${CERT_DIR}/lua_http_server.pem \
    -days 365 \
    -config ${CERT_DIR}/openssl.cnf \
    -extensions v3_req

# Cleanup
rm ${CERT_DIR}/temp.key ${CERT_DIR}/openssl.cnf

echo "Generated certificates in ${CERT_DIR}:"
echo "  lua_http_server.pem - Certificate"
echo "  lua_http_server.pkcs8.key - PKCS8 private key"
