#!/bin/bash

# Set variables
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../build"
LUA_DIR=${BUILD_DIR}/lua
CERTS_DIR="${LUA_DIR}/certs/client"
CONFIG_DIR="${LUA_DIR}/config"
COMMON_NAME="pkce-client.local.com"
SHORT_NAME="pkce-client"
SSL_CONF_PATH=${CONFIG_DIR}/openssl.lua.conf
DAYS=365

# Certificates
LUA_KEY_PATH=${CERTS_DIR}/${SHORT_NAME}.lua.key
LUA_PEM_PATH=${CERTS_DIR}/${SHORT_NAME}.lua.pem

# Create all required directories
mkdir -p ${CERTS_DIR}
mkdir -p ${CONFIG_DIR}

# Generate OpenSSL config
cat > ${SSL_CONF_PATH} << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = DE
ST = Nordrhein-Westfalen
L = Bonn
O = Brakmic GmbH
CN = ${COMMON_NAME}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${COMMON_NAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# Generate certificates for OpenResty
echo "Generating OpenResty certificates..."
openssl req -x509 -nodes \
    -days ${DAYS} \
    -newkey rsa:2048 \
    -keyout ${LUA_KEY_PATH} \
    -out ${LUA_PEM_PATH} \
    -config ${SSL_CONF_PATH} \
    -extensions v3_req

# Verify certificates were created
if [ ! -f "${LUA_KEY_PATH}" ] || [ ! -f "${LUA_PEM_PATH}" ]; then
    echo "Error: Certificate generation failed"
    exit 1
fi

# Set permissions
chmod 600 ${LUA_KEY_PATH}
chmod 644 ${LUA_PEM_PATH}

# Verify certificates
echo "Verifying certificates..."
openssl x509 -in ${LUA_PEM_PATH} -text -noout

echo "Certificate generation complete!"
