#!/bin/bash

set -e

# Script directory and path definitions
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../build"
CONFIG_DIR="${BUILD_DIR}/config"
CERTS_DIR="${BUILD_DIR}/certs/client"
LOGS_DIR="${BUILD_DIR}/logs"

# Certificate paths
SSL_KEY="${CERTS_DIR}/pkce-client.key"
SSL_PEM="${CERTS_DIR}/pkce-client.pem"
SSL_CA="${CERTS_DIR}/ca.pem"

echo "Setting up C demo environment..."

# Create all necessary directories
mkdir -p "${CONFIG_DIR}" "${CERTS_DIR}" "${LOGS_DIR}"

# Generate SSL certificate in PEM format for CivetWeb
if [ ! -f "${SSL_PEM}" ]; then
    echo "Generating SSL certificate..."
    
    # Generate private key
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "${SSL_KEY}"
    
    # Generate self-signed certificate and combine with key into PEM
    openssl req -new -x509 -key "${SSL_KEY}" \
        -out "${CERTS_DIR}/pkce-client.crt" \
        -days 365 \
        -subj "/C=DE/ST=Nordrhein-Westfalen/L=Bonn/O=Brakmic GmbH/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:pkce-client.local.com,DNS=pkce-client"

    # Combine key and certificate into single PEM file (required by CivetWeb)
    cat "${SSL_KEY}" "${CERTS_DIR}/pkce-client.crt" > "${SSL_PEM}"
    
    # Set proper permissions
    chmod 600 "${SSL_PEM}"
    chmod 600 "${SSL_KEY}"
    
    # Clean up intermediate files
    rm -f "${CERTS_DIR}/pkce-client.crt"
    
    echo "SSL certificate generated successfully"
fi

# Create CivetWeb configuration file
echo "Creating CivetWeb configuration..."
cat > "${CONFIG_DIR}/civetweb.conf" << EOF
# CivetWeb Server Configuration

# Server settings
document_root .
listening_ports 18080s
enable_auth_domain_check no

# SSL/TLS configuration
ssl_certificate certs/client/pkce-client.pem
ssl_protocol_version 3
ssl_verify_peer no
ssl_cipher_list ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256
ssl_short_trust yes
ssl_verify_depth 0
ssl_default_verify_paths no

# Security settings
access_control_list -0.0.0.0/0,+127.0.0.1
access_control_allow_origin *
strict_transport_security_max_age 31536000

# Performance tuning
num_threads 50
request_timeout_ms 30000
keep_alive_timeout_ms 500
linger_timeout_ms 1000

# Logging configuration
access_log_file logs/access.log
error_log_file logs/error.log

# CORS settings
access_control_allow_methods GET,POST,OPTIONS
access_control_allow_headers Content-Type,Authorization,X-Requested-With
access_control_expose_headers Content-Length,Content-Range
EOF

# Create web root directory
mkdir -p "${BUILD_DIR}/www"

# Create basic library configuration if it doesn't exist
if [ ! -f "${CONFIG_DIR}/library_config.json" ]; then
    echo "Creating library configuration..."
    cat > "${CONFIG_DIR}/library_config.json" << EOF
{
    "keycloak": {
        "protocol": "https",
        "host": "keycloak.local.com",
        "port": 9443,
        "realm": "TestRealm",
        "client_id": "test-client",
        "scopes": ["openid", "email", "profile"],
        "ssl": {
            "verify_peer": false,
            "ca_cert_path": ""
        }
    },
    "pkce": {
        "state_store": {
            "expiry_duration": 300,
            "enable_cryptographic_verification": true,
            "max_entries": 1000
        },
        "cookies": {
            "path": "/",
            "http_only": true,
            "secure": true,
            "domain": ".local.com",
            "same_site": "None",
            "max_age": 3600,
            "access_token_name": "access_token",
            "refresh_token_name": "refresh_token",
            "id_token_name": "id_token"
        }
    }
}
EOF
fi

# Create log files with proper permissions
touch "${LOGS_DIR}/access.log" "${LOGS_DIR}/error.log"
chmod 666 "${LOGS_DIR}/access.log" "${LOGS_DIR}/error.log"

echo "Environment setup completed successfully"
echo
echo "Setup complete. The following files have been created:"
echo "- SSL certificate: ${SSL_PEM}"
echo "- CivetWeb config: ${CONFIG_DIR}/civetweb.conf"
echo "- Library config: ${CONFIG_DIR}/library_config.json"
echo "- Log files: ${LOGS_DIR}/access.log, ${LOGS_DIR}/error.log"
echo
echo "To build and run the demo:"
echo "1. cd ${BUILD_DIR}"
echo "2. cmake .."
echo "3. make"
echo "4. ./pkce_demo_c"
echo
echo "The server will be available at https://localhost:18080"
