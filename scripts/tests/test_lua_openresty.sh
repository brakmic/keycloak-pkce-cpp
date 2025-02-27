#!/bin/bash

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../build"
C_DIR="${BUILD_DIR}/c"
KC_LIB_DIR="${C_DIR}/lib"
LUA_DIR="${BUILD_DIR}/lua"

# Kill any existing nginx processes
# $SCRIPT_DIR/kill_nginx.sh

# Create mime.types
echo "Setting up mime.types..."
cat > "${LUA_DIR}/mime.types" << 'EOF'
types {
    text/html                                        html htm shtml;
    text/css                                         css;
    text/xml                                         xml;
    image/gif                                        gif;
    image/jpeg                                       jpeg jpg;
    application/javascript                           js;
    application/atom+xml                             atom;
    application/rss+xml                              rss;
    text/plain                                       txt;
    application/json                                 json;
}
EOF

# Create necessary directories
mkdir -p "${LUA_DIR}/logs"
mkdir -p "${LUA_DIR}/certs/client"

# Verify certificate files
echo "Checking SSL certificates..."
if [ ! -f "${LUA_DIR}/certs/client/pkce-client.lua.pem" ] || [ ! -f "${LUA_DIR}/certs/client/pkce-client.lua.key" ]; then
    echo "SSL certificates missing. Regenerating..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${LUA_DIR}/certs/client/pkce-client.lua.key" \
        -out "${LUA_DIR}/certs/client/pkce-client.lua.pem" \
        -days 365 \
        -subj "/C=DE/ST=NRW/L=Bonn/O=Brakmic GmbH/CN=pkce-client.local.com" \
        -addext "subjectAltName=DNS:pkce-client.local.com,DNS:localhost,IP:127.0.0.1"
fi

# Set correct permissions
chmod 600 "${LUA_DIR}/certs/client/pkce-client.lua.key"
chmod 644 "${LUA_DIR}/certs/client/pkce-client.lua.pem"

# Start OpenResty
cd "${LUA_DIR}"
export LD_LIBRARY_PATH="${KC_LIB_DIR}:$LD_LIBRARY_PATH"
export KC_PKCE_LIB="${KC_LIB_DIR}/libkc_pkce.so"

echo "Starting OpenResty..."
openresty -p . -c nginx.conf -g "daemon off;" &
NGINX_PID=$!

# Wait for nginx to start and verify it's running
echo "Waiting for OpenResty to start..."
for i in {1..10}; do
    if curl -sk https://pkce-client.local.com:18080/test >/dev/null 2>&1; then
        echo "OpenResty started successfully"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "Failed to start OpenResty"
        cat logs/error.log
        exit 1
    fi
    sleep 1
done

# Test endpoints
echo "Testing /test endpoint..."
curl -k -v --http1.1 https://pkce-client.local.com:18080/test

echo -e "\nTesting /auth/keycloak endpoint..."
curl -k -v --http1.1 --keepalive-time 5 https://pkce-client.local.com:18080/auth/keycloak

# Clean up
if [ -n "$NGINX_PID" ]; then
    echo "Stopping OpenResty..."
    kill $NGINX_PID || true
    wait $NGINX_PID 2>/dev/null || true
fi

echo "Test complete"
