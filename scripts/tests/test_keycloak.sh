#!/usr/bin/env bash

# ==============================================================================================
# Usage Examples
# With mandatory flags only
# ./test_keycloak.sh -c "auth_code_here" -v "verifier_here"
#
# With all flags
# ./test_keycloak.sh -c "auth_code_here" -v "verifier_here" -r "CustomRealm" -n "custom-client"
# =============================================================================================

# Default values
CLIENT="test-client"
REALM="TestRealm"
CODE=""
VERIFIER=""

# Parse command line arguments
while getopts "c:v:r:n:" opt; do
    case $opt in
        c) CODE="$OPTARG";;
        v) VERIFIER="$OPTARG";;
        r) REALM="$OPTARG";;
        n) CLIENT="$OPTARG";;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1;;
    esac
done

# Check mandatory parameters
if [ -z "$CODE" ] || [ -z "$VERIFIER" ]; then
    echo "Usage: $0 -c <code> -v <verifier> [-r <realm>] [-n <client>]"
    echo "Mandatory flags:"
    echo "  -c    Authorization code"
    echo "  -v    Code verifier"
    echo "Optional flags:"
    echo "  -r    Realm name (default: TestRealm)"
    echo "  -n    Client ID (default: test-client)"
    exit 1
fi

curl -vk --http1.1 POST "https://keycloak.local.com:9443/realms/$REALM/protocol/openid-connect/token" \
-d "grant_type=authorization_code" \
-d "client_id=$CLIENT" \
-d "code=$CODE" \
-d "redirect_uri=https://pkce-client.local.com:18080/auth/keycloak/callback" \
-d "code_verifier=$VERIFIER"
