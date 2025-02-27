#!/usr/bin/env bash

curl -vk --http1.1 POST https://keycloak.local.com:9443/realms/TestRealm/protocol/openid-connect/token \
-d "grant_type=authorization_code" \
-d "client_id=test-client" \
-d "code=YOUR_CODE" \
-d "redirect_uri=https://pkce-client.local.com:18080/auth/keycloak/callback" \
-d "code_verifier=YOUR_VERIFIER"

