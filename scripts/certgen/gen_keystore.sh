#!/bin/bash

CN="${CN:-keycloak.local.com}"
OU="${OU:-Development}"
O="${O:-MyCompany}"
L="${L:-City}"
ST="${ST:-State}"
C="${C:-US}"

# Construct the slash-separated subject string that OpenSSL expects
DNAME="/CN=${CN}/OU=${OU}/O=${O}/L=${L}/ST=${ST}/C=${C}"

# Other settings
KEYSTORE_FILE="${KEYSTORE_FILE:-keycloak.p12}"
KEY_ALIAS="${KEY_ALIAS:-keycloak}"
STORE_PASS="${STORE_PASS:-changeit}"
VALIDITY="${VALIDITY:-365}"

echo "Generating PKCS#12 keystore '$KEYSTORE_FILE' for host ${CN}..."

# Remove previous temporary files if they exist
rm -f keycloak.key keycloak.crt "$KEYSTORE_FILE"

# Generate a new private key and self-signed certificate using OpenSSL
openssl req -newkey rsa:2048 -nodes -keyout keycloak.key -x509 -days "$VALIDITY" -out keycloak.crt -subj "$DNAME"
if [ $? -ne 0 ]; then
    echo "Failed to generate key or certificate." >&2
    exit 1
fi

# Combine certificate and key into a PKCS#12 keystore
openssl pkcs12 -export -in keycloak.crt -inkey keycloak.key -name "$KEY_ALIAS" -out "$KEYSTORE_FILE" -passout pass:"$STORE_PASS"
if [ $? -eq 0 ]; then
    echo "Keystore generated successfully: $KEYSTORE_FILE"
else
    echo "Failed to generate the keystore." >&2
    exit 1
fi

# Optionally remove the temporary key and certificate files
rm -f keycloak.key keycloak.crt