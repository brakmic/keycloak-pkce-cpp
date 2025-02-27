# Python Integration Guide

## Overview
The Python binding uses ctypes to interact with the C API of the Keycloak PKCE library, providing a Pythonic interface while maintaining the full functionality of the core library.

## Requirements
- Python 3.8 or higher
- ctypes (included in Python standard library)
- OpenSSL libraries (runtime dependency)

## Basic Usage

```python
from keycloak_pkce import KeycloakClient, Config

# Load configuration
config = Config.from_file("config/library_config.json")

# Create client instance
client = KeycloakClient(config)

# Get authorization URL for login
auth_url = client.get_authorization_url()

# Handle callback after user authentication
tokens = client.handle_callback(code="...", state="...")

# Validate session token
is_valid = client.validate_session(tokens.access_token)
```

## Configuration

```python
# Load from JSON file
config = Config.from_file("config/library_config.json")

# Or create programmatically
config = Config(
    keycloak={
        "protocol": "https",
        "host": "keycloak.local.com",
        "port": 9443,
        "realm": "TestRealm",
        "client_id": "test-client",
        "scopes": ["openid", "profile", "email"]
    },
    ssl={
        "verify_peer": True,
        "ca_cert": "path/to/ca.pem"
    },
    proxy={
        "host": "proxy.local",
        "port": 8080
    }
)
```

## Web Application Example

```python
from flask import Flask, request, redirect
from keycloak_pkce import KeycloakClient, Config

app = Flask(__name__)

# Initialize client
config = Config.from_file("config/library_config.json")
kc_client = KeycloakClient(config)

@app.route("/login")
def login():
    auth_url = kc_client.get_authorization_url()
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    
    tokens = kc_client.handle_callback(code, state)
    if not tokens:
        return "Authentication failed", 400
        
    response = redirect("/protected")
    response.set_cookie(
        "session",
        tokens.access_token,
        httponly=True,
        secure=True,
        samesite="Strict"
    )
    return response

@app.route("/protected")
def protected():
    session = request.cookies.get("session")
    if not session or not kc_client.validate_session(session):
        return redirect("/login")
    return "Protected resource"
```

## Error Handling

```python
from keycloak_pkce.exceptions import KeycloakError

try:
    client = KeycloakClient(config)
    auth_url = client.get_authorization_url()
except KeycloakError as e:
    print(f"Authentication error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Resource Management

```python
# Using context manager (recommended)
with KeycloakClient(config) as client:
    auth_url = client.get_authorization_url()
    # Resources automatically cleaned up

# Manual cleanup
client = KeycloakClient(config)
try:
    auth_url = client.get_authorization_url()
finally:
    client.close()  # Explicit cleanup
```

## Security Notes

- Always use HTTPS in production
- Store tokens securely (httponly cookies)
- Validate state parameter
- Use secure cookie settings
- Keep SSL certificates up to date

# Environment Variables

- KC_PKCE_LIB - path to kc_pkce.so (C API)
