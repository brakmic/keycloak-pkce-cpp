#!/usr/bin/env python3
import os
import ssl
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from keycloak_pkce import KeycloakPKCE
import json
import base64

# ---------------------------------------------------------------------------
# 1) Global PKCE config
# ---------------------------------------------------------------------------
class PKCEState:
    def __init__(self):
        self.pkce = None
        self.auth_url = None
        self.initialized = False

g_state = PKCEState()

# ---------------------------------------------------------------------------
# 2) Simple JWT decode helper (just the payload)
# ---------------------------------------------------------------------------
def decode_jwt_payload(token):
    # "header.payload.signature"
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    # Add padding if needed
    padding_needed = 4 - (len(payload_b64) % 4)
    if padding_needed < 4:
        payload_b64 += "=" * padding_needed
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

# ---------------------------------------------------------------------------
# 3) Minimal request handler
# ---------------------------------------------------------------------------
class PKCERequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # parse path + query
        parsed = urllib.parse.urlparse(self.path)  # e.g. "/auth/keycloak/callback?code=..."
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)  # returns { 'code': ['xxx'], ...}

        # Helper to write a response
        def send_response(status_code, content_type, body):
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            # Minimal security headers
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if body:
                self.wfile.write(body.encode("utf-8"))

        # Helper to set a cookie
        def set_cookie(name, value):
            # A real version might set secure, httponly, samesite, etc.
            self.send_header("Set-Cookie", f"{name}={value}; Path=/; HttpOnly")

        # Routes
        if path == "/":
            html = """
            <html><body>
            <h1>Keycloak PKCE Demo (Python)</h1>
            <p><a href='/auth/keycloak'>Start Login</a></p>
            <p><a href='/protected'>Protected Resource</a></p>
            </body></html>
            """
            send_response(200, "text/html", html)

        elif path == "/auth/keycloak":
            # redirect
            self.send_response(302)
            self.send_header("Location", g_state.auth_url)
            self.end_headers()

        elif path == "/auth/keycloak/callback":
            # Extract code, state, error
            code = query_params.get("code", [None])[0]
            state = query_params.get("state", [None])[0]
            error = query_params.get("error", [None])[0]

            if error:
                send_response(400, "text/plain", f"Auth error: {error}")
                return
            if not code or not state:
                send_response(400, "text/plain", "Missing code or state")
                return

            # Exchange tokens
            try:
                tokens = g_state.pkce.handle_callback(code, state)
            except Exception as ex:
                send_response(500, "text/plain", f"Token exchange failed: {ex}")
                return

            # Set a session cookie, redirect to /protected
            self.send_response(302)
            self.send_header("Location", "/protected")
            cookie_value = tokens["access_token"]
            self.send_header("Set-Cookie", f"KC_SESSION={cookie_value}; Path=/; HttpOnly; Secure; SameSite=Strict")
            self.end_headers()

        elif path == "/protected":
            # Check cookie
            cookie_header = self.headers.get("Cookie", "")
            cookies = {}
            for c in cookie_header.split(";"):
                c = c.strip()
                if "=" in c:
                    k, v = c.split("=", 1)
                    cookies[k] = v

            session_token = cookies.get("KC_SESSION")

            if not session_token:
                # No session -> redirect
                self.send_response(302)
                self.send_header("Location", "/auth/keycloak")
                self.end_headers()
                return

            # Validate session
            if not g_state.pkce.validate_session(session_token):
                send_response(401, "text/plain", "Invalid session")
                return

            # Optionally decode payload to show claims
            claims = decode_jwt_payload(session_token)
            if not claims:
                # fallback
                send_response(200, "text/html", "<h1>Protected!</h1><p>Authenticated, no claims parsed.</p>")
                return

            # Build a small table
            rows = ""
            for k, v in claims.items():
                rows += f"<tr><td>{k}</td><td>{v}</td></tr>\n"

            html = f"""
            <html><body>
            <h1>Protected Resource (Python)</h1>
            <h2>Hello, {claims.get('preferred_username', claims.get('sub', 'anonymous'))}!</h2>
            <table border="1" cellpadding="5"><tr><th>Claim</th><th>Value</th></tr>
            {rows}
            </table>
            <p><a href='/'>Return to Home</a></p>
            </body></html>
            """
            send_response(200, "text/html", html)

        else:
            send_response(404, "text/plain", "Not Found")

# ---------------------------------------------------------------------------
# 4) Initialize PKCE, start HTTPS server
# ---------------------------------------------------------------------------
def main():
    # 4a) Create PKCE object
    print("Creating PKCE instance")
    pkce = KeycloakPKCE(config_path="config/library_config.json")

    # optional: set proxy if needed
    pkce.set_proxy("host.docker.internal", 9443)

    # init PKCE, set redirect URI, get auth URL
    pkce.init()
    pkce.set_redirect_uri("https://pkce-client.local.com:18080/auth/keycloak/callback")
    auth_url = pkce.get_auth_url()

    # store in global state
    g_state.pkce = pkce
    g_state.auth_url = auth_url
    g_state.initialized = True

    # 4b) Create an SSLContext (self-signed certs)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(
        certfile="certs/client/pkce-client.py.pem",
        keyfile="certs/client/pkce-client.py.key"
    )
    
    # 4c) Start an HTTPS server on 0.0.0.0:18080
    server_address = ("0.0.0.0", 18080)
    httpd = HTTPServer(server_address, PKCERequestHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Open https://pkce-client.local.com:18080/auth/keycloak in your browser.")
    print("Server started on https://0.0.0.0:18080 ... Press Ctrl+C to stop.")

    # 4d) Serve until Ctrl+C
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        httpd.server_close()
        pkce.destroy()

if __name__ == "__main__":
    main()
