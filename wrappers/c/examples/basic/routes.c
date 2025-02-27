#include "routes.h"
#include "context.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void set_security_headers(struct mg_connection* conn) {
  mg_response_header_add(conn, "Cache-Control", 
                        "no-cache, no-store, max-age=0, must-revalidate", -1);
  mg_response_header_add(conn, "Pragma", "no-cache", -1);
  mg_response_header_add(conn, "Expires", "0", -1);
  mg_response_header_add(conn, "X-Content-Type-Options", "nosniff", -1);
  mg_response_header_add(conn, "X-Frame-Options", "DENY", -1);
  mg_response_header_add(conn, "X-XSS-Protection", "1; mode=block", -1);
  mg_response_header_add(conn, "Strict-Transport-Security", 
                        "max-age=31536000; includeSubDomains", -1);
}

int handle_root(struct mg_connection* conn, void* cbdata) {
    (void)cbdata;
    set_security_headers(conn);
    mg_printf(conn,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><body>"
        "<h1>Keycloak PKCE Demo</h1>"
        "<p>This demo shows the PKCE authentication flow with Keycloak:</p>"
        "<ul>"
        "<li>Uses PKCE flow for secure authentication</li>"
        "<li>Manages tokens via secure cookies</li>"
        "<li>Protects resources with token validation</li>"
        "</ul>"
        "<p><a href='/auth/keycloak'>Start Authentication</a></p>"
        "<p><a href='/protected'>Access Protected Resource</a></p>"
        "</body></html>");
    return 1;
}

int handle_auth_init(struct mg_connection* conn, void* cbdata) {
    (void)cbdata;
    set_security_headers(conn);
    mg_printf(conn,
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n\r\n",
        g_context.auth_url);
    return 1;
}

int handle_callback(struct mg_connection* conn, void* cbdata) {
    (void)cbdata;
    if (!conn) {
        printf("Error: Invalid connection or request info\n");
        return 0;
    }

    const struct mg_request_info* req_info = mg_get_request_info(conn);
    if (!req_info) {
        printf("Error: Could not get request info\n");
        return 0;
    }
    
    if (!req_info->query_string) {
        printf("Error: No query string in callback\n");
        return handle_error(conn, "missing_parameters");
    }

    char buf[2048];
    const char *code = NULL, *state = NULL, *error = NULL;
    
    // Extract OAuth2 parameters
    int code_len = mg_get_var(req_info->query_string, 
                             strlen(req_info->query_string), 
                             "code", buf, sizeof(buf));
    if (code_len > 0) {
        code = strdup(buf);
    }
    
    int state_len = mg_get_var(req_info->query_string, 
                              strlen(req_info->query_string), 
                              "state", buf, sizeof(buf));
    if (state_len > 0) {
        state = strdup(buf);
    }
    
    int error_len = mg_get_var(req_info->query_string, 
                              strlen(req_info->query_string), 
                              "error", buf, sizeof(buf));
    if (error_len > 0) {
        error = strdup(buf);
    }

    // Debug output
    printf("Callback received - code: %s, state: %s, error: %s\n",
           code ? code : "null",
           state ? state : "null",
           error ? error : "null");

    set_security_headers(conn);

    // Handle authentication errors
    if (error) {
        mg_printf(conn,
            "HTTP/1.1 302 Found\r\n"
            "Location: /auth/error?error=%s\r\n\r\n",
            error);
        free((void*)error);
        free((void*)code);
        free((void*)state);
        return 1;
    }

    // Process successful authentication with null checks
    if (code && state && g_context.pkce) {
        kc_pkce_token_info_t token_info = {0};
        kc_pkce_error_t result = kc_pkce_handle_callback(g_context.pkce, 
                                                        code, state, &token_info);

        printf("Token exchange result: %d\n", result);

        if (result == KC_PKCE_SUCCESS && token_info.access_token) {
            // Set session cookie and redirect to protected resource
            mg_printf(conn,
                "HTTP/1.1 302 Found\r\n"
                "Set-Cookie: KC_SESSION=%s; Path=/; HttpOnly; Secure; SameSite=Strict\r\n"
                "Location: /protected\r\n\r\n",
                token_info.access_token);
        } else {
            mg_printf(conn,
                "HTTP/1.1 302 Found\r\n"
                "Location: /auth/error?error=token_exchange_failed\r\n\r\n");
        }

        kc_pkce_free_token_info(&token_info);
    } else {
        mg_printf(conn,
            "HTTP/1.1 302 Found\r\n"
            "Location: /auth/error?error=invalid_callback_parameters\r\n\r\n");
    }

    free((void*)code);
    free((void*)state);
    return 1;
}

int handle_protected(struct mg_connection* conn, void* cbdata) {
    (void)cbdata;
    const char* cookie_header = mg_get_header(conn, "Cookie");
    if (!cookie_header) {
        mg_printf(conn,
            "HTTP/1.1 302 Found\r\n"
            "Location: /auth/keycloak\r\n\r\n");
        return 1;
    }

    // Extract token from cookie
    char cookie_value[4096] = {0};
    if (mg_get_cookie(cookie_header, "KC_SESSION", 
                      cookie_value, sizeof(cookie_value)) <= 0) {
        mg_printf(conn,
            "HTTP/1.1 302 Found\r\n"
            "Location: /auth/error?error=missing_session\r\n\r\n");
        return 1;
    }

    // Debug token
    printf("Validating token: %s\n", cookie_value);

    // Validate access token from cookie
    bool valid = kc_pkce_validate_session(g_context.pkce, cookie_value);
    set_security_headers(conn);

    if (!valid) {
        printf("Token validation failed\n");
        mg_printf(conn,
            "HTTP/1.1 302 Found\r\n"
            "Location: /auth/error?error=invalid_token\r\n\r\n");
        return 1;
    }

    // Token is valid, show protected content
    mg_printf(conn,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><body>"
        "<h1>Protected Resource</h1>"
        "<p>Successfully authenticated!</p>"
        "<hr>"
        "<p><a href='/'>Return to Home</a></p>"
        "</body></html>");
    return 1;
}

int handle_error(struct mg_connection* conn, void* cbdata) {
    (void)cbdata;
    const struct mg_request_info* req_info = mg_get_request_info(conn);
    char error_buf[256] = "Unknown error";
    
    if (req_info->query_string) {
        mg_get_var(req_info->query_string, 
                    strlen(req_info->query_string),
                    "error", error_buf, sizeof(error_buf));
    }

    set_security_headers(conn);
    mg_printf(conn,
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><body>"
        "<h1>Authentication Error</h1>"
        "<p>Error: %s</p>"
        "<hr>"
        "<p><a href='/'>Return to Home</a></p>"
        "</body></html>",
        error_buf);
    return 1;
}

// Route table definition
const struct Route ROUTES[] = {
  { "/", handle_root, "GET" },
  { "/auth/keycloak", handle_auth_init, "GET" },
  { "/auth/keycloak/callback", handle_callback, "GET" },
  { "/protected", handle_protected, "GET" },
  { "/auth/error", handle_error, "GET" }
};

const size_t ROUTES_COUNT = sizeof(ROUTES) / sizeof(ROUTES[0]);
