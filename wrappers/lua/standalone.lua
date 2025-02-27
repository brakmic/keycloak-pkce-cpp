--------------------------------------------------------------------------------
-- Keycloak PKCE Authentication Demo (Standalone Version)
-- Version: 1.0
--
-- This demo implements OAuth2 PKCE authentication flow with Keycloak using
-- lua-http for a lightweight, embedded HTTPS server with proper SSL support
-- and non-blocking I/O through cqueues.
--------------------------------------------------------------------------------

local tls = require "http.tls"
local openssl = require "openssl"
local x509 = require "openssl.x509"
local pkey = require "openssl.pkey"
local openssl_ctx = require "openssl.ssl.context"
local ssl = require "ssl"
local http_server = require "http.server"
local http_headers = require "http.headers"
local http_util = require "http.util"
local posix = require "posix"
local KeycloakPKCE = require "keycloak_pkce"
local cjson = require("cjson")
local basexx = require("basexx")
local ffi = require "ffi"

-- Application settings
local APP_SETTINGS = {
    server = {
        protocol = "https",
        host = "localhost",
        bind = "0.0.0.0",
        port = 18080
    },
    proxy = {
        host = "host.docker.internal",
        port = 9443
    },
    auth = {
        redirect_uri = "https://pkce-client.local.com:18080/auth/keycloak/callback"
    },
    paths = {
        library_config = "config/library_config.json",
        ssl_cert = "certs/client/lua_http_server.pem",
        ssl_key = "certs/client/lua_http_server.pkcs8.key"
    }
}

-- Global state
local g_state = {
    pkce = nil,
    auth_url = nil,
    initialized = false,
    running = true
}

-- Logging function
local function log(level, msg, ...)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    print(string.format("[%s] [%s] " .. msg, timestamp, level, ...))
    io.stdout:flush()
end

local function log_ssl_error()
    local err = ssl.error()
    if err then
        log("ERROR", "SSL Error: %s", err)
    end
end

-- Helper try function
local function try(f, ...)
    local ok, result = pcall(f, ...)
    if not ok then
        log("ERROR", result)
        return nil
    end
    return result
end

-- Keeping existing cookie handling
local function create_cookie(name, value, params)
    local cookie = string.format("%s=%s", name, value)
    if params then
        if params.path then cookie = cookie .. "; Path=" .. params.path end
        if params.httponly then cookie = cookie .. "; HttpOnly" end
        if params.secure then cookie = cookie .. "; Secure" end
        if params.samesite then cookie = cookie .. "; SameSite=" .. params.samesite end
    end
    return cookie
end

-- Helper function to parse cookies from headers
local function parse_cookies(cookie_header)
    if not cookie_header then return {} end
    local cookies = {}
    for cookie in cookie_header:gmatch("[^;]+") do
        local name, value = cookie:match("^%s*(.-)%s*=%s*(.-)%s*$")
        if name then cookies[name] = value end
    end
    return cookies
end

-- Helper function to set security headers
local function set_security_headers(headers)
    headers:append("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
    headers:append("Pragma", "no-cache")
    headers:append("Expires", "0")
    headers:append("X-Content-Type-Options", "nosniff")
    headers:append("X-Frame-Options", "DENY")
    headers:append("X-XSS-Protection", "1; mode=block")
    headers:append("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
end

-- Request handler
local cjson = require("cjson")
local basexx = require("basexx")

local function handle_request(server, stream)
    log("DEBUG", "New connection received")

    -- 1) Helper: split :path and :query for both HTTP/1.1 and HTTP/2
    local function split_path_and_query(req_headers)
        local raw_path = req_headers:get(":path") or "/"
        local raw_query = req_headers:get(":query")

        if raw_query then
            -- HTTP/2 style: path is everything before '?'; query is in :query
            return raw_path, raw_query
        else
            -- HTTP/1.1 style: path may already have ? in it
            local path_only, q = raw_path:match("^(.-)%?(.*)$")
            if path_only then
                return path_only, q
            else
                return raw_path, nil
            end
        end
    end

    -- 2) Helper: manually parse a query string into a Lua table
    local function parse_querystring(q)
        local res = {}
        for kv in (q or ""):gmatch("[^&]+") do
            local key, val = kv:match("([^=]*)=?(.*)")
            -- Optional decode if needed:
            key = http_util.decodeURI(key or "")
            val = http_util.decodeURI(val or "")
            res[key] = val
        end
        return res
    end

    -- 3) Helper: respond with headers and optional body
    local function send_response(status, content_type, body)
        local headers = http_headers.new()
        headers:append(":status", status)
        headers:append("content-type", content_type)
        set_security_headers(headers)

        local ok, err = stream:write_headers(headers, body == nil)
        if not ok then
            log("ERROR", "Failed to write headers: %s", err)
            return
        end
        if body then
            ok, err = stream:write_chunk(body, true)
            if not ok then
                log("ERROR", "Failed to write body: %s", err)
            end
        end
    end

    -- 4) Helper: decode the middle part (payload) of a JWT
    local function decode_jwt_payload(jwt)
        -- Expect "header.payload.signature"
        local header_b64, payload_b64, signature_b64 = jwt:match("([^%.]+)%.([^%.]+)%.([^%.]+)")
        if not header_b64 or not payload_b64 or not signature_b64 then
            return nil, "Invalid JWT format (expected header.payload.signature)"
        end
        
        -- base64url decode the payload
        -- basexx.from_url64 automatically handles typical JWT base64url
        -- If length isn't multiple of 4, basexx also copes with that
        local payload_json = basexx.from_url64(payload_b64)
        if not payload_json then
            return nil, "Failed to decode JWT payload"
        end

        -- parse JSON
        local ok, claims_or_err = pcall(cjson.decode, payload_json)
        if not ok then
            return nil, "Failed to parse JSON claims: " .. tostring(claims_or_err)
        end
        return claims_or_err, nil
    end

    -------------------------------------------------------------------------
    -- A) Fetch request headers safely
    -------------------------------------------------------------------------
    local ok, req_headers_or_err = pcall(function()
        return stream:get_headers()
    end)
    if not ok or not req_headers_or_err then
        send_response("500", "text/plain", "Internal Server Error")
        return
    end

    local req_headers = req_headers_or_err

    -------------------------------------------------------------------------
    -- B) Split the path + query
    -------------------------------------------------------------------------
    local path, query_str = split_path_and_query(req_headers)
    log("DEBUG", "Request path: %s", path)
    log("DEBUG", "Query string: %s", query_str or "nil")

    -------------------------------------------------------------------------
    -- C) Route handling
    -------------------------------------------------------------------------
    if path == "/" then
        send_response("200", "text/html", [[
            <html><body>
            <h1>Keycloak PKCE Demo</h1>
            <p><a href='/auth/keycloak'>Start Login</a></p>
            <p><a href='/protected'>Protected Resource</a></p>
            </body></html>
        ]])

    elseif path == "/auth/keycloak" then
        -- Redirect to Keycloak login
        local headers = http_headers.new()
        headers:append(":status", "302")
        headers:append("location", g_state.auth_url)
        set_security_headers(headers)

        local ok, err = stream:write_headers(headers, true)
        if not ok then
            log("ERROR", "Failed to write redirect headers: %s", err)
        end

    elseif path == "/auth/keycloak/callback" then
        -- Callback from Keycloak after login
        log("DEBUG", "Callback route: extracting query params")

        local params = parse_querystring(query_str)
        local code, state = params.code, params.state
        log("DEBUG", "code=%s, state=%s", code or "nil", state or "nil")

        if params.error then
            send_response("400", "text/plain",
                string.format("Auth error: %s", params.error))
            return
        end

        if not code or not state then
            send_response("400", "text/plain", "Missing code or state")
            return
        end

        local tokens = try(g_state.pkce.handle_callback, g_state.pkce, code, state)
        if not tokens then
            send_response("500", "text/plain", "Token exchange failed")
            return
        end

        -- Set cookie & redirect to /protected
        local headers = http_headers.new()
        headers:append(":status", "302")
        headers:append("location", "/protected")
        headers:append("set-cookie", create_cookie('KC_SESSION', tokens.access_token, {
            path = '/',
            httponly = true,
            secure = true,
            samesite = 'Strict'
        }))
        set_security_headers(headers)
        local ok, err = stream:write_headers(headers, true)
        if not ok then
            log("ERROR", "Failed to write callback headers: %s", err)
        end

    elseif path == "/protected" then
        -- Protected resource
        local cookies = parse_cookies(req_headers:get("cookie"))
        local session = cookies.KC_SESSION

        if not session then
            -- No session -> redirect to login
            local headers = http_headers.new()
            headers:append(":status", "302")
            headers:append("location", "/auth/keycloak")
            set_security_headers(headers)
            local ok, err = stream:write_headers(headers, true)
            if not ok then
                log("ERROR", "Failed to write protected headers: %s", err)
            end
            return
        end

        -- Validate existing session
        if not try(g_state.pkce.validate_session, g_state.pkce, session) then
            send_response("401", "text/plain", "Invalid session")
            return
        end

        -- Decode JWT payload to show user claims
        local claims, err = decode_jwt_payload(session)
        if not claims then
            -- If decoding fails, just show a minimal screen
            send_response("200", "text/html", [[
                <html><body>
                <h1>Protected Resource</h1>
                <p>Successfully authenticated, but couldn't decode JWT claims.</p>
                <p><a href='/'>Return to Home</a></p>
                </body></html>
            ]])
            return
        end

        -- Build an HTML table of claims
        local html_parts = {}
        html_parts[#html_parts+1] = [[
            <html>
            <head>
                <style>
                    table { border-collapse: collapse; width: 100%; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                </style>
            </head>
            <body>
            <h1>Protected Resource</h1>
        ]]

        -- Show a basic greeting
        local username = claims.preferred_username or claims.sub or "Anonymous"
        html_parts[#html_parts+1] = "<h2>Welcome " .. username .. "!</h2>\n"

        -- Start the table
        html_parts[#html_parts+1] = [[
            <h3>Your JWT Claims:</h3>
            <table>
            <tr><th>Claim</th><th>Value</th></tr>
        ]]

        -- Add each claim as a row
        for k, v in pairs(claims) do
            local value_str
            if type(v) == "table" then
                value_str = cjson.encode(v)
            elseif type(v) == "boolean" then
                value_str = v and "true" or "false"
            else
                value_str = tostring(v)
            end
            html_parts[#html_parts+1] = string.format("<tr><td>%s</td><td>%s</td></tr>\n", k, value_str)
        end

        -- Close table & page
        html_parts[#html_parts+1] = [[
            </table>
            <p><a href='/'>Return to Home</a></p>
            </body></html>
        ]]

        -- Concatenate & send final HTML
        local final_html = table.concat(html_parts, "")
        send_response("200", "text/html", final_html)

    else
        -- 404
        send_response("404", "text/plain", "Not Found")
    end
end

-- Initialize PKCE
local function init_kc_pkce()
    log("INFO", "Creating PKCE instance with config: %s", APP_SETTINGS.paths.library_config)
    
    local pkce = try(KeycloakPKCE.new, APP_SETTINGS.paths.library_config)
    if not pkce then
        return nil
    end

    if APP_SETTINGS.proxy.host then
        if not try(pkce.set_proxy, pkce, APP_SETTINGS.proxy.host, APP_SETTINGS.proxy.port) then
            return nil
        end
        log("INFO", "Configured proxy: %s:%d", APP_SETTINGS.proxy.host, APP_SETTINGS.proxy.port)
    end

    if not try(pkce.init, pkce) then
        return nil
    end

    if not try(pkce.set_redirect_uri, pkce, APP_SETTINGS.auth.redirect_uri) then
        return nil
    end

    local auth_url = try(pkce.get_auth_url, pkce)
    if not auth_url then
        return nil
    end

    return pkce, auth_url
end

-- Signal handling setup
local function setup_signals()
    posix.signal(posix.SIGINT, function()
        print("")
        log("INFO", "Received SIGINT, shutting down...")
        g_state.running = false
    end)
end

-- Main function that starts everything
local function main()
    setup_signals()
    
    log("INFO", "Starting Keycloak PKCE Demo...")

    -- Initialize PKCE
    local pkce, auth_url = init_kc_pkce()
    if not pkce or not auth_url then
        log("ERROR", "PKCE initialization failed")
        return 1
    end

    -- Store in global state
    g_state.pkce = pkce
    g_state.auth_url = auth_url
    g_state.initialized = true

      -- Create custom SSL context
    local ctx = assert(openssl_ctx.new("TLS", true))
    ctx:setVerify(openssl_ctx.VERIFY_NONE)
    ctx:setCipherList(tls.intermediate_cipher_list)
    ctx:setOptions(bit.bor(
        openssl_ctx.OP_NO_SSLv2,
        openssl_ctx.OP_NO_SSLv3,
        openssl_ctx.OP_NO_COMPRESSION,
        openssl_ctx.OP_CIPHER_SERVER_PREFERENCE
    ))
    
    -- Load certificate and key from files
    local cert_data = assert(io.open(APP_SETTINGS.paths.ssl_cert)):read("*a")
    local key_data = assert(io.open(APP_SETTINGS.paths.ssl_key)):read("*a")

    -- Create proper X509 and PKey objects
    local cert = assert(x509.new(cert_data))
    local key = assert(pkey.new(key_data))
    
    -- Set certificate and key directly
    ctx:setCertificate(cert)
    ctx:setPrivateKey(key)
    
    -- Start server
    local server = assert(http_server.listen({
        host = APP_SETTINGS.server.bind,
        port = APP_SETTINGS.server.port,
        onstream = handle_request,
        tls = true,
        ctx = ctx,
        alpn_protocols = {"http/1.1", "http2"}
    }))

    -- Log server configuration
    log("INFO", "Server configuration:")
    log("INFO", "  Bind address: %s", APP_SETTINGS.server.bind)
    log("INFO", "  Port: %d", APP_SETTINGS.server.port)
    log("INFO", "  SSL enabled: yes")
    log("INFO", "  Certificate: %s", APP_SETTINGS.paths.ssl_cert)
    log("INFO", "  Key: %s", APP_SETTINGS.paths.ssl_key)

    -- Run server until shutdown
    local cqueues = require "cqueues"
    local cq = cqueues.new()
    cq:wrap(function()
        while g_state.running do
            local ok, err = server:step(1)
            if not ok then
                if err and type(err) == "string" and err:match("ssl") then
                    log("DEBUG", "SSL warning (continuing): %s", err)
                else
                    log("ERROR", "Server error: %s", err)
                    break
                end
            end
        end
    end)
    assert(cq:loop())

    -- Cleanup
    server:close()
    if g_state.pkce then
        g_state.pkce:destroy()
    end

    log("INFO", "Server stopped")
    return 0
end

-- Run main with error handling
local ok, err = xpcall(main, debug.traceback)
if not ok then
    log("ERROR", "Fatal error occurred:")
    log("ERROR", "Stack trace:")
    log("ERROR", err)
    if g_state.pkce then
        g_state.pkce:destroy()
    end
    os.exit(1)
end
