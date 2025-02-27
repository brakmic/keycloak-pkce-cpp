# Lua Integration Guide

## Overview
The Lua binding uses LuaJIT's FFI (Foreign Function Interface) to interact with the Keycloak PKCE library's C API. This provides high-performance integration while maintaining Lua's simplicity.

## Requirements
- LuaJIT 2.0+
- OpenSSL libraries
- lua-http (for standalone server implementation)

### System Dependencies
```bash
# Install basic development packages
sudo apt install -y libssl-dev pkg-config lua5.1 libluajit-5.1-dev liblua5.1-dev zlib1g-dev
```

### Lua Dependencies
The following Lua packages are required:

#### Core Dependencies
```bash
# Install essential packages for HTTPS and JSON handling
sudo luarocks install luasocket    # TCP/IP support
sudo luarocks install luasec       # SSL/TLS support
sudo luarocks install lua-cjson    # JSON parsing
sudo luarocks install basexx       # Base64 encoding
```

#### HTTP Server Dependencies
For the standalone server implementation:
```bash
# Install HTTP server requirements
sudo luarocks install cqueues      # Async I/O
sudo luarocks install lua-http     # HTTP/2 server
```

#### Optional Dependencies
For advanced features and development:
```bash
# Install additional utilities
sudo luarocks install luaposix     # POSIX functionality
sudo luarocks install luaossl      # OpenSSL bindings
sudo luarocks install lzlib        # Compression support
```

## Basic Usage

```lua
local kc = require "keycloak_pkce"

-- Load configuration
local config = kc.load_config("config/library_config.json")

-- Create PKCE instance
local pkce, err = kc.new(config)
if not pkce then
    error("Failed to create PKCE instance: " .. err)
end

-- Get authorization URL
local auth_url = pkce:get_authorization_url()

-- Handle callback
local tokens = pkce:handle_callback(code, state)

-- Validate session
local is_valid = pkce:validate_session(tokens.access_token)
```

## Configuration

```lua
-- Load from JSON file
local config = kc.load_config("config/library_config.json")

-- Or create programmatically
local config = {
    keycloak = {
        protocol = "https",
        host = "keycloak.local.com",
        port = 9443,
        realm = "TestRealm",
        client_id = "test-client"
    },
    ssl = {
        verify_peer = true,
        ca_cert = "/path/to/ca.pem"
    }
}
```

## Standalone HTTP Server Example

```lua
local http_server = require "http.server"
local http_headers = require "http.headers"
local kc = require "keycloak_pkce"

-- Initialize PKCE
local config = kc.load_config("config/library_config.json")
local pkce = kc.new(config)

-- Request handler
local function handle_request(server, stream)
    local req_headers = stream:get_headers()
    local path = req_headers:get(":path")

    if path == "/login" then
        -- Redirect to Keycloak login
        local auth_url = pkce:get_authorization_url()
        local headers = http_headers.new()
        headers:append(":status", "302")
        headers:append("location", auth_url)
        stream:write_headers(headers, true)

    elseif path:match("^/auth/callback") then
        -- Handle OAuth callback
        local params = http_util.query_args(req_headers:get(":query"))
        local tokens = pkce:handle_callback(params.code, params.state)

        if tokens then
            local headers = http_headers.new()
            headers:append(":status", "302")
            headers:append("location", "/protected")
            headers:append("set-cookie", string.format(
                "session=%s; HttpOnly; Secure; SameSite=Strict",
                tokens.access_token
            ))
            stream:write_headers(headers, true)
        else
            local headers = http_headers.new()
            headers:append(":status", "400")
            stream:write_headers(headers, false)
            stream:write_chunk("Authentication failed", true)
        end
    end
end

-- Create and start server
local server = http_server.listen({
    host = "0.0.0.0",
    port = 8080,
    onstream = handle_request,
    tls = true,
    ctx = ssl_context
})

-- Run server
server:loop()
```

## Error Handling

```lua
local ok, err = pcall(function()
    local pkce = kc.new(config)
    local auth_url = pkce:get_authorization_url()
end)

if not ok then
    print("Error: " .. err)
end
```

## Resource Management
The Lua binding automatically manages resources through Lua's garbage collector:

```lua
do
    local pkce = kc.new(config)
    -- Use PKCE instance
end  -- Resources cleaned up when out of scope
```

## Security Considerations

- Use HTTPS for all communication
- Enable secure cookie attributes
- Validate state parameter
- Keep SSL certificates updated
- Use proxy settings in development environments

## Thread Safety Notes

- Configuration objects are thread-safe
- PKCE instances should not be shared between threads
- Each request should create its own instance if needed

# Environment Variables

- KC_PKCE_LIB - path to kc_pkce.so (C API)
- LD_LIBRARY_PATH
