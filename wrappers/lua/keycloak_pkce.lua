local ffi = require("ffi")
local M = {}

-- Single global instance storage
local _instance = {
    config = nil,
    handle = nil,
    initialized = false
}

-- Add ngx detection for OpenResty environment
local has_ngx, ngx = pcall(require, "ngx")

-- Logging wrapper that works in both OpenResty and standalone Lua
local function log(level, msg, ...)
    if has_ngx then
        ngx.log(level, string.format(msg, ...))
    else
        print(string.format(msg, ...))
    end
end

-- FFI definitions for the C API
ffi.cdef[[
    typedef struct kc_pkce_context_s* kc_pkce_handle_t;
    typedef struct kc_pkce_config_s* kc_pkce_config_t;
    
    typedef struct {
        const char* host;
        uint16_t port;
    } kc_pkce_proxy_config_t;

    typedef struct {
        char* access_token;
        char* refresh_token;
        char* id_token;
        char* token_type;
        uint64_t expires_in;
        char* error;
        char* error_description;
    } kc_pkce_token_info_t;

    /* Core API functions */
    int kc_pkce_config_create(kc_pkce_config_t* config);
    int kc_pkce_config_load_file(kc_pkce_config_t config, const char* path);
    void kc_pkce_config_destroy(kc_pkce_config_t config);
    int kc_pkce_create(kc_pkce_handle_t* handle, const kc_pkce_config_t config);
    void kc_pkce_destroy(kc_pkce_handle_t handle);
    int kc_pkce_set_redirect_uri(kc_pkce_handle_t handle, const char* uri);
    int kc_pkce_create_auth_url(kc_pkce_handle_t handle, char* buffer, size_t size);
    int kc_pkce_handle_callback(kc_pkce_handle_t handle, const char* code, 
                               const char* state, kc_pkce_token_info_t* token_info);
    bool kc_pkce_validate_session(kc_pkce_handle_t handle, const char* token);
    void kc_pkce_free_token_info(kc_pkce_token_info_t* token_info);
    /* Added missing proxy function */
    int kc_pkce_set_proxy_config(const kc_pkce_proxy_config_t* proxy);
]]

-- Load the C shared library
local lib_path = os.getenv("KC_PKCE_LIB") or "libkc_pkce.so"
local ok, lib = pcall(ffi.load, lib_path)
if not ok then
    error("Failed to load Keycloak PKCE library: " .. lib)
end

-- Create a new PKCE client instance
function M.new(config_path)
    -- If already initialized, return existing instance
    if _instance.initialized then
        return _instance
    end

    local self = {}
    
    -- Step 1: Create config
    log(ngx and ngx.INFO or "INFO", "Creating PKCE configuration")
    local config = ffi.new("kc_pkce_config_t[1]")
    local result = lib.kc_pkce_config_create(config)
    if result ~= 0 then
        error("Failed to create PKCE configuration")
    end
    
    -- Store config globally
    _instance.config = config
    
    -- Step 2: Load config file
    log(ngx and ngx.INFO or "INFO", "Loading config from: %s", config_path)
    result = lib.kc_pkce_config_load_file(config[0], config_path)
    if result ~= 0 then
        lib.kc_pkce_config_destroy(config[0])
        _instance.config = nil
        error("Failed to load config from: " .. config_path)
    end

    -- Step 3: Set proxy configuration
    function self:set_proxy(host, port)
        log(ngx and ngx.INFO or "INFO", "Setting global proxy: %s:%d", host, port)
        local proxy = ffi.new("kc_pkce_proxy_config_t")
        proxy.host = host
        proxy.port = port
        result = lib.kc_pkce_set_proxy_config(proxy)
        if result ~= 0 then
            error("Failed to set proxy configuration")
        end
        return true
    end

    -- Step 4: Create PKCE instance
    function self:init()
        if _instance.initialized then
            return true
        end

        log(ngx and ngx.INFO or "INFO", "Creating PKCE instance")
        local handle = ffi.new("kc_pkce_handle_t[1]")
        result = lib.kc_pkce_create(handle, _instance.config[0])
        if result ~= 0 then
            error("Failed to create PKCE instance")
        end

        _instance.handle = handle
        _instance.initialized = true
        
        return true
    end

    -- Step 5: Set redirect URI
    function self:set_redirect_uri(redirect_uri)
        if not _instance.initialized then
            error("PKCE instance not initialized. Call init() first")
        end

        log(ngx and ngx.INFO or "INFO", "Setting redirect URI: %s", redirect_uri)
        result = lib.kc_pkce_set_redirect_uri(_instance.handle[0], redirect_uri)
        if result ~= 0 then
            error("Failed to set redirect URI")
        end
        return true
    end

    -- Generate authorization URL
    function self:get_auth_url()
        if not _instance.initialized then
            error("PKCE instance not initialized")
        end

        local buffer = ffi.new("char[4096]")
        ffi.fill(buffer, 4096)

        result = lib.kc_pkce_create_auth_url(_instance.handle[0], buffer, 4096)
        if result ~= 0 then
            error("Failed to create auth URL")
        end

        local url = ffi.string(buffer)
        -- log(ngx and ngx.INFO or "INFO", "Generated auth URL: %s", url)
        return url
    end

    -- Handle OAuth callback
    function self:handle_callback(code, state)
        if not _instance.initialized then
            error("PKCE instance not initialized")
        end

        if not code or not state then
            error("Missing code or state parameters")
        end

        log(ngx and ngx.INFO or "INFO", "Handling callback - code: %s, state: %s", 
            code:sub(1,8).."...", state)

        local token_info = ffi.new("kc_pkce_token_info_t")
        ffi.fill(token_info, ffi.sizeof("kc_pkce_token_info_t"))

        local result = lib.kc_pkce_handle_callback(_instance.handle[0], code, state, token_info)
        
        log(ngx and ngx.INFO or "INFO", "Token exchange result: %d", result)

        if result ~= 0 then
            local err_msg = token_info.error and ffi.string(token_info.error) or "unknown error"
            local err_desc = token_info.error_description and 
                           ffi.string(token_info.error_description) or ""
            
            lib.kc_pkce_free_token_info(token_info)
            error(string.format("Token exchange failed: %s (%s)", err_msg, err_desc))
        end

        local tokens = {
            access_token = token_info.access_token and ffi.string(token_info.access_token) or nil,
            refresh_token = token_info.refresh_token and ffi.string(token_info.refresh_token) or nil,
            id_token = token_info.id_token and ffi.string(token_info.id_token) or nil,
            token_type = token_info.token_type and ffi.string(token_info.token_type) or nil,
            expires_in = tonumber(token_info.expires_in) or 0
        }

        lib.kc_pkce_free_token_info(token_info)
        return tokens
    end

    -- Validate session
    function self:validate_session(token)
        if not _instance.initialized or not token then
            return false
        end
        return lib.kc_pkce_validate_session(_instance.handle[0], token)
    end

    -- Cleanup only when explicitly called
    function self:destroy()
        if _instance.handle then
            lib.kc_pkce_destroy(_instance.handle[0])
        end
        if _instance.config then
            lib.kc_pkce_config_destroy(_instance.config[0])
        end
        _instance = {
            config = nil,
            handle = nil,
            initialized = false
        }
    end

    -- Store all methods in the instance
    _instance.set_proxy = self.set_proxy
    _instance.init = self.init
    _instance.set_redirect_uri = self.set_redirect_uri
    _instance.get_auth_url = self.get_auth_url
    _instance.handle_callback = self.handle_callback
    _instance.validate_session = self.validate_session
    _instance.destroy = self.destroy

    return _instance
end

return M
