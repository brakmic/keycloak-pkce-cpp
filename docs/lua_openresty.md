## OpenResty/Nginx Integration

The library can be used with [OpenResty](https://openresty.org/en/), providing better performance and scalability through Nginx's event-driven architecture.

### Nginx Configuration

```nginx
# Basic settings
worker_processes 1;
error_log logs/error.log debug;

http {
    # OpenResty Lua settings
    lua_package_path '${prefix}/?.lua;;';
    lua_code_cache on;
    
    # Shared memory for state
    lua_shared_dict init_state 1m;
    lua_shared_dict pkce_state 1m;

    # Initialize PKCE client once at startup
    init_by_lua_block {
        local KeycloakPKCE = require "keycloak_pkce"
        package.loaded.pkce_instance = KeycloakPKCE.new(
            "config/library_config.json"
        )
        
        -- Configure proxy and redirect URI
        package.loaded.pkce_instance:set_proxy("host.docker.internal", 9443)
        package.loaded.pkce_instance:init()
        package.loaded.pkce_instance:set_redirect_uri(
            "https://pkce-client.local.com:18080/auth/keycloak/callback"
        )
    }

    server {
        listen 18080 ssl;
        server_name pkce-client.local.com;

        # SSL configuration
        ssl_certificate     certs/client/pkce-client.lua.pem;
        ssl_certificate_key certs/client/pkce-client.lua.key;
        
        # Make PKCE instance available to handlers
        rewrite_by_lua_block {
            ngx.ctx.pkce = package.loaded.pkce_instance
        }
```

### Key Differences from Standalone Server

1. **Initialization**
   - Single PKCE instance created during Nginx startup
   - Stored in `package.loaded` for persistence across requests
   - Available to all worker processes

2. **State Management**
   - Uses Nginx shared memory zones
   - Thread-safe state handling
   - Persistent across worker processes

3. **Request Handling**
   ```lua
   -- Access PKCE client in handlers
   location = /auth/keycloak {
       content_by_lua_block {
           local pkce = ngx.ctx.pkce
           local auth_url = pkce:get_authorization_url()
           return ngx.redirect(auth_url)
       }
   }
   ```

4. **Session Management**
   ```lua
   -- Handle callback and set secure cookies
   location = /auth/keycloak/callback {
       content_by_lua_block {
           local tokens = pkce:handle_callback(
               ngx.req.get_uri_args().code,
               ngx.req.get_uri_args().state
           )
           
           ngx.header["Set-Cookie"] = {
               "KC_SESSION=" .. tokens.access_token .. 
               "; Path=/; HttpOnly; Secure; SameSite=Strict"
           }
       }
   }
   ```

5. **Protected Resources**
   ```lua
   location = /protected {
       content_by_lua_block {
           local token = ngx.var.cookie_KC_SESSION
           if not token or not pkce:validate_session(token) then
               return ngx.redirect("/auth/keycloak")
           end
           -- Serve protected content
       }
   }
   ```

### Advantages of OpenResty Integration

1. **Performance**
   - Non-blocking I/O
   - Connection pooling
   - Shared memory caching
   - Worker process model

2. **Security**
   - Built-in SSL/TLS handling
   - Header filtering
   - Request rate limiting
   - IP blocking

3. **Scalability**
   - Multiple worker processes
   - Load balancing
   - Shared state across workers
   - Connection pooling

4. **Monitoring**
   - Detailed access logs
   - Error logging
   - Request timing
   - SSL handshake debugging
