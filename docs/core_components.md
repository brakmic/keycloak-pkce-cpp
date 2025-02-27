# Core Components

## Authentication Strategy

The authentication module implements the Strategy pattern for OAuth2 PKCE flow, defined through the IAuthenticationStrategy interface:

```cpp
namespace keycloak::auth {
    class IAuthenticationStrategy {
    public:
        // Creates authorization URL for OAuth2 flow
        virtual std::string create_authorization_url() = 0;
        
        // Handles OAuth2 callback with PKCE verification
        virtual TokenResponse handle_callback(
            std::string_view code, 
            std::string_view state) = 0;
        
        // Validates session using stored cookies
        virtual bool validate_session(
            const std::unordered_map<std::string, std::string>& cookies) = 0;

        // Access to cookie configuration
        virtual const config::CookieConfig& get_cookie_config() const = 0;
    };
}
```

### PKCE Strategy
Concrete implementation of the authentication strategy using PKCE (RFC 7636):

```cpp
class PKCEStrategy : public IAuthenticationStrategy {
public:
    PKCEStrategy(
        std::shared_ptr<ITokenService> token_service,
        std::string_view client_id,
        std::string_view redirect_uri,
        const config::PKCEConfig& pkce_config);

    std::string create_authorization_url() override;
    TokenResponse handle_callback(std::string_view code, 
                                std::string_view state) override;
    bool validate_session(const std::unordered_map<std::string, 
                                                 std::string>& cookies) override;
private:
    std::shared_ptr<ITokenService> token_service_;
    std::string client_id_;
    std::string redirect_uri_;
    const config::CookieConfig& cookie_config_;
    pkce::StateStore state_store_;
};
```

## Token Service

Interface for OAuth2 token operations:

```cpp
class ITokenService {
public:
    // Gets Keycloak authorization endpoint URL
    virtual std::string get_authorization_endpoint() const = 0;
    
    // Exchanges authorization code for tokens
    virtual TokenResponse exchange_code(
        std::string_view code,
        std::string_view code_verifier,
        std::string_view redirect_uri,
        std::string_view client_id) = 0;
    
    // Gets configured OAuth2 scopes
    virtual const std::vector<std::string>& get_scopes() const = 0;
};
```

## State Management

Manages PKCE state and CSRF protection:

```cpp
namespace keycloak::pkce {
    class StateStore {
    public:
        explicit StateStore(const config::StateStoreConfig& config);
        
        // Creates new state entry with code verifier
        std::string create_state(std::string_view code_verifier);
        
        // Validates state and returns associated verifier
        std::string verify_and_consume(std::string_view state);
    private:
        std::unordered_map<std::string, StateEntry> store_;
        mutable std::shared_mutex mutex_;
        const config::StateStoreConfig& config_;
    };
}
```

## HTTP Client

Handles secure communication with Keycloak:

```cpp
namespace keycloak::http {
    class HttpClient {
    public:
        struct Response {
            int status_code;
            std::string body;
            std::unordered_map<std::string, std::string> headers;
        };

        static Response post(
            std::string_view host,
            std::string_view port,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string>& headers,
            const SSLConfig& ssl_config,
            const ProxyConfig& proxy_config);
    };
}
```

## Configuration

Type-safe configuration system:

```cpp
namespace keycloak::config {
    struct KeycloakConfig {
        std::string protocol;
        std::string host;
        uint16_t port;
        std::string realm;
        std::string client_id;
        std::vector<std::string> scopes;
        SSLConfig ssl;
    };

    struct LibraryConfig {
        KeycloakConfig keycloak;
        PKCEConfig pkce;
    };
}
```

## Language Integration

The library provides a C API that enables integration with other languages:

```cpp
// C API wrapper
extern "C" {
    KC_PKCE_API kc_pkce_error_t kc_pkce_create(
        kc_pkce_handle_t* handle, 
        const kc_pkce_config_t config);
        
    KC_PKCE_API kc_pkce_error_t kc_pkce_handle_callback(
        kc_pkce_handle_t handle,
        const char* code,
        const char* state,
        kc_pkce_token_info_t* token_info);
}

// Language bindings use this C API:
// - Python via ctypes
// - Lua via LuaJIT FFI
```
