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
    class IStateStore {
    public:
        virtual ~IStateStore() = default;
        virtual std::string create(std::string_view code_verifier) = 0;
        virtual std::string verify(std::string_view state) = 0;
    };

    class StateStore : public IStateStore {
    public:
        explicit StateStore(const config::StateStoreConfig& config);
        std::string create(std::string_view code_verifier) override;
        std::string verify(std::string_view state) override;
    private:
        std::unordered_map<std::string, StateEntry> store_;
        mutable std::shared_mutex mutex_;
        const config::StateStoreConfig& config_;
    };
}
```

## HTTP Client

Handles secure communication with Keycloak through a flexible transport layer:

```cpp
namespace keycloak::http {
    // Transport interface hierarchy
    class ITransport {
    public:
        virtual ~ITransport() = default;
        virtual Response send_request(
            std::string_view host,
            std::string_view port, 
            std::string_view method,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string>& headers) = 0;
    };
    
    class ISecureTransport : virtual public ITransport {
    public:
        virtual ~ISecureTransport() = default;
        virtual void configure_ssl(const SSLConfig& config) = 0;
    };
    
    class IProxyAware : virtual public ITransport {
    public:
        virtual ~IProxyAware() = default;
        virtual void configure_proxy(const ProxyConfig& config) = 0;
    };
    
    // HttpClient implementation
    class HttpClient {
    public:
        // Factory methods for common client types
        static std::shared_ptr<HttpClient> create(std::unique_ptr<ITransport> transport);
        static std::shared_ptr<HttpClient> create_https_client(
            const SSLConfig& ssl_config = {},
            const ProxyConfig& proxy_config = {});
        static std::shared_ptr<HttpClient> create_http_client(
            const ProxyConfig& proxy_config = {});
        
        // HTTP operations
        Response post(
            std::string_view host,
            std::string_view port,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string>& headers);
            
        // Access to underlying transport
        std::shared_ptr<ITransport> get_transport();
            
    private:
        std::unique_ptr<ITransport> transport_;
        std::shared_ptr<ITransport> shared_transport_;
    };
    
    // Response structure
    struct Response {
        int status_code;
        std::string body;
        std::unordered_map<std::string, std::string> headers;
    };
}
```

### ASIO Transport Implementation

```cpp
namespace keycloak::http {
    class AsioTransport : public ITransport, public IProxyAware {
    public:
        AsioTransport();
        Response send_request(
            std::string_view host,
            std::string_view port,
            std::string_view method,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string>& headers) override;
            
        void configure_proxy(const ProxyConfig& config) override;
        
    protected:
        asio::io_context io_context_;
        ProxyConfig proxy_config_;
    };
    
    class AsioSecureTransport : 
        public AsioTransport,
        public ISecureTransport {
    public:
        AsioSecureTransport();
        void configure_ssl(const SSLConfig& config) override;
        
    protected:
        asio::ssl::context ssl_context_;
        SSLConfig ssl_config_;
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
        http::SSLConfig ssl;
    };

    struct PKCEConfig {
        StateStoreConfig state_store;
        CookieConfig cookies;
    };

    struct LibraryConfig {
        KeycloakConfig keycloak;
        PKCEConfig pkce;
    };
}

namespace keycloak::http {
    struct SSLConfig {
        bool verify_peer = true;
        std::string ca_cert_path;
        std::string client_cert_path;
        std::string client_key_path;
    };
    
    struct ProxyConfig {
        std::string host;
        uint16_t port = 0;
        
        bool is_enabled() const {
            return !host.empty() && port > 0;
        }
    };
}
```

## Keycloak Client

Provides high-level access to Keycloak server operations:

```cpp
namespace keycloak {
    class KeycloakClient : public auth::ITokenService {
    public:
        static std::shared_ptr<KeycloakClient> create(
            const config::KeycloakConfig& config,
            std::shared_ptr<http::HttpClient> http_client = nullptr);
            
        // ITokenService implementation
        std::string get_authorization_endpoint() const override;
        auth::TokenResponse exchange_code(
            std::string_view code,
            std::string_view code_verifier,
            std::string_view redirect_uri,
            std::string_view client_id) override;
        const std::vector<std::string>& get_scopes() const override;
        
    private:
        const config::KeycloakConfig& config_;
        std::shared_ptr<http::HttpClient> http_client_;
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
        
    KC_PKCE_API kc_pkce_error_t kc_pkce_set_ssl_config(
        kc_pkce_config_t config,
        const kc_pkce_ssl_config_t* ssl_config);
}

// Language bindings use this C API:
// - Python via ctypes
// - Lua via LuaJIT FFI
```

## Internal Wrappers

C API implementation uses wrapper classes to bridge between C and C++:

```cpp
namespace keycloak::c_api {
    class ConfigWrapper {
    public:
        void load_from_file(std::string_view path);
        void set_keycloak_config(const kc_pkce_keycloak_config_t* config);
        void set_ssl_config(const kc_pkce_ssl_config_t* ssl_config);
        const config::LibraryConfig& get_config() const;
        
    private:
        config::LibraryConfig config_;
    };
    
    class PKCEWrapper {
    public:
        PKCEWrapper(const config::LibraryConfig& config);
        std::string create_authorization_url(std::string_view redirect_uri);
        kc_pkce_error_t handle_callback(const char* code, 
                                       const char* state,
                                       kc_pkce_token_info_t* token_info);
        
    private:
        std::shared_ptr<auth::IAuthenticationStrategy> strategy_;
    };
}
```
