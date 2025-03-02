# Architecture Overview

## High-Level Architecture

The Keycloak PKCE library follows a layered architecture with clear separation of concerns:

```plaintext
┌─────────────────────────────────────────────────┐
│              Language Bindings                  │
│            Python (ctypes)                      │
│            Lua (LuaJIT FFI)                     │
├─────────────────────────────────────────────────┤
│                    C API                        │
│            (kc_pkce.h Interface)                │
├─────────────────────────────────────────────────┤
│              Core C++ Library                   │
├───────────────┬───────────────┬─────────────────┤
│  PKCE Flow    │  HTTP Client  │  State Store    │
└───────────────┴───────────────┴─────────────────┘
```

## Core Components

### Authentication Flow (PKCE Strategy)
- Implements OAuth2 PKCE extension (RFC 7636)
- Manages authorization flow state
- Handles token exchange and validation
```cpp
keycloak::auth::PKCEStrategy
keycloak::auth::ITokenService
```

### HTTP Layer
- HTTPS communication with Keycloak server
- SSL/TLS certificate handling
- Proxy support for development
- Pluggable transport architecture
```cpp
keycloak::http::HttpClient
keycloak::http::ITransport
keycloak::http::ISecureTransport
keycloak::http::IProxyAware
keycloak::http::SSLConfig
keycloak::http::ProxyConfig
```

### State Management
- Thread-safe state store interface
- Default implementation with cryptographic verification
- Mock implementation for testing
```cpp
keycloak::pkce::IStateStore    // Interface
keycloak::pkce::StateStore     // Default implementation
keycloak::test::MockStateStore // Test implementation
```
#### The state store hierarchy provides:

* Abstract interface for dependency injection
* Thread-safe default implementation
* Testable design through mocking

## Data Flow

### Authorization Flow
```plaintext
1. Client requests login
   ┌──────────┐
   │  Client  │ ────────────────────┐
   └──────────┘                     │
                                    ▼
2. Generate PKCE parameters    ┌──────────┐
   - Code verifier             │  Library │
   - Code challenge            │          │
   - State token               └────┬─────┘
                                    │
3. Redirect to Keycloak             │
   ┌──────────┐                     │
   │  Client  │ ◄───────────────────┘
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ Keycloak │
   └────┬─────┘
        │
        ▼
4. User authenticates
   ┌──────────┐
   │  Client  │ 
   └────┬─────┘
        │
        ▼
5. Callback with code           
   ┌──────────┐            ┌──────────┐
   │  Client  │ ──────────▶│  Library │
   └──────────┘            └────┬─────┘
                                │
6. Exchange code for tokens     │
   ┌──────────┐                 │
   │ Keycloak │◄────────────────┘
   └────┬─────┘
        │
        ▼
7. Return tokens
   ┌──────────┐            ┌──────────┐
   │  Client  │◄───────────│  Library │
   └──────────┘            └──────────┘
```

## HTTP Transport Architecture

The HTTP layer follows a flexible, composable design pattern:

```plaintext
┌───────────────────────────────────────────────────────┐
│                     HttpClient                        │
└───────────────────────┬───────────────────────────────┘
                        │
           ┌────────────┴───────────┐
           │                        │
           │    <<Interface>>       │
           │     ITransport         │
           │                        │
           └────────────┬───────────┘
                        │
        ┌───────────────┼────────────────┐
        │               │                │
┌───────┴──────┐ ┌──────┴──────┐ ┌───────┴──────┐
│ AsioTransport│ │   Another   │ │  Test/Mock   │
│              │ │  Transport  │ │   Transport  │
└──────┬───────┘ └─────────────┘ └──────────────┘
       │
       │ inherits
       ▼
┌───────────────────┐
│AsioSecureTransport│
└───────────────────┘
```

### Transport Interfaces

- **[ITransport](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/lib/include/keycloak/http/transport.hpp)**: Base interface for all HTTP transports
  - Common request/response handling
  - Protocol-agnostic design

- **[ISecureTransport](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/lib/include/keycloak/http/ssl_config.hpp)**: SSL/TLS capabilities extension
  - Certificate handling
  - Verification settings

- **[IProxyAware](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/lib/include/keycloak/http/proxy_config.hpp)**: Proxy support capabilities
  - Proxy configuration
  - Connection routing

### Transport Implementations

- **[AsioTransport](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/lib/src/http/transport/asio_transport.hpp)**: Base HTTP transport using ASIO library
  - Connection management
  - Request formatting
  - Response parsing

- **[AsioSecureTransport](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/lib/src/http/transport/asio_transport.hpp)**: HTTPS transport with SSL/TLS support
  - TLS handshake management
  - Certificate verification
  - Server Name Indication (SNI)

## Memory Management

### C++ Core
- RAII for resource management
- Smart pointers (std::shared_ptr, std::unique_ptr)
- Exception safety guarantees
- Factory methods for object creation

### C API Layer
- Opaque handles for C++ objects
- Error codes for status reporting
- Manual cleanup functions

## Thread Safety

### Thread-Safe Components
- StateStore (uses shared mutex)
- Configuration objects (immutable)
- HTTP client (stateless operations)
- Transport factory functions

### Non-Thread-Safe Components
- PKCE client instances
- Token service instances
- Authentication strategy instances
- Transport implementations (use per-request instances)

## Extension Points

### Strategy Pattern
```cpp
class CustomStrategy : public keycloak::auth::IAuthenticationStrategy {
    // Custom authentication implementation
};
```

### HTTP Transport Customization
```cpp
class CustomTransport : public keycloak::http::ITransport {
    // Custom transport implementation
};

class CustomSecureTransport : 
    public CustomTransport,
    public keycloak::http::ISecureTransport {
    // Custom secure transport implementation
};
```

## HTTP Client Design

The HTTP client implementation uses composition for flexibility:

```cpp
// Creating transport-specific clients
auto http_client = HttpClient::create_http_client(proxy_config);
auto https_client = HttpClient::create_https_client(ssl_config, proxy_config);

// Creating client with custom transport
auto custom_client = HttpClient::create(std::make_unique<CustomTransport>());

// Making requests
auto response = http_client->post(host, port, path, body, headers);
```

### Client Features
- Factory methods for common configurations
- Automatic transport selection based on protocol
- Support for custom transport implementations
- Clean separation between client logic and transport details

## Security Considerations

- HTTPS required for all Keycloak communication
- CSRF protection via state tokens
- PKCE challenge/verifier pairs
- Secure cookie handling
- Certificate validation
- TLS protocol version control
- SNI support for multi-tenant environments

## Configuration System

```cpp
namespace keycloak::config {
    struct LibraryConfig {
        KeycloakConfig keycloak;
        PKCEConfig pkce;
    };
    
    struct KeycloakConfig {
        // Server settings
        std::string protocol;
        std::string host;
        uint16_t port;
        std::string realm;
        std::string client_id;
        std::vector<std::string> scopes;
        
        // Security settings
        SSLConfig ssl;
    };
}

namespace keycloak::http {
    struct SSLConfig {
        bool verify_peer;
        std::string ca_cert_path;
        std::string client_cert_path;
        std::string client_key_path;
    };
    
    struct ProxyConfig {
        std::string host;
        uint16_t port;
        
        bool is_enabled() const;
    };
}
```

## Language Bindings

### C API ([kc_pkce.h](https://github.com/brakmic/keycloak-pkce-cpp/blob/main/wrappers/c/include/kc_pkce.h))
- Error handling via return codes
- Opaque handles for objects
- Thread-safety considerations
- Wrapper implementations for C++ objects

### Python Integration
- ctypes for C API access
- Pythonic wrapper classes
- Exception handling

### Lua Integration
- LuaJIT FFI for C API access
- Object-oriented wrapper
- Error handling via Lua patterns
