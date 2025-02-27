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
```cpp
keycloak::http::HttpClient
keycloak::http::SSLConfig
keycloak::http::ProxyConfig
```

### State Management
- Thread-safe state store
- CSRF protection
- PKCE code verifier management
```cpp
keycloak::pkce::StateStore
```

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

## Memory Management

### C++ Core
- RAII for resource management
- Smart pointers (std::shared_ptr, std::unique_ptr)
- Exception safety guarantees

### C API Layer
- Opaque handles for C++ objects
- Error codes for status reporting
- Manual cleanup functions

## Thread Safety

### Thread-Safe Components
- StateStore (uses shared mutex)
- Configuration objects (immutable)
- HTTP client (stateless operations)

### Non-Thread-Safe Components
- PKCE client instances
- Token service instances
- Authentication strategy instances

## Extension Points

### Strategy Pattern
```cpp
class CustomStrategy : public keycloak::auth::IAuthenticationStrategy {
    // Custom authentication implementation
};
```

### HTTP Client Customization
```cpp
class CustomHttpClient {
    // Custom HTTP implementation using the defined interfaces
};
```

## Security Considerations

- HTTPS required for all Keycloak communication
- CSRF protection via state tokens
- PKCE challenge/verifier pairs
- Secure cookie handling
- Certificate validation

## Configuration System

```cpp
namespace keycloak::config {
    struct LibraryConfig {
        KeycloakConfig keycloak;
        PKCEConfig pkce;
        SSLConfig ssl;
        ProxyConfig proxy;
    };
}
```

## Language Bindings

### C API (kc_pkce.h)
- Error handling via return codes
- Opaque handles for objects
- Thread-safety considerations

### Python Integration
- ctypes for C API access
- Pythonic wrapper classes
- Exception handling

### Lua Integration
- LuaJIT FFI for C API access
- Object-oriented wrapper
- Error handling via Lua patterns
