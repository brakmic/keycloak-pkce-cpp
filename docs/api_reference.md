# Keycloak PKCE API Reference

## Overview

This document provides a comprehensive reference for all APIs in the Keycloak PKCE library:

1. **Core C++ API**: The foundation library implementing OAuth2 PKCE authentication
2. **C API**: A language-agnostic wrapper providing access to the library from C and other languages
3. **Language Bindings**: Notes on Python and Lua integration points

## API Hierarchies

```plaintext
┌─────────────────────────────────────────────────┐
│                Language Bindings                │
│   ┌───────────────────┐  ┌───────────────────┐  │
│   │      Python       │  │        Lua        │  │
│   │    (via ctypes)   │  │   (via LuaJIT)    │  │
│   └─────────┬─────────┘  └─────────┬─────────┘  │
└─────────────┼──────────────────────┼────────────┘
              │                      │
┌─────────────┼──────────────────────┼────────────┐
│             │                      │            │
│             ▼                      ▼            │
│       ┌──────────────────────────────────┐      │
│       │             C API                │      │
│       │          (kc_pkce.h)             │      │
│       └─────────────────┬────────────────┘      │
│                         │                       │
│                         ▼                       │
│       ┌──────────────────────────────────┐      │
│       │         Core C++ Library         │      │
│       └──────────────────────────────────┘      │
│                                                 │
└─────────────────────────────────────────────────┘
```

## 1. Core C++ API

### 1.1 Authentication

#### 1.1.1 `keycloak::auth::IAuthenticationStrategy`

Base interface for authentication strategies.

**Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `create_authorization_url()` | Generates OAuth2 authorization URL with PKCE parameters | None | `std::string` |
| `handle_callback(code, state)` | Processes OAuth2 callback and exchanges code for tokens | `std::string_view code, std::string_view state` | `TokenResponse` |
| `validate_session(cookies)` | Checks if current session cookies are valid | `const std::unordered_map<std::string, std::string>& cookies` | `bool` |
| `get_cookie_config()` | Retrieves cookie configuration | None | `const config::CookieConfig&` |

#### 1.1.2 `keycloak::auth::PKCEStrategy`

Concrete implementation of PKCE authentication flow.

**Factory Method:**
```cpp
static std::unique_ptr<PKCEStrategy> create(
    std::shared_ptr<ITokenService> token_service,
    std::string_view client_id,
    std::string_view redirect_uri,
    const config::PKCEConfig& pkce_config,
    std::unique_ptr<pkce::IStateStore> state_store = nullptr)
```

### 1.2 HTTP Layer

#### 1.2.1 `keycloak::http::HttpClient`

Client for making HTTP/HTTPS requests.

**Factory Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `create(transport)` | Create client with custom transport | `std::unique_ptr<ITransport> transport` | `std::shared_ptr<HttpClient>` |
| `create_https_client(ssl_config, proxy_config)` | Create HTTPS client | `const SSLConfig& ssl_config, const ProxyConfig& proxy_config` | `std::shared_ptr<HttpClient>` |
| `create_http_client(proxy_config)` | Create HTTP client | `const ProxyConfig& proxy_config` | `std::shared_ptr<HttpClient>` |

**Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `post(host, port, path, body, headers)` | Send POST request | `std::string_view host, std::string_view port, std::string_view path, std::string_view body, const std::unordered_map<std::string, std::string>& headers` | `Response` |
| `get_transport()` | Get underlying transport | None | `std::shared_ptr<ITransport>` |

#### 1.2.2 Transport Interfaces

```cpp
class ITransport
class ISecureTransport : virtual public ITransport
class IProxyAware : virtual public ITransport
```

### 1.3 Token Service

#### 1.3.1 `keycloak::auth::ITokenService`

Interface for OAuth2 token operations.

**Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `get_authorization_endpoint()` | Get Keycloak authorization URL | None | `std::string` |
| `exchange_code(code, code_verifier, redirect_uri, client_id)` | Exchange code for tokens | `std::string_view code, std::string_view code_verifier, std::string_view redirect_uri, std::string_view client_id` | `TokenResponse` |
| `get_scopes()` | Get OAuth2 scopes | None | `const std::vector<std::string>&` |

### 1.4 Keycloak Client

#### 1.4.1 `keycloak::KeycloakClient`

Main client for Keycloak server communication.

**Factory Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `create(config, proxy_config, logger)` | Create Keycloak client | `const config::KeycloakConfig& config, const http::ProxyConfig& proxy_config, LogCallback logger` | `std::shared_ptr<KeycloakClient>` |
| `create_pkce_strategy(config, proxy_config, redirect_uri, logger)` | Create PKCE strategy | `const config::LibraryConfig& config, const http::ProxyConfig& proxy_config, std::string_view redirect_uri, LogCallback logger` | `std::shared_ptr<auth::IAuthenticationStrategy>` |

### 1.5 State Management

#### 1.5.1 `keycloak::pkce::IStateStore`

Interface for PKCE state management.

**Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `create(code_verifier)` | Create new state entry | `std::string_view code_verifier` | `std::string` |
| `verify(state)` | Verify and retrieve code verifier | `std::string_view state` | `std::string` |

#### 1.5.2 `keycloak::pkce::StateStore`

Default implementation of state management.

**Constructor:**
```cpp
explicit StateStore(const config::StateStoreConfig& config)
```

### 1.6 PKCE Cryptography

#### 1.6.1 `keycloak::pkce::generate_pkce_pair()`

Generates PKCE code verifier and challenge.

**Return Type:** `PkcePair` (code_verifier, code_challenge)

## 2. C API Reference

### 2.1 Common Definitions

#### 2.1.1 Opaque Handles

```c
typedef struct kc_pkce_context_s* kc_pkce_handle_t;
typedef struct kc_pkce_config_s* kc_pkce_config_t;
```

#### 2.1.2 Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `KC_PKCE_SUCCESS` | Operation successful |
| -1 | `KC_PKCE_ERROR_INVALID_HANDLE` | Invalid handle provided |
| -2 | `KC_PKCE_ERROR_INVALID_ARGUMENT` | Invalid argument provided |
| -3 | `KC_PKCE_ERROR_ALLOCATION` | Memory allocation failure |
| -4 | `KC_PKCE_ERROR_NETWORK` | Network communication error |
| -5 | `KC_PKCE_ERROR_SSL` | SSL/TLS error |
| -6 | `KC_PKCE_ERROR_AUTH` | Authentication error |
| -7 | `KC_PKCE_ERROR_CONFIG` | Configuration error |
| -8 | `KC_PKCE_ERROR_INVALID_STATE` | Invalid state parameter |
| -9 | `KC_PKCE_ERROR_BUFFER_TOO_SMALL` | Buffer too small for output |
| -10 | `KC_PKCE_ERROR_VALIDATION` | Validation error |
| -11 | `KC_PKCE_ERROR_INITIALIZATION` | Initialization error |

### 2.2 Configuration Management

#### 2.2.1 Configuration Structures

```c
typedef struct {
    const char* protocol;    
    const char* host;    
    uint16_t port;    
    const char* realm;    
    const char* client_id;    
    const char** scopes;    
    size_t scope_count;
} kc_pkce_keycloak_config_t;

typedef struct {
    bool verify_peer;    
    const char* ca_cert_path;
} kc_pkce_ssl_config_t;

typedef struct {
    const char* host;    
    uint16_t port;
} kc_pkce_proxy_config_t;
```

#### 2.2.2 Configuration Functions

| Function | Description | Parameters | Return Type |
|----------|-------------|------------|-------------|
| `kc_pkce_config_create` | Create configuration | `kc_pkce_config_t* config` | `kc_pkce_error_t` |
| `kc_pkce_config_load_file` | Load config from file | `kc_pkce_config_t config, const char* path` | `kc_pkce_error_t` |
| `kc_pkce_config_destroy` | Destroy configuration | `kc_pkce_config_t config` | `void` |
| `kc_pkce_set_keycloak_config` | Set Keycloak settings | `kc_pkce_config_t config, const kc_pkce_keycloak_config_t* kc_config` | `kc_pkce_error_t` |
| `kc_pkce_set_ssl_config` | Set SSL settings | `kc_pkce_config_t config, const kc_pkce_ssl_config_t* ssl_config` | `kc_pkce_error_t` |
| `kc_pkce_set_proxy_config` | Set proxy settings | `const kc_pkce_proxy_config_t* proxy_config` | `kc_pkce_error_t` |

### 2.3 PKCE Authentication

#### 2.3.1 Authentication Structures

```c
typedef struct {
    char* access_token;    
    char* refresh_token;    
    char* id_token;    
    char* token_type;    
    uint64_t expires_in;    
    char* error;    
    char* error_description;
} kc_pkce_token_info_t;

typedef struct {
    const char* name;    
    const char* value;
} kc_pkce_cookie_t;
```

#### 2.3.2 Authentication Functions

| Function | Description | Parameters | Return Type |
|----------|-------------|------------|-------------|
| `kc_pkce_create` | Create PKCE client | `kc_pkce_handle_t* handle, const kc_pkce_config_t config` | `kc_pkce_error_t` |
| `kc_pkce_destroy` | Destroy PKCE client | `kc_pkce_handle_t handle` | `void` |
| `kc_pkce_set_redirect_uri` | Set redirect URI | `kc_pkce_handle_t handle, const char* redirect_uri` | `kc_pkce_error_t` |
| `kc_pkce_create_auth_url` | Generate auth URL | `kc_pkce_handle_t handle, char* url_buffer, size_t buffer_size` | `kc_pkce_error_t` |
| `kc_pkce_handle_callback` | Handle OAuth callback | `kc_pkce_handle_t handle, const char* code, const char* state, kc_pkce_token_info_t* token_info` | `kc_pkce_error_t` |
| `kc_pkce_validate_session` | Validate session | `kc_pkce_handle_t handle, const char* access_token` | `bool` |
| `kc_pkce_free_token_info` | Free token resources | `kc_pkce_token_info_t* token_info` | `void` |

## 3. Language Bindings

### 3.1 Python Integration

The Python binding uses `ctypes` to interact with the C API. Key components:

#### 3.1.1 Module Structure

```python
from ctypes import *

# Load shared library
_lib = cdll.LoadLibrary('libkc_pkce.so')

class KeycloakPKCE:
    """Python wrapper for Keycloak PKCE authentication"""
    
    def __init__(self, config_path=None):
        """Initialize with optional config path"""
        # Implementation details...
    
    def create_auth_url(self):
        """Generate authorization URL for PKCE flow"""
        # Implementation details...
    
    def handle_callback(self, code, state):
        """Handle OAuth callback with code and state"""
        # Implementation details...
```

### 3.2 Lua Integration

The Lua binding uses LuaJIT FFI to interface with the C API:

```lua
local ffi = require("ffi")

-- Load the shared library
local kc_pkce = ffi.load("libkc_pkce")

-- Define C API structures and functions
ffi.cdef[[
    typedef struct kc_pkce_context_s* kc_pkce_handle_t;
    typedef struct kc_pkce_config_s* kc_pkce_config_t;
    
    // Error codes and other type definitions
    // Function declarations
]]

-- Create Lua wrapper object
local KeycloakPKCE = {}
KeycloakPKCE.__index = KeycloakPKCE

function KeycloakPKCE.new(config_path)
    -- Implementation details
end

function KeycloakPKCE:create_auth_url()
    -- Implementation details
end

function KeycloakPKCE:handle_callback(code, state)
    -- Implementation details
end
```

## 4. Configuration Structures

### 4.1 C++ Configuration

```cpp
struct KeycloakConfig {
    std::string protocol;
    std::string host;
    uint16_t port;
    std::string realm;
    std::string client_id;
    std::vector<std::string> scopes;
    SSLConfig ssl;
};

struct PKCEConfig {
    StateStoreConfig state_store;
    CookieConfig cookies;
};

struct LibraryConfig {
    KeycloakConfig keycloak;
    PKCEConfig pkce;
};
```

### 4.2 C Configuration

Corresponding C structures that map to the C++ configuration:

```c
typedef struct {
    const char* protocol;
    const char* host;
    uint16_t port;
    const char* realm;
    const char* client_id;
    const char** scopes;
    size_t scope_count;
} kc_pkce_keycloak_config_t;

typedef struct {
    bool verify_peer;
    const char* ca_cert_path;
} kc_pkce_ssl_config_t;
```

## 5. Error Handling

### 5.1 C++ Error Handling

The C++ API uses exceptions for error handling:

| Exception Type | Use Case |
|----------------|----------|
| `std::invalid_argument` | Invalid parameters |
| `std::runtime_error` | Runtime failures |
| `std::bad_alloc` | Memory allocation errors |

### 5.2 C API Error Handling

The C API uses error codes returned by functions:

```c
const char* kc_pkce_get_error_message(kc_pkce_error_t error);
```

## 6. API Versioning

The library follows semantic versioning:

- **Major version**: Incompatible API changes
- **Minor version**: Backward-compatible additions
- **Patch version**: Backward-compatible fixes

## 7. Thread Safety

| Component | Thread Safety |
|-----------|--------------|
| `HttpClient` | Thread-safe for different instances |
| `StateStore` | Fully thread-safe |
| `PKCEStrategy` | Not thread-safe |
| C API functions | Thread-safe except for global state |
```
