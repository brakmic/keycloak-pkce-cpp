# Getting Started with Keycloak PKCE Library

## Installation

### Prerequisites
- CMake (>= 3.20)
- C++ compiler with C++23 support (GCC >= 12 or Clang >= 16)
- OpenSSL development libraries
- Git

### Building from Source
```bash
# Clone the repository
git clone https://github.com/brakmic/keycloak-pkce-cpp.git
cd keycloak-pkce-cpp

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make -j$(nproc)

# Optional: Install system-wide
sudo make install
```

## Basic Usage

### C++ Example
```cpp
#include <keycloak/keycloak_client.hpp>
#include <keycloak/config/library_config.hpp>

int main() {
    // Load configuration
    auto config = keycloak::config::load_from_file("config/library_config.json");
    
    // Create PKCE client
    keycloak::KeycloakClient client(config);
    
    // Generate authorization URL
    auto auth_url = client.get_authorization_url();
    
    // Handle callback after user authentication
    auto tokens = client.handle_callback(code, state);
    
    // Validate session
    bool is_valid = client.validate_session(tokens.access_token);
}
```

### Configuration

The library requires a JSON configuration file:

```json
{
    "auth_server_url": "https://keycloak.example.com:8443",
    "realm": "your-realm",
    "client_id": "your-client-id",
    "redirect_uri": "https://your-app.com:8080/callback",
    "ssl": {
        "verify_peer": true,
        "ca_cert": "/path/to/ca.pem"
    },
    "proxy": {
        "host": "proxy.local",
        "port": 8080
    }
}
```

### Quick Start Examples

#### 1. Basic Web Application
```cpp
#include <keycloak/keycloak_client.hpp>
#include <http_server.hpp>  // Your preferred HTTP server library

void handle_login(HttpRequest& req, HttpResponse& res) {
    auto auth_url = pkce_client.get_authorization_url();
    res.redirect(auth_url);
}

void handle_callback(HttpRequest& req, HttpResponse& res) {
    auto code = req.get_param("code");
    auto state = req.get_param("state");
    
    auto tokens = pkce_client.handle_callback(code, state);
    if (tokens) {
        res.set_cookie("session", tokens.access_token);
        res.redirect("/dashboard");
    }
}
```

#### 2. Protected Resource
```cpp
void handle_protected_resource(HttpRequest& req, HttpResponse& res) {
    auto session = req.get_cookie("session");
    if (!session || !pkce_client.validate_session(session)) {
        res.redirect("/login");
        return;
    }
    
    // Serve protected content
    res.send("Protected resource content");
}
```

## Language Bindings

The library provides C API bindings which are used to create Python and Lua integrations. See the respective integration guides for detailed usage:

- [C API Integration Guide](./c_integration.md)
- [Python Integration Guide](./python_integration.md)
- [Lua Integration Guide](./lua_integration.md)

## Next Steps

- Review the [Core Components](./core_components.md) documentation
- Check out the [Examples](../examples) directory
- Read about [Security Considerations](./security.md)
- Learn about [Advanced Configuration](./advanced_config.md)
