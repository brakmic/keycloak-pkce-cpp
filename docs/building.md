# Building from Source

## Prerequisites

### Required Tools
- CMake (>= 3.18)
- C++ compiler with C++23 support (GCC >= 12 or Clang >= 16)
- OpenSSL development libraries
- pkg-config

### Optional Dependencies
- LuaJIT for Lua bindings
- Python 3.8+ for Python bindings

## Directory Structure

```plaintext
keycloak-pkce/
├── CMakeLists.txt           # Main CMake configuration
├── lib/                     # Core C++ library
├── wrappers/
│   ├── c/                   # C API wrapper
│   ├── lua/                 # Lua bindings
│   └── python/              # Python bindings
├── config/                  # Configuration templates
├── certs/                   # SSL certificates
└── scripts/                 # Build and utility scripts
```

## Basic Build

```bash
# Create and enter build directory
mkdir build && cd build

# Configure project
cmake ..

# Build all targets
make -j$(nproc)
```

## Build Options

CMake options can be configured using `-D` flags:

```bash
cmake -DCMAKE_BUILD_TYPE=Release \  # Build type (Debug/Release/RelWithDebInfo/MinSizeRel)
      -DCMAKE_INSTALL_PREFIX=/usr \ # Installation prefix
      ..
```

### Available Build Types
- `Debug`: Includes debug symbols and sanitizers
- `Release`: Optimized build (-O2)
- `RelWithDebInfo`: Optimized with debug info
- `MinSizeRel`: Size-optimized (-Os)

## Component-Specific Setup

### C Example Setup
```bash
# Run setup script for C environment
./scripts/setup_c_env.sh

# This will:
# - Generate SSL certificates
# - Create CivetWeb configuration
# - Set up logging directories
# - Create default library configuration
```

### Python Setup
```bash
# Python environment is set up automatically during build
# Run Python example
cd build/python
python3 standalone.py
```

### Lua Setup
```bash
# Generate Lua HTTP server certificates
./scripts/gen_lua_http_certs.sh

# Run Lua example
./scripts/run_lua_script.sh build/lua/standalone.lua
```

## Lua Integration with OpenResty

In addition to the standalone Lua server, the library can be used with OpenResty, an Nginx distribution with Lua support.

### OpenResty Requirements
```bash
# Required packages
sudo apt-get install openresty
sudo luarocks install lua-cjson    # JSON handling
sudo luarocks install lua-resty-http  # HTTP client

# Optional but recommended for development
sudo luarocks install lua-resty-jwt  # JWT token handling
```

### Running the OpenResty Example
```bash
# First, ensure no existing nginx processes are running
./scripts/kill_nginx.sh

# Start OpenResty with our config
openresty -p . -c wrappers/lua/nginx.conf

# Access the demo at:
# https://pkce-client.local.com:18080
```

The [OpenResty integration](./lua_openresty.md) provides better performance and scalability through Nginx's event-driven architecture. See `wrappers/lua/nginx.conf` for the complete implementation.

## Build Artifacts

After successful build, you'll find:

```plaintext
build/
├── libkeycloak_pkce.so    # Core C++ library
├── libkc_pkce.so          # C wrapper library
├── pkce_demo_c            # C example executable
├── lua/                   # Lua binding files
│   ├── keycloak_pkce.lua
│   └── standalone.lua
└── python/               # Python binding files
    ├── keycloak_pkce.py
    └── standalone.py
```

## SSL Certificates

The build system generates different certificate sets for each binding:
- C API: `certs/client/pkce-client.pem`
- Lua: `certs/client/lua_http_server.pem`
- Python: `certs/client/pkce-client.py.pem`

## Configuration Files

Each binding has its own configuration files in the build directory:
```plaintext
build/
├── config/
│   ├── library_config.json  # Core library configuration
│   └── civetweb.conf        # C example web server config
├── lua/config/             # Lua-specific configs
└── python/config/          # Python-specific configs
```

## Troubleshooting

### Common Issues

1. Missing SSL certificates
```bash
# Regenerate certificates
./scripts/gen_lua_http_certs.sh  # For Lua
./scripts/setup_c_env.sh         # For C example
```

2. Nginx process conflicts
```bash
# Kill existing nginx processes
./scripts/kill_nginx.sh
```

3. Library load errors
```bash
# Set library path
export LD_LIBRARY_PATH="build:$LD_LIBRARY_PATH"
```

### Debug Build
For detailed debugging:
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```
Debug builds include:
- Address Sanitizer
- Undefined Behavior Sanitizer
- Full debug symbols
- No optimization (-O0)
