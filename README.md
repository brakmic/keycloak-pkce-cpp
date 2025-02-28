# Keycloak PKCE Authentication Library

## Overview
A C++ library implementing OAuth2 PKCE (Proof Key for Code Exchange) authentication flow for secure client-side authentication with Keycloak servers.

## Key Features
- Full OAuth2 PKCE flow implementation
- TLS/SSL support with certificate management
- Cookie-based session handling
- State management for CSRF protection
- Proxy support for development environments
- Thread-safe operations
- Comprehensive error handling

## Language Support
- Core implementation in modern C++ (C++23)
- C API wrapper for language interoperability (C99)
- Language bindings available for:
  - Python (via ctypes)
  - Lua (via LuaJIT FFI)

## Index

### 1. Integration Guides
- [C API Usage](./docs/c_integration.md)
- [Python Integration](./docs/python_integration.md)
- [Lua Integration](./docs/lua_integration.md)
- [Web Server Integration Examples](./wrappers/)

### 4. Technical Documentation
- [Architecture Overview](./docs/architecture.md)
- Security Considerations
- API Reference
- Configuration Reference
- Error Handling

### 5. Development
- [Building from Source](./docs/building.md)
- [Running Tests](./docs/testing.md)
- Contributing Guidelines
- Code Style Guide
