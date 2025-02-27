# C API Integration Guide

## Overview

The C API provides a platform-independent interface to the C++ Keycloak PKCE library. It's designed for:
- Direct use in C applications
- Integration with other languages via FFI
- Maximum portability and ABI stability

## Header File

```c
#include <kc_pkce.h>
```

## Core Types

```c
typedef struct kc_pkce_t* kc_pkce_handle_t;
typedef struct kc_pkce_config_t* kc_pkce_config_handle_t;

typedef struct {
    const char* access_token;
    const char* refresh_token;
    const char* id_token;
} kc_pkce_token_info_t;

typedef enum {
    KC_PKCE_SUCCESS = 0,
    KC_PKCE_ERROR_INVALID_HANDLE,
    KC_PKCE_ERROR_INVALID_ARGUMENT,
    KC_PKCE_ERROR_NETWORK,
    KC_PKCE_ERROR_SERVER,
    KC_PKCE_ERROR_STATE_INVALID,
    KC_PKCE_ERROR_CONFIG
} kc_pkce_error_t;
```

## Configuration API

```c
// Load configuration from JSON file
kc_pkce_error_t kc_pkce_config_load(
    const char* config_path,
    kc_pkce_config_handle_t* config
);

// Free configuration resources
void kc_pkce_config_destroy(kc_pkce_config_handle_t config);
```

## Core Functions

```c
// Create PKCE instance
kc_pkce_error_t kc_pkce_create(
    kc_pkce_handle_t* handle,
    kc_pkce_config_handle_t config
);

// Get authorization URL
kc_pkce_error_t kc_pkce_get_auth_url(
    kc_pkce_handle_t handle,
    const char** url
);

// Handle OAuth callback
kc_pkce_error_t kc_pkce_handle_callback(
    kc_pkce_handle_t handle,
    const char* code,
    const char* state,
    kc_pkce_token_info_t* token_info
);

// Validate session token
kc_pkce_error_t kc_pkce_validate_session(
    kc_pkce_handle_t handle,
    const char* token,
    bool* is_valid
);

// Cleanup resources
void kc_pkce_destroy(kc_pkce_handle_t handle);
```

## Basic Usage Example

```c
#include <kc_pkce.h>
#include <stdio.h>

int main() {
    kc_pkce_config_handle_t config = NULL;
    kc_pkce_handle_t pkce = NULL;
    kc_pkce_error_t err;

    // Load configuration
    err = kc_pkce_config_load("config/library_config.json", &config);
    if (err != KC_PKCE_SUCCESS) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }

    // Create PKCE instance
    err = kc_pkce_create(&pkce, config);
    if (err != KC_PKCE_SUCCESS) {
        fprintf(stderr, "Failed to create PKCE instance\n");
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Get authorization URL
    const char* auth_url = NULL;
    err = kc_pkce_get_auth_url(pkce, &auth_url);
    if (err == KC_PKCE_SUCCESS) {
        printf("Authorization URL: %s\n", auth_url);
    }

    // Cleanup
    kc_pkce_destroy(pkce);
    kc_pkce_config_destroy(config);
    return 0;
}
```

## Error Handling

- Functions return `kc_pkce_error_t` to indicate success/failure
- String outputs are owned by the library
- NULL handle checks are performed internally
- Resources must be freed in reverse order of creation

## Memory Management

- All string returns are managed by the library
- Do not free strings returned by the API
- Always call destroy functions for handles
- Handles must be initialized to NULL

## Thread Safety

- Configuration objects are thread-safe
- PKCE handles are not thread-safe
- Each thread should create its own PKCE instance
- No global state is maintained

## Building

```bash
# Compile with C API
gcc your_app.c -lkc_pkce -o your_app
```