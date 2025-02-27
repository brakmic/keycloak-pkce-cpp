/**
 * @file kc_pkce.h
 * @brief C API Wrapper for Keycloak PKCE Authentication Library
 * @version 1.0
 * 
 * Provides a C-compatible interface to the Keycloak PKCE C++ library.
 * Implements OAuth2 PKCE (RFC 7636) authentication flow with features:
 * - Configuration management
 * - HTTPS communication
 * - Token handling
 * - Session validation
 * - Cookie management
 * - Error handling
 */

#ifndef KC_PKCE_H
#define KC_PKCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Export macro for different platforms
#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef KC_PKCE_EXPORTS
        #define KC_PKCE_API __declspec(dllexport)
    #else
        #define KC_PKCE_API __declspec(dllimport)
    #endif
#else
    #define KC_PKCE_API __attribute__((visibility("default")))
#endif

/**
 * @brief Opaque handle to PKCE context
 * Wraps C++ PKCEStrategy instance
 */
typedef struct kc_pkce_context_s* kc_pkce_handle_t;

/**
 * @brief Opaque handle to configuration
 * Wraps C++ LibraryConfig instance
 */
typedef struct kc_pkce_config_s* kc_pkce_config_t;

/**
 * @enum kc_pkce_error_t
 * @brief Error codes for PKCE operations
 */
typedef enum {
    KC_PKCE_SUCCESS = 0,                    ///< Operation completed successfully
    KC_PKCE_ERROR_INVALID_HANDLE = -1,      ///< Invalid or NULL handle provided
    KC_PKCE_ERROR_INVALID_ARGUMENT = -2,    ///< Invalid function argument
    KC_PKCE_ERROR_ALLOCATION = -3,          ///< Memory allocation failure
    KC_PKCE_ERROR_NETWORK = -4,             ///< Network communication error
    KC_PKCE_ERROR_SSL = -5,                 ///< SSL/TLS error
    KC_PKCE_ERROR_AUTH = -6,                ///< Authentication error
    KC_PKCE_ERROR_CONFIG = -7,              ///< Configuration error
    KC_PKCE_ERROR_INVALID_STATE = -8,       ///< Invalid PKCE state
    KC_PKCE_ERROR_BUFFER_TOO_SMALL = -9,    ///< Output buffer too small
    KC_PKCE_ERROR_VALIDATION = -10,         ///< Validation failure
    KC_PKCE_ERROR_INITIALIZATION = -11      ///< Initialization error
} kc_pkce_error_t;

/**
 * @struct kc_pkce_keycloak_config_t
 * @brief Keycloak server configuration
 * Maps to C++ KeycloakConfig
 */
typedef struct {
    const char* protocol;     ///< Connection protocol (http/https)
    const char* host;         ///< Keycloak server hostname
    uint16_t port;            ///< Server port
    const char* realm;        ///< Keycloak realm name
    const char* client_id;    ///< OAuth2 client identifier
    const char** scopes;      ///< Array of OAuth2 scopes
    size_t scope_count;       ///< Number of scopes
} kc_pkce_keycloak_config_t;

/**
 * @struct kc_pkce_ssl_config_t
 * @brief SSL/TLS configuration
 * Maps to C++ SSLConfig
 */
typedef struct {
    bool verify_peer;         ///< Enable peer certificate verification
    const char* ca_cert_path; ///< Path to CA certificate file
} kc_pkce_ssl_config_t;

/**
 * @struct kc_pkce_proxy_config_t
 * @brief HTTP proxy configuration
 * Maps to C++ ProxyConfig
 */
typedef struct {
    const char* host;         ///< Proxy server hostname
    uint16_t port;            ///< Proxy server port
} kc_pkce_proxy_config_t;

/**
 * @struct kc_pkce_token_info_t
 * @brief OAuth2 token response
 * Maps to C++ TokenResponse
 */
typedef struct {
    char* access_token;       ///< OAuth2 access token
    char* refresh_token;      ///< Refresh token for obtaining new access tokens
    char* id_token;           ///< OpenID Connect ID token
    char* token_type;         ///< Token type (usually "Bearer")
    uint64_t expires_in;      ///< Access token validity period in seconds
    char* error;              ///< OAuth2 error code
    char* error_description;  ///< Human-readable error description
} kc_pkce_token_info_t;

/**
 * @struct kc_pkce_cookie_t
 * @brief Cookie management structure
 * Maps to C++ CookieConfig attributes
 */
typedef struct {
    const char* name;         ///< Cookie name
    const char* value;        ///< Cookie value
} kc_pkce_cookie_t;

// Configuration API Functions

/**
 * @brief Creates a new configuration instance
 * @param[out] config Pointer to receive configuration handle
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Creates an empty configuration container that can be populated
 * through subsequent API calls or configuration file loading.
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_config_create(
    kc_pkce_config_t* config);

/**
 * @brief Loads configuration from JSON file
 * @param[in] config Configuration handle
 * @param[in] path Path to JSON configuration file
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Expected JSON structure matches C++ library configuration format
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_config_load_file(
    kc_pkce_config_t config, const char* path);

/**
 * @brief Destroys configuration instance
 * @param[in] config Configuration to destroy
 * 
 * Frees all resources associated with configuration:
 * - Keycloak settings
 * - SSL configuration
 * - Scopes
 */
KC_PKCE_API void 
kc_pkce_config_destroy(
    kc_pkce_config_t config);

    /**
 * @brief Sets Keycloak server configuration
 * @param[in] config Configuration handle
 * @param[in] kc_config Keycloak server settings
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Required fields:
 * - host
 * - realm
 * - client_id
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_keycloak_config(
    kc_pkce_config_t config, 
    const kc_pkce_keycloak_config_t* kc_config);

/**
 * @brief Sets SSL/TLS configuration
 * @param[in] config Configuration handle
 * @param[in] ssl_config SSL settings
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_ssl_config(
    kc_pkce_config_t config, 
    const kc_pkce_ssl_config_t* ssl_config);

/**
 * @brief Sets global proxy configuration
 * @param[in] proxy_config Proxy settings
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Affects all subsequent HTTP(S) connections
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_proxy_config(
    const kc_pkce_proxy_config_t* proxy_config);

/**
 * @brief Retrieves configured OAuth2 scopes
 * @param[in] config Configuration handle
 * @param[out] scopes Pointer to receive scope array
 * @param[out] scope_count Number of scopes
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Caller must free returned scope array using kc_pkce_free_scopes
 */
KC_PKCE_API kc_pkce_error_t
kc_pkce_get_scopes(
    kc_pkce_config_t config,
    const char*** scopes,
    size_t* scope_count);

/**
 * @brief Frees scope array from kc_pkce_get_scopes
 * @param[in] scopes Scope array to free
 * @param[in] scope_count Number of scopes
 */
KC_PKCE_API void
kc_pkce_free_scopes(
    const char** scopes,
    size_t scope_count);

// Core API Functions

/**
 * @brief Creates PKCE authentication instance
 * @param[out] handle Pointer to receive PKCE handle
 * @param[in] config Validated configuration
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * @throws KC_PKCE_ERROR_INVALID_ARGUMENT if parameters are null
 * @throws KC_PKCE_ERROR_CONFIG if configuration is invalid
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_create(
    kc_pkce_handle_t* handle, 
    const kc_pkce_config_t config);

/**
 * @brief Destroys PKCE instance
 * @param[in] handle PKCE instance to destroy
 * 
 * Cleans up all resources associated with PKCE instance:
 * - Configuration
 * - State store
 * - Tokens
 * - Cookies
 */
KC_PKCE_API void 
kc_pkce_destroy(
    kc_pkce_handle_t handle);

// Authentication API Functions

/**
 * @brief Generates authorization URL with PKCE parameters
 * @param[in] handle PKCE instance handle
 * @param[out] url_buffer Buffer to receive URL
 * @param[in] buffer_size Size of url_buffer
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * @throws KC_PKCE_ERROR_BUFFER_TOO_SMALL if buffer is insufficient
 * 
 * URL includes:
 * - OAuth2 parameters
 * - PKCE code challenge
 * - State parameter
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_create_auth_url(
    kc_pkce_handle_t handle,
    char* url_buffer,
    size_t buffer_size);

/**
 * @brief Sets OAuth2 redirect URI
 * @param[in] handle PKCE instance handle
 * @param[in] redirect_uri OAuth2 callback URL
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Must match redirect URI registered with Keycloak
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_redirect_uri(
    kc_pkce_handle_t handle,
    const char* redirect_uri);

/**
 * @brief Handles OAuth2/PKCE callback
 * @param[in] handle PKCE instance handle
 * @param[in] code Authorization code from Keycloak
 * @param[in] state State parameter for validation
 * @param[out] token_info Structure to receive tokens
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Performs:
 * - State validation
 * - Code exchange
 * - Token validation
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_handle_callback(
    kc_pkce_handle_t handle,
    const char* code,
    const char* state,
    kc_pkce_token_info_t* token_info);

/**
 * @brief Validates session token
 * @param[in] handle PKCE instance handle
 * @param[in] access_token Access token to validate
 * @return true if token is valid, false otherwise
 * 
 * Checks:
 * - Token format and signature
 * - Token expiration
 * - Token claims
 */
KC_PKCE_API bool 
kc_pkce_validate_session(
    kc_pkce_handle_t handle,
    const char* access_token);

// Cookie Management API functions

/**
 * @brief Sets single cookie value
 * @param[in] handle PKCE instance handle
 * @param[in] name Cookie name
 * @param[in] value Cookie value
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Used for individual cookie management during authentication flow
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_cookie(
    kc_pkce_handle_t handle,
    const char* name,
    const char* value);

/**
 * @brief Sets multiple cookies at once
 * @param[in] handle PKCE instance handle
 * @param[in] cookies Array of cookie structures
 * @param[in] cookie_count Number of cookies in array
 * @return KC_PKCE_SUCCESS on success, error code otherwise
 * 
 * Batch operation for setting multiple authentication cookies
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_cookies(
    kc_pkce_handle_t handle,
    const kc_pkce_cookie_t* cookies,
    size_t cookie_count);

// Configuration Validation API functions

/**
 * @brief Validates configuration completeness
 * @param[in] config Configuration handle to validate
 * @return KC_PKCE_SUCCESS if valid, error code otherwise
 * 
 * Validates:
 * - Required fields presence
 * - Field value correctness
 * - Configuration consistency
 */
KC_PKCE_API kc_pkce_error_t 
kc_pkce_validate_config(
    kc_pkce_config_t config);

// Memory management API functions

/**
 * @brief Frees token information structure
 * @param[in] token_info Token structure to free
 * 
 * Properly deallocates all memory associated with token_info:
 * - access_token
 * - refresh_token
 * - id_token
 * - token_type
 * - error fields
 */
KC_PKCE_API void 
kc_pkce_free_token_info(
    kc_pkce_token_info_t* token_info);

// Error handling API functions

/**
 * @brief Retrieves error message for error code
 * @param[in] error Error code to translate
 * @return Human-readable error message
 * 
 * Thread-safe, returns static string, do not free
 */
KC_PKCE_API const char* 
kc_pkce_get_error_message(
    kc_pkce_error_t error);

#ifdef __cplusplus
}
#endif

#endif // KC_PKCE_H
