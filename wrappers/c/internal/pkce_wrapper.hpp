/**
 * @file pkce_wrapper.hpp
 * @brief PKCE Authentication Wrapper for C API
 * @version 1.0
 * 
 * Provides C++-side implementation of PKCE authentication flow for C API.
 * Manages authentication state, token handling, and cookie management
 * while providing a clean C interface.
 */

#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include "keycloak/types.hpp"
#include "keycloak/auth/pkce_strategy.hpp"
#include "keycloak/auth/token_service.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/config/library_config.hpp"
#include "keycloak/http/proxy_config.hpp"

namespace keycloak::c_api {

/**
 * @class PKCEWrapper
 * @brief Wraps C++ PKCE authentication for C API use
 * 
 * Responsibilities:
 * - PKCE flow management
 * - Token handling
 * - Cookie management
 * - Session validation
 * - Proxy configuration
 */
class PKCEWrapper {
public:
    /**
     * @brief Creates new PKCE wrapper instance
     * @param config Library configuration
     * @throws std::runtime_error if initialization fails
     * 
     * Initializes:
     * - Keycloak client
     * - PKCE strategy
     * - Cookie storage
     */
    explicit PKCEWrapper(const config::LibraryConfig& config);
    
    /**
     * @brief Sets OAuth2 redirect URI
     * @param uri Callback URL for OAuth2 flow
     * @throws std::invalid_argument if URI is empty
     */
    void set_redirect_uri(const std::string& uri);

    /**
     * @brief Validates authentication session
     * @param access_token Access token to validate
     * @return true if session is valid, false otherwise
     * 
     * Checks:
     * - Token format
     * - Token signature
     * - Token expiration
     */
    bool validate_session(const std::string& access_token);

    /**
     * @brief Creates OAuth2 authorization URL with PKCE
     * @return Complete authorization URL
     * @throws std::runtime_error if URL generation fails
     * 
     * Includes:
     * - PKCE parameters
     * - State parameter
     * - Redirect URI
     * - Client ID
     */
    std::string create_authorization_url();

    /**
     * @brief Handles OAuth2 callback
     * @param code Authorization code from Keycloak
     * @param state State parameter for validation
     * @return TokenResponse containing tokens or error
     * @throws std::runtime_error if token exchange fails
     * 
     * Performs:
     * - State validation
     * - Code exchange
     * - Token validation
     */
    TokenResponse handle_callback(std::string_view code, std::string_view state);

    /**
     * @brief Updates cookie storage
     * @param name Cookie name
     * @param value Cookie value
     * @throws std::invalid_argument if name is empty
     */
    void update_cookies(const char* name, const char* value);
    // void configure_proxy(const std::string& host, uint16_t port);

private:
    config::LibraryConfig config_;                    ///< Library configuration
    std::shared_ptr<KeycloakClient> client_;          ///< Keycloak client instance
    std::shared_ptr<auth::PKCEStrategy> strategy_;    ///< PKCE authentication strategy
    std::string redirect_uri_;                        ///< OAuth2 callback URL
    std::unordered_map<std::string, std::string> cookies_; ///< Cookie storage
    http::ProxyConfig proxy_config_;                       ///< Proxy configuration
};

} // namespace keycloak::c_api
