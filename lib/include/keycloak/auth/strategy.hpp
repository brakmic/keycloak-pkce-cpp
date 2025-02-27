/**
 * @file strategy.hpp
 * @brief Authentication Strategy Interface for Keycloak
 * @version 1.0
 * 
 * Defines the core authentication strategy interface that all authentication
 * implementations must follow. Supports OAuth2/OIDC flows with cookie-based
 * session management.
 */

#pragma once
#include <string>
#include <string_view>  
#include <unordered_map>
#include "keycloak/types.hpp"
#include "keycloak/config/library_config.hpp"

namespace keycloak::auth {

/**
 * @class IAuthenticationStrategy
 * @brief Interface for implementing OAuth2/OIDC authentication flows
 * 
 * Defines the contract for authentication strategies, providing:
 * - Authorization URL generation
 * - OAuth2 callback handling
 * - Session validation
 * - Cookie management
 */
class IAuthenticationStrategy {
public:
    virtual ~IAuthenticationStrategy() = default;
    
    /**
     * @brief Creates the OAuth2 authorization URL
     * @return Complete URL including all required OAuth2 parameters
     * @throws std::runtime_error if URL generation fails
     * 
     * The URL includes:
     * - client_id
     * - response_type
     * - redirect_uri
     * - scope
     * - state (for CSRF protection)
     * - Additional flow-specific parameters
     */
    virtual std::string create_authorization_url() = 0;
    
    /**
     * @brief Handles OAuth2 callback and token exchange
     * @param code Authorization code from Keycloak
     * @param state State parameter for CSRF validation
     * @return TokenResponse containing tokens or error information
     * @throws std::runtime_error if token exchange fails
     * @throws std::invalid_argument if code or state is invalid
     */
    virtual TokenResponse handle_callback(
        std::string_view code, 
        std::string_view state) = 0;
        
    /**
     * @brief Validates an active session using cookies
     * @param cookies Map of cookie names to values
     * @return true if session is valid, false otherwise
     * 
     * Checks:
     * - Presence of required cookies
     * - Token validity
     * - Token expiration
     */
    virtual bool validate_session(const std::unordered_map<std::string, std::string>& cookies) = 0;

    /**
     * @brief Retrieves cookie configuration
     * @return Reference to cookie configuration
     * 
     * Used by implementations to maintain consistent
     * cookie settings across the authentication flow.
     */
    virtual const config::CookieConfig& get_cookie_config() const = 0;
};

} // namespace keycloak::auth
