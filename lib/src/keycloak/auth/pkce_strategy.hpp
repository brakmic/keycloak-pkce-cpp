/**
 * @file pkce_strategy.hpp
 * @brief PKCE (Proof Key for Code Exchange) Authentication Strategy Implementation
 * @version 1.0
 * 
 * Implements the OAuth2 PKCE flow for secure authentication with Keycloak.
 * PKCE extends the authorization code flow to prevent authorization code interception
 * attacks, making it suitable for native and mobile applications.
 */

#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <utility>
#include "pkce/pkce.hpp"
#include "keycloak/pkce/state_store.hpp"
#include "keycloak/auth/strategy.hpp"
#include "keycloak/auth/token_service.hpp"
#include "keycloak/config/library_config.hpp"

namespace keycloak::auth {

class PKCEStrategy : public IAuthenticationStrategy {
public:
    static std::unique_ptr<PKCEStrategy> create(
        std::shared_ptr<ITokenService> token_service,
        std::string_view client_id,
        std::string_view redirect_uri,
        const config::PKCEConfig& pkce_config,
        std::unique_ptr<pkce::IStateStore> state_store = nullptr) {
        if (!state_store) {
            state_store = std::make_unique<pkce::StateStore>(pkce_config.state_store);
        }
        return std::unique_ptr<PKCEStrategy>(new PKCEStrategy(
            token_service, client_id, redirect_uri, pkce_config, std::move(state_store)));
    }

    /**
     * @brief Generates the authorization URL with PKCE parameters
     * @return Complete URL for initiating the OAuth2 PKCE flow
     * @throws std::runtime_error if code challenge generation fails
     * 
     * Includes:
     * - Standard OAuth2 parameters
     * - PKCE code challenge
     * - PKCE code challenge method (S256)
     * - State parameter for CSRF protection
     */
    std::string create_authorization_url() override;
    
    /**
     * @brief Handles the OAuth2 callback with PKCE verification
     * @param code Authorization code from Keycloak
     * @param state State parameter for CSRF protection
     * @return TokenResponse containing OAuth2 tokens or error information
     * @throws std::runtime_error if state verification or token exchange fails
     * @throws std::invalid_argument if code or state is invalid
     * 
     * Security checks:
     * - State parameter validation
     * - PKCE code verifier matching
     * - Token response validation
     */
    TokenResponse handle_callback(std::string_view code, std::string_view state) override;

    /**
     * @brief Validates an active session using stored tokens
     * @param cookies Map of cookie names to values
     * @return true if session is valid, false otherwise
     * 
     * Validates:
     * - Access token presence
     * - Token format and signature
     * - Token expiration
     */
    bool validate_session(const std::unordered_map<std::string, std::string>& cookies) override;

    /**
     * @brief Gets the cookie configuration
     * @return Reference to cookie settings
     */
    const config::CookieConfig& get_cookie_config() const override { return cookie_config_; }

private:
/**
     * @brief Creates a new PKCE authentication strategy instance
     * @param token_service Token service for OAuth2 operations
     * @param client_id OAuth2 client identifier
     * @param redirect_uri OAuth2 redirect URI
     * @param pkce_config PKCE-specific configuration
     * @throws std::invalid_argument if token_service is null or parameters are invalid
     * 
     * Configuration includes:
     * - Cookie settings for token storage
     * - State store parameters
     * - PKCE challenge method (S256)
     */
     PKCEStrategy(
        std::shared_ptr<ITokenService> token_service,
        std::string_view client_id,
        std::string_view redirect_uri,
        const config::PKCEConfig& pkce_config,
        std::unique_ptr<pkce::IStateStore> state_store)
        : token_service_(token_service)
        , client_id_(client_id)
        , redirect_uri_(redirect_uri)
        , cookie_config_(pkce_config.cookies)
        , state_store_(std::move(state_store))
    {}
    std::shared_ptr<ITokenService> token_service_;      ///< OAuth2 token operations
    std::string client_id_;                             ///< OAuth2 client identifier
    std::string redirect_uri_;                          ///< OAuth2 redirect URI
    const config::CookieConfig& cookie_config_;         ///< Cookie settings
    std::unique_ptr<pkce::IStateStore> state_store_;    ///< PKCE state management
};

} // namespace keycloak::auth
