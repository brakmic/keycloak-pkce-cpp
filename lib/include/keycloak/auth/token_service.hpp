/**
* @file token_service.hpp
* @brief OAuth2 Token Service Interface for Keycloak Authentication
* @version 1.0
* 
* Defines the core interface for OAuth2 token exchange operations with Keycloak servers.
* This interface is used by authentication strategies to handle token lifecycle,
* including obtaining access, refresh, and ID tokens through OAuth2 flows.
*/

#pragma once
#include "keycloak/types.hpp"
#include <string>
#include <string_view>

namespace keycloak::auth {

class ITokenService {
public:
    virtual ~ITokenService() = default;
    

    /**
    * @brief Retrieves the authorization endpoint URL from Keycloak
    * @return Complete URL string to the authorization endpoint
    */
    virtual std::string get_authorization_endpoint() const = 0;
    
    /**
     * @brief Exchanges an authorization code for OAuth2 tokens
     * @param code Authorization code received from Keycloak
     * @param code_verifier PKCE code verifier used in the initial request
     * @param redirect_uri The OAuth2 redirect URI registered with Keycloak
     * @param client_id The OAuth2 client identifier
     * @return TokenResponse containing tokens on success or error information on failure
     * @throws std::runtime_error if network or server errors occur
     */
    virtual TokenResponse exchange_code(
        std::string_view code,
        std::string_view code_verifier,
        std::string_view redirect_uri,
        std::string_view client_id) = 0;

    /**
     * @brief Retrieves the configured OAuth2 scopes for token requests
     * @return Vector of scope strings (e.g., "openid", "profile", "email")
     * @note Scopes determine the level of access and information provided in tokens
     */
    virtual const std::vector<std::string>& get_scopes() const = 0;
};

} // namespace keycloak::auth
