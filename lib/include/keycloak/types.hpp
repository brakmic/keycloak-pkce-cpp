/**
 * @file types.hpp
 * @brief Common types for Keycloak authentication
 * @version 1.0
 * 
 * Defines data structures used across the Keycloak client implementation
 * including token responses, authentication results, and callback parameters.
 * Provides JSON serialization support via nlohmann::json.
 */

#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <optional>

namespace keycloak {

/**
 * @struct TokenResponse
 * @brief Contains OAuth2 tokens and error information from Keycloak
 * 
 * Encapsulates both successful token responses and error conditions
 * from Keycloak's token endpoint. Includes JSON serialization support
 * and helper methods for response validation.
 */
struct TokenResponse {
    // Success fields
    std::string access_token;        ///< OAuth2 access token for API calls
    std::string refresh_token;       ///< Token used to obtain new access tokens
    std::string id_token;            ///< OpenID Connect ID token containing user info
    std::string token_type;          ///< Token type (usually "Bearer")
    int expires_in{0};               ///< Access token validity period in seconds
    int refresh_expires_in{0};       ///< Refresh token validity period in seconds
    
    // Error fields
    std::string error;               ///< OAuth2 error code (RFC 6749)
    std::string error_description;   ///< Human-readable error description
    
    /**
     * @brief Checks if the token response indicates success
     * @return true if no error is present, false otherwise
     * 
     * Success is determined by the absence of an error code,
     * following OAuth2 error handling specifications.
     */
    bool is_success() const { return error.empty(); }
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(TokenResponse, 
        access_token, refresh_token, id_token, 
        token_type, expires_in, refresh_expires_in,
        error, error_description)
};

} // namespace keycloak
