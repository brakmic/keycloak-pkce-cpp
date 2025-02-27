/**
 * @file keycloak_client.hpp
 * @brief Core Keycloak Client Implementation
 * @version 1.0
 * 
 * Implements the main client interface for interacting with Keycloak servers.
 * Provides OAuth2/OIDC authentication flows, token management, and PKCE support.
 */

#pragma once
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include "keycloak/auth/token_service.hpp"
#include "keycloak/auth/strategy.hpp"
#include "keycloak/config/library_config.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/types.hpp"

namespace keycloak {

/**
 * @typedef LogCallback
 * @brief Callback function type for logging integration
 * 
 * Allows external logging system integration with configurable levels
 * and message formatting.
 */
using LogCallback = std::function<void(std::string_view level, std::string_view message)>;

/**
 * @class KeycloakClient
 * @brief Primary client interface for Keycloak authentication
 * 
 * Implements ITokenService interface and provides:
 * - OAuth2/OIDC authentication flows
 * - PKCE enhanced security
 * - Token management and validation
 * - Proxy support
 * - SSL/TLS configuration
 * - Custom logging integration
 */
class KeycloakClient : public auth::ITokenService {
public:
    /**
     * @brief Constructs a new Keycloak client instance
     * @param config Keycloak server configuration
     * @param proxy_config Proxy server settings
     * @param logger Optional logging callback
     * @throws std::invalid_argument if required config fields are missing
     */
    explicit KeycloakClient(
        const config::KeycloakConfig& config,
        const http::HttpClient::ProxyConfig& proxy_config,
        LogCallback logger)
        : config_(config)
        , protocol_(config.protocol)
        , host_(config.host)
        , port_(config.port)
        , realm_(config.realm)
        , logger_(logger)
        , ssl_config_(config.ssl)
        , proxy_config_(proxy_config)
    {
        init_endpoints();
    }

    /**
     * @brief Factory method for creating shared client instances
     * @param config Keycloak server configuration
     * @param proxy_config Proxy server settings
     * @param logger Optional logging callback
     * @return Shared pointer to new KeycloakClient instance
     */
    static std::shared_ptr<KeycloakClient> create(
        const config::KeycloakConfig& config,
        const http::HttpClient::ProxyConfig& proxy_config,
        LogCallback logger = nullptr)
    {
        return std::shared_ptr<KeycloakClient>(new KeycloakClient(config, proxy_config, logger));
    }

    /**
     * @brief Gets the authorization endpoint URL
     * @return Full URL to Keycloak's authorization endpoint
     * @implements ITokenService
     */
    std::string get_authorization_endpoint() const override {
        return protocol_ + "://" + host_ + ":" + std::to_string(port_) + auth_endpoint_;
    }

    /**
     * @brief Gets configured OAuth2 scopes
     * @return Vector of scope strings
     * @implements ITokenService
     */
    const std::vector<std::string>& get_scopes() const override {
        return config_.scopes;
    }
 
    /**
     * @brief Performs OAuth2 code exchange for tokens
     * @param code Authorization code from Keycloak
     * @param code_verifier PKCE verifier used in initial request
     * @param redirect_uri OAuth2 redirect URI
     * @param client_id OAuth2 client identifier
     * @return TokenResponse containing tokens or error information
     * @throws std::runtime_error for network or server errors
     * @implements ITokenService
     */
    TokenResponse exchange_code(
        std::string_view code,
        std::string_view code_verifier,
        std::string_view redirect_uri,
        std::string_view client_id) override;

    /**
     * @brief Creates a PKCE authentication strategy
     * @param config Library configuration
     * @param proxy_config Proxy settings
     * @param redirect_uri OAuth2 redirect URI
     * @param logger Optional logging callback
     * @return Shared pointer to IAuthenticationStrategy implementation
     * @throws std::invalid_argument if config is invalid
     */
    static std::shared_ptr<auth::IAuthenticationStrategy> create_pkce_strategy(
        const config::LibraryConfig& config,
        const http::HttpClient::ProxyConfig& proxy_config,
        std::string_view redirect_uri,
        LogCallback logger = nullptr);

private:
    /**
     * @brief Initializes Keycloak endpoint URLs
     * Sets up authentication and token endpoints based on configuration
     */
    void init_endpoints();

    /**
     * @brief Internal logging function
     * @param level Log severity level
     * @param message Log message
     */
    void log(std::string_view level, std::string_view message) const;

    const config::KeycloakConfig& config_;      ///< Keycloak configuration
    std::string protocol_;                      ///< Connection protocol (http/https)
    std::string host_;                          ///< Keycloak server hostname
    uint16_t port_;                             ///< Server port
    std::string realm_;                         ///< Keycloak realm
    LogCallback logger_;                        ///< Logging callback
    config::SSLConfig ssl_config_;              ///< SSL/TLS configuration
    http::HttpClient::ProxyConfig proxy_config_;///< Proxy settings

    std::string auth_endpoint_;                 ///< Authorization endpoint path
    std::string token_endpoint_;                ///< Token endpoint path
};

} // namespace keycloak
