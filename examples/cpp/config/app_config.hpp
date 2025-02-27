/**
 * @file app_config.hpp
 * @brief Configuration Structures for Demo Application
 * @version 1.0
 * 
 * Defines configuration structures for all aspects of the demo application:
 * - Server settings (HTTP/HTTPS)
 * - SSL/TLS configuration
 * - Proxy settings
 * - Logging configuration
 * - Authentication parameters
 */

#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace app::config {

/**
 * @struct ServerSSLConfig
 * @brief SSL/TLS configuration for HTTPS server
 * 
 * Controls server-side SSL settings including certificate management
 * and peer verification options.
 */
struct ServerSSLConfig {
    std::string cert_path;      ///< Path to SSL certificate file
    std::string key_path;       ///< Path to private key file
    bool verify_peer{false};    ///< Enable client certificate verification

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ServerSSLConfig, 
        cert_path, key_path, verify_peer)
};

/**
 * @struct ServerConfig
 * @brief Web server configuration
 * 
 * Defines core server settings including protocol selection,
 * binding address, port, and SSL configuration.
 */
struct ServerConfig {
    std::string protocol{"https"};  ///< Server protocol (http/https)
    std::string host{"0.0.0.0"};    ///< Binding address
    uint16_t port{18080};           ///< Server port
    ServerSSLConfig ssl;            ///< SSL configuration

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ServerConfig,
        protocol, host, port, ssl)
};

/**
 * @struct ProxyConfig
 * @brief HTTP proxy configuration
 * 
 * Settings for outbound proxy connections to Keycloak server.
 */
struct ProxyConfig {
    std::string host;           ///< Proxy server hostname
    uint16_t port{0};           ///< Proxy server port

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ProxyConfig,
        host, port)
};

/**
 * @struct LoggingConfig
 * @brief Logging configuration
 * 
 * Controls logging behavior for both application and Crow framework:
 * - Log levels
 * - Output destinations
 * - Message formatting
 */
struct LoggingConfig {
    std::string app_level{"info"};     ///< Application log level
    std::string crow_level{"info"};    ///< Crow framework log level
    bool console_logging{true};        ///< Enable console output
    std::string log_pattern{           ///< Log message format
        "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v"
    };

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(LoggingConfig,
        app_level, crow_level, console_logging, log_pattern)
};

/**
 * @struct AuthConfig
 * @brief OAuth2/PKCE authentication configuration
 * 
 * Defines authentication-specific parameters for OAuth2 flow.
 */
struct AuthConfig {
    std::string redirect_uri;   ///< OAuth2 callback URI

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AuthConfig, redirect_uri)
};

/**
 * @struct AppConfig
 * @brief Root configuration structure
 * 
 * Top-level configuration container combining all settings
 * for the demo application.
 */
struct AppConfig {
    ServerConfig server;        ///< Web server settings
    ProxyConfig proxy;          ///< Proxy configuration
    AuthConfig auth;            ///< Authentication settings
    LoggingConfig logging;      ///< Logging configuration

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AppConfig,
        server, proxy, auth, logging)
};

} // namespace app::config
