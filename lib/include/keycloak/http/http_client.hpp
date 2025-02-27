/**
 * @file http_client.hpp
 * @brief HTTPS Client Implementation for Keycloak Communication
 * @version 1.0
 * 
 * Implements a secure HTTP client for communicating with Keycloak servers.
 * Provides SSL/TLS support, proxy configuration, and synchronous HTTP operations
 * using the ASIO library for network communication.
 */

#pragma once
#include <asio.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include "keycloak/config/library_config.hpp"

namespace keycloak::http {

class HttpClient {
public:
    /**
     * @brief Proxy configuration for HTTP requests
     * @struct ProxyConfig
     */
    struct ProxyConfig {
        std::string host;   ///< Proxy server hostname
        uint16_t port{0};   ///< Proxy server port

        /**
         * @brief Checks if proxy configuration is valid and enabled
         * @return true if both host and port are set
         */
        bool is_enabled() const {
            return !host.empty() && port > 0;
        }
    };

    /**
     * @brief SSL/TLS configuration for secure connections
     * @struct SSLConfig
     */
    struct SSLConfig {
        bool verify_peer{false};        ///< Enable peer certificate verification
        std::string ca_cert_path;       ///< Path to CA certificate file
        std::string client_cert_path;   ///< Path to client certificate file
        std::string client_key_path;    ///< Path to client private key file

        SSLConfig() = default;

        /**
         * @brief Converts library SSL config to client SSL config
         * @param lib_config Source configuration from library
         */
        explicit SSLConfig(const config::SSLConfig& lib_config) 
            : verify_peer(lib_config.verify_peer)
            , ca_cert_path(lib_config.ca_cert_path)
        {}
    };

    /**
     * @brief HTTP response structure
     * @struct Response
     */
    struct Response {
        int status_code{0};                                     ///< HTTP status code
        std::string body;                                       ///< Response body
        std::unordered_map<std::string, std::string> headers;   ///< Response headers
    };
    
    /**
     * @brief Performs an HTTPS POST request
     * @param host Target server hostname
     * @param port Target server port
     * @param path Request path
     * @param body Request body
     * @param headers Request headers
     * @param ssl_config SSL configuration
     * @param proxy_config Proxy configuration
     * @return Response containing status code, headers, and body
     * @throws std::runtime_error for network or SSL errors
     */
    static Response post(
        std::string_view host,
        std::string_view port,
        std::string_view path,
        std::string_view body,
        const std::unordered_map<std::string, std::string>& headers,
        const SSLConfig& ssl_config,
        const ProxyConfig& proxy_config);

private:
    /**
     * @brief Sends an HTTP request with the specified parameters
     * @param host Target server hostname
     * @param port Target server port
     * @param method HTTP method (GET, POST, etc.)
     * @param path Request path
     * @param body Request body
     * @param headers Request headers
     * @param ssl_config SSL configuration
     * @param proxy_config Proxy configuration
     * @return Response containing status code, headers, and body
     * @throws std::runtime_error for network or SSL errors
     */
    static Response send_request(
        std::string_view host,
        std::string_view port,
        std::string_view method,
        std::string_view path,
        std::string_view body,
        const std::unordered_map<std::string, std::string>& headers,
        const SSLConfig& ssl_config,
        const ProxyConfig& proxy_config);
};

} // namespace keycloak::http
