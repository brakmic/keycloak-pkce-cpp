/**
* @file http_client.hpp
* @brief HTTP client implementation
* @version 1.0
*
* Provides a client interface for making HTTP requests using
* configurable transport implementations.
*/

#pragma once
#include "transport.hpp"
#include "ssl_config.hpp"
#include "proxy_config.hpp"
#include <string>
#include <string_view>
#include <memory>
#include <unordered_map>

namespace keycloak::http {

/**
* @class HttpClient
* @brief Client for making HTTP requests
*
* Uses pluggable transport implementations to provide
* HTTP communication with optional SSL/TLS and proxy support.
*/
class HttpClient {
public:
    /**
    * @brief Create an HTTP client with the specified transport
    * @param transport Transport implementation to use
    * @return Shared pointer to HTTP client
    */
    static std::shared_ptr<HttpClient> create(std::unique_ptr<ITransport> transport);

    /**
    * @brief Create a client for HTTPS communication
    * @param ssl_config SSL configuration
    * @param proxy_config Optional proxy configuration
    * @return Shared pointer to HTTP client configured for HTTPS
    */
    static std::shared_ptr<HttpClient> create_https_client(
        const SSLConfig& ssl_config = {},
        const ProxyConfig& proxy_config = {});

    /**
    * @brief Create a client for plain HTTP communication
    * @param proxy_config Optional proxy configuration
    * @return Shared pointer to HTTP client configured for HTTP
    */
    static std::shared_ptr<HttpClient> create_http_client(
        const ProxyConfig& proxy_config = {});
    
    /**
    * @brief Send POST request
    * @param host Target host
    * @param port Target port
    * @param path Request path
    * @param body Request body
    * @param headers Request headers
    * @return HTTP response
    */
    Response post(
        std::string_view host,
        std::string_view port,
        std::string_view path,
        std::string_view body,
        const std::unordered_map<std::string, std::string>& headers);

    /**
    * @brief Get shared access to underlying transport
    * @return Shared pointer to transport implementation
    */
    std::shared_ptr<ITransport> get_transport() {
        if (!shared_transport_) {
            shared_transport_ = std::shared_ptr<ITransport>(transport_.get(),
                /* no-op deleter - ownership stays with unique_ptr */
                [this](ITransport*) {});
        }
        return shared_transport_;
    }

    // Backward compatibility
    static Response post(
        std::string_view host,
        std::string_view port,
        std::string_view path,
        std::string_view body,
        const std::unordered_map<std::string, std::string>& headers,
        const SSLConfig& ssl_config,
        const ProxyConfig& proxy_config);

private:
    explicit HttpClient(std::unique_ptr<ITransport> transport);
    std::unique_ptr<ITransport> transport_;
    std::shared_ptr<ITransport> shared_transport_;
};

} // namespace keycloak::http
