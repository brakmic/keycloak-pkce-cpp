/**
* @file http_client.cpp
* @brief Implementation of HTTP client
* @version 1.0
*/

#include "keycloak/http/http_client.hpp"
#include "transport/asio_transport.hpp"
#include "keycloak/utils/logging.hpp"

namespace keycloak::http {

HttpClient::HttpClient(std::unique_ptr<ITransport> transport)
    : transport_(std::move(transport))
{
}

std::shared_ptr<HttpClient> HttpClient::create(std::unique_ptr<ITransport> transport) {
    return std::shared_ptr<HttpClient>(new HttpClient(std::move(transport)));
}

std::shared_ptr<HttpClient> HttpClient::create_https_client(
    const SSLConfig& ssl_config,
    const ProxyConfig& proxy_config)
{
    auto secure_transport = std::make_unique<AsioSecureTransport>();
    secure_transport->configure_ssl(ssl_config);

    if (proxy_config.is_enabled()) {
        secure_transport->set_proxy(proxy_config);
    }

    return create(std::move(secure_transport));
}

std::shared_ptr<HttpClient> HttpClient::create_http_client(
    const ProxyConfig& proxy_config)
{
    auto transport = std::make_unique<AsioTransport>();

    if (proxy_config.is_enabled()) {
        transport->set_proxy(proxy_config);
    }

    return create(std::move(transport));
}

// New implementation that uses ITransport
Response HttpClient::post(
    std::string_view host,
    std::string_view port,
    std::string_view path,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers)
{
    return transport_->send_request(host, port, "POST", path, body, headers);
}

// Backward compatibility
Response HttpClient::post(
    std::string_view host,
    std::string_view port,
    std::string_view path,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers,
    const SSLConfig& ssl_config,
    const ProxyConfig& proxy_config)
{
    // Create a temporary HTTPS client
    auto client = create_https_client(ssl_config, proxy_config);
    return client->post(host, port, path, body, headers);
}

} // namespace keycloak::http
