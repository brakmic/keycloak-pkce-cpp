#include <ranges>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <sstream>
#include <unordered_map>
#include "keycloak/http/http_client.hpp"
#include "keycloak/utils/logging.hpp"

namespace lg = logging;

namespace keycloak::http {

HttpClient::Response HttpClient::post(
    std::string_view host,
    std::string_view port,
    std::string_view path,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers,
    const SSLConfig& ssl_config,
    const ProxyConfig& proxy_config) 
{
    return send_request(host, port, "POST", path, body, headers, ssl_config, proxy_config);
}

void log_ssl_error() {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        lg::Logger::error("SSL error details: {}", buf);
    }
}

HttpClient::Response HttpClient::send_request(
    std::string_view host,
    std::string_view port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers,
    const SSLConfig& ssl_config,
    const ProxyConfig& proxy_config) 
{
    try {
        asio::io_context io_context;
        asio::ssl::context ssl_ctx(asio::ssl::context::sslv23_client);

        ssl_ctx.set_options(
            asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3 |
            asio::ssl::context::tlsv12 |
            asio::ssl::context::tlsv13
        );
        
        if (!ssl_config.verify_peer) {
            lg::Logger::debug("SSL verification disabled");
            ssl_ctx.set_verify_mode(asio::ssl::verify_none);
            SSL_CTX_set_verify(ssl_ctx.native_handle(), SSL_VERIFY_NONE, nullptr);
        } else {
            lg::Logger::debug("SSL verification enabled");
            ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
            if (!ssl_config.ca_cert_path.empty()) {
                lg::Logger::debug("Loading CA certificate from: {}", ssl_config.ca_cert_path);
                ssl_ctx.load_verify_file(ssl_config.ca_cert_path);
            }
            if (!ssl_config.client_cert_path.empty()) {
                lg::Logger::debug("Loading client certificate from: {}", ssl_config.client_cert_path);
                ssl_ctx.use_certificate_file(
                    ssl_config.client_cert_path, 
                    asio::ssl::context::pem
                );
            }
            if (!ssl_config.client_key_path.empty()) {
                lg::Logger::debug("Loading client key from: {}", ssl_config.client_key_path);
                ssl_ctx.use_private_key_file(
                    ssl_config.client_key_path, 
                    asio::ssl::context::pem
                );
            }
        }

        asio::ssl::stream<asio::ip::tcp::socket> ssl_stream(io_context, ssl_ctx);

        auto connection_host = std::string(host);
        auto connection_port = std::string(port);
        
        if (proxy_config.is_enabled()) {
            lg::Logger::debug("Using proxy: {}:{}", proxy_config.host, proxy_config.port);
            connection_host = proxy_config.host;
            connection_port = std::to_string(proxy_config.port);
        }

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(
            asio::ip::tcp::v4(),
            connection_host,
            connection_port
        );

        lg::Logger::debug("Attempting connection to {}:{}", host, port);
        for (const auto& endpoint : endpoints) {
            lg::Logger::debug("Resolved endpoint: {}:{}", 
                endpoint.endpoint().address().to_string(),
                endpoint.endpoint().port());
        }

        asio::connect(ssl_stream.lowest_layer(), endpoints);
        lg::Logger::debug("TCP connection established, performing SSL handshake");

        if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str())) {
            throw std::runtime_error("Failed to set SNI hostname");
        }

        ssl_stream.handshake(asio::ssl::stream_base::client);
        lg::Logger::debug("SSL handshake completed");

        std::ostringstream request_stream;
        request_stream << method << " " << path << " HTTP/1.1\r\n";
        request_stream << "Host: " << host << ":" << port << "\r\n";
        
        std::ranges::for_each(headers, [&request_stream](const auto& pair) {
            request_stream << pair.first << ": " << pair.second << "\r\n";
        });
        
        if (!body.empty()) {
            request_stream << "Content-Type: application/x-www-form-urlencoded\r\n";
            request_stream << "Content-Length: " << body.length() << "\r\n";
        }
        
        request_stream << "Connection: close\r\n\r\n";
        if (!body.empty()) {
            request_stream << body;
        }

        lg::Logger::debug("Sending request");
        asio::write(ssl_stream, asio::buffer(request_stream.str()));

        asio::streambuf response;
        asio::read_until(ssl_stream, response, "\r\n\r\n");

        std::istream response_stream(&response);
        Response result;
        std::string http_version;
        response_stream >> http_version;
        response_stream >> result.status_code;

        std::string status_message;
        std::getline(response_stream, status_message);

        std::string header;
        while (std::getline(response_stream, header) && header != "\r") {
            if (auto separator = header.find(": "); separator != std::string::npos) {
                auto name = header.substr(0, separator);
                auto value = header.substr(separator + 2);
                if (!value.empty() && value.back() == '\r') {
                    value.pop_back();
                }
                result.headers.emplace(std::move(name), std::move(value));
            }
        }

        std::stringstream body_stream;
        if (response.size() > 0) {
            body_stream << &response;
        }

        asio::error_code error;
        while (asio::read(ssl_stream, response, asio::transfer_at_least(1), error)) {
            body_stream << &response;
        }

        if (error && error != asio::error::eof) {
            throw asio::system_error(error);
        }

        result.body = body_stream.str();
        return result;

    } catch (const std::exception& e) {
        lg::Logger::error("HTTP request failed: {}", e.what());
        log_ssl_error();
        return Response{
            500,
            std::string("Request failed: ") + e.what(),
            std::unordered_map<std::string, std::string>{}
        };
    }
}

} // namespace keycloak::http
