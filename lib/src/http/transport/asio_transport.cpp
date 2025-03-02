/**
* @file asio_transport.cpp
* @brief Implementation of ASIO-based HTTP transports
*/

#include "asio_transport.hpp"
#include "keycloak/utils/logging.hpp"
#include <sstream>
#include <iostream>

namespace keycloak::http {

using namespace keycloak::logging;

AsioTransport::AsioTransport() {
}

Response AsioTransport::send_request(
    std::string_view host,
    std::string_view port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers)
{
    try {
        // Determine actual target based on proxy configuration
        std::string target_host = proxy_config_.is_enabled() ? proxy_config_.host : std::string(host);
        std::string target_port = proxy_config_.is_enabled() ? 
            std::to_string(proxy_config_.port) : std::string(port);

        // Create socket
        asio::ip::tcp::resolver resolver(io_context_);
        asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(target_host, target_port);
        asio::ip::tcp::socket socket(io_context_);
        asio::connect(socket, endpoints);

        // Build request
        std::string request = build_request(method, path, host, body, headers);
        
        // Send request
        asio::write(socket, asio::buffer(request));

        // Read response
        asio::streambuf response_buf;
        asio::read_until(socket, response_buf, "\r\n\r\n");

        // Check if there's more data
        size_t bytes_available = socket.available();
        if (bytes_available > 0) {
            asio::read(socket, response_buf, asio::transfer_exactly(bytes_available));
        }

        // Parse response
        std::istream response_stream(&response_buf);
        return parse_response(response_stream);

    } catch (const std::exception& e) {
        Logger::error("HTTP transport error: {}", e.what());
        throw std::runtime_error(std::string("HTTP transport error: ") + e.what());
    }
}

void AsioTransport::set_proxy(const ProxyConfig& config) {
    proxy_config_ = config;
}

std::string AsioTransport::build_request(
    std::string_view method,
    std::string_view path,
    std::string_view host,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& headers)
{
    std::stringstream request_stream;
    
    // Request line
    request_stream << method << " " << path << " HTTP/1.1\r\n";
    
    // Headers
    request_stream << "Host: " << host << "\r\n";
    request_stream << "Content-Length: " << body.size() << "\r\n";
    
    // Custom headers
    for (const auto& [name, value] : headers) {
        request_stream << name << ": " << value << "\r\n";
    }
    
    // End of headers
    request_stream << "\r\n";
    
    // Body
    request_stream << body;
    
    return request_stream.str();
}

Response AsioTransport::parse_response(std::istream& response_stream) {
    Response response;
    std::string http_version;
    std::string status_message;
    
    // Parse status line
    response_stream >> http_version >> response.status_code;
    std::getline(response_stream, status_message);
    
    // Parse headers
    std::string header_line;
    while (std::getline(response_stream, header_line) && header_line != "\r") {
        auto separator = header_line.find(':');
        if (separator != std::string::npos) {
            auto name = header_line.substr(0, separator);
            auto value = header_line.substr(separator + 1);
            
            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of("\r") + 1);
            
            response.headers[name] = value;
        }
    }
    
    // Read body
    std::stringstream body_stream;
    body_stream << response_stream.rdbuf();
    response.body = body_stream.str();
    
    return response;
}

// AsioSecureTransport implementation

AsioSecureTransport::AsioSecureTransport()
    : ssl_context_(asio::ssl::context::sslv23)
{
    // Default SSL configuration
    ssl_context_.set_default_verify_paths();
    ssl_context_.set_options(
        asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::no_sslv3 |
        asio::ssl::context::no_tlsv1 |
        asio::ssl::context::no_tlsv1_1
    );
}

Response AsioSecureTransport::send_request(
  std::string_view host,
  std::string_view port,
  std::string_view method,
  std::string_view path,
  std::string_view body,
  const std::unordered_map<std::string, std::string>& headers)
{
  try {
      // Determine actual target based on proxy configuration
      std::string target_host = proxy_config_.is_enabled() ? proxy_config_.host : std::string(host);
      std::string target_port = proxy_config_.is_enabled() ? 
          std::to_string(proxy_config_.port) : std::string(port);

      logging::Logger::debug("Connection: {}:{} via {}:{}", 
                           std::string(host), std::string(port),
                           target_host, target_port);

      // Create socket and resolver
      asio::ip::tcp::resolver resolver(io_context_);
      auto endpoints = resolver.resolve(target_host, target_port);
      
      // Create SSL stream
      asio::ssl::stream<asio::ip::tcp::socket> ssl_stream(io_context_, ssl_context_);
      
      // Enable SNI (Server Name Indication)
      if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str())) {
          throw std::runtime_error("Failed to set SNI hostname");
      }

      // Connect to the endpoint
      asio::connect(ssl_stream.lowest_layer(), endpoints);
      logging::Logger::debug("TCP connection established, performing SSL handshake");
      
      // Perform SSL handshake
      ssl_stream.handshake(asio::ssl::stream_base::client);
      logging::Logger::debug("SSL handshake completed");

      // Build the request
      std::ostringstream request_stream;
      request_stream << method << " " << path << " HTTP/1.1\r\n";
      request_stream << "Host: " << host << ":" << port << "\r\n";
      
      for (const auto& [name, value] : headers) {
          request_stream << name << ": " << value << "\r\n";
      }
      
      if (!body.empty()) {
          request_stream << "Content-Length: " << body.length() << "\r\n";
      }
      
      // Use close connection to simplify reading the response
      request_stream << "Connection: close\r\n\r\n";
      
      if (!body.empty()) {
          request_stream << body;
      }

      // Send the request
      logging::Logger::debug("Sending request");
      asio::write(ssl_stream, asio::buffer(request_stream.str()));

      // Read the response
      asio::streambuf response_buf;
      asio::read_until(ssl_stream, response_buf, "\r\n\r\n");

      // Process response headers
      std::istream response_stream(&response_buf);
      Response response;
      std::string http_version;
      response_stream >> http_version;
      response_stream >> response.status_code;
      
      std::string status_message;
      std::getline(response_stream, status_message);

      // Parse headers
      std::string header;
      while (std::getline(response_stream, header) && header != "\r") {
          if (auto separator = header.find(": "); separator != std::string::npos) {
              auto name = header.substr(0, separator);
              auto value = header.substr(separator + 2);
              if (!value.empty() && value.back() == '\r') {
                  value.pop_back();
              }
              response.headers.emplace(std::move(name), std::move(value));
          }
      }

      // Read the response body
      std::stringstream body_stream;
      if (response_buf.size() > 0) {
          body_stream << &response_buf;
      }

      // Continue reading until connection is closed (due to "Connection: close")
      asio::error_code error;
      while (asio::read(ssl_stream, response_buf, asio::transfer_at_least(1), error)) {
          body_stream << &response_buf;
      }

      if (error && error != asio::error::eof) {
          throw asio::system_error(error);
      }

      response.body = body_stream.str();
      logging::Logger::debug("Response status: {}, body length: {}", 
                           response.status_code, response.body.length());

      return response;

  } catch (const std::exception& e) {
      logging::Logger::error("HTTPS request failed: {}", e.what());
      
      // Log SSL errors
      unsigned long err = ERR_get_error();
      if (err != 0) {
          char buf[256];
          ERR_error_string_n(err, buf, sizeof(buf));
          logging::Logger::error("SSL error details: {}", buf);
      }
      
      return Response{
          0,  // Status 0 indicates a connection/protocol error
          std::string("Request failed: ") + e.what(),
          {}
      };
  }
}

void AsioSecureTransport::configure_ssl(const SSLConfig& config) {
  ssl_config_ = config;
  
  ssl_context_.set_options(
      asio::ssl::context::default_workarounds |
      asio::ssl::context::no_sslv2 |
      asio::ssl::context::no_sslv3
  );
  
  if (!config.verify_peer) {
      logging::Logger::debug("SSL verification disabled");
      ssl_context_.set_verify_mode(asio::ssl::verify_none);
      SSL_CTX_set_verify(ssl_context_.native_handle(), SSL_VERIFY_NONE, nullptr);
  } else {
      logging::Logger::debug("SSL verification enabled");
      ssl_context_.set_verify_mode(asio::ssl::verify_peer);
      
      if (!config.ca_cert_path.empty()) {
          logging::Logger::debug("Loading CA certificate from: {}", config.ca_cert_path);
          ssl_context_.load_verify_file(config.ca_cert_path);
      }
      
      if (!config.client_cert_path.empty()) {
          logging::Logger::debug("Loading client certificate from: {}", config.client_cert_path);
          ssl_context_.use_certificate_file(
              config.client_cert_path, 
              asio::ssl::context::pem
          );
      }
      
      if (!config.client_key_path.empty()) {
          logging::Logger::debug("Loading client key from: {}", config.client_key_path);
          ssl_context_.use_private_key_file(
              config.client_key_path, 
              asio::ssl::context::pem
          );
      }
  }
}

// Factory functions
std::unique_ptr<ITransport> create_default_transport() {
    return std::make_unique<AsioTransport>();
}

std::unique_ptr<ISecureTransport> create_default_secure_transport(const SSLConfig& config) {
    auto transport = std::make_unique<AsioSecureTransport>();
    transport->configure_ssl(config);
    return transport;
}

} // namespace keycloak::http
