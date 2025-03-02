/**
 * @file asio_transport.hpp
 * @brief ASIO-based HTTP transport implementation
 * @version 1.0
 * 
 * Implements transport interfaces using ASIO networking library
 */

 #pragma once
 #include "keycloak/http/transport.hpp"
 #include "keycloak/http/ssl_config.hpp"
 #include "keycloak/http/proxy_config.hpp"
 #include <asio.hpp>
 #include <asio/ssl.hpp>
 
 namespace keycloak::http {
 
 /**
  * @class AsioTransport
  * @brief Plain HTTP transport using ASIO
  */
 class AsioTransport : 
     public ITransport,
     public IProxyAware {
 public:
     AsioTransport();
     
     Response send_request(
         std::string_view host,
         std::string_view port,
         std::string_view method,
         std::string_view path,
         std::string_view body,
         const std::unordered_map<std::string, std::string>& headers) override;
         
     void set_proxy(const ProxyConfig& config) override;
     
 protected:
     asio::io_context io_context_;
     ProxyConfig proxy_config_;
     
     std::string build_request(
         std::string_view method,
         std::string_view path,
         std::string_view host,
         std::string_view body,
         const std::unordered_map<std::string, std::string>& headers);
         
     Response parse_response(std::istream& response_stream);
 };
 
 /**
  * @class AsioSecureTransport
  * @brief HTTPS transport using ASIO with SSL
  */
 class AsioSecureTransport : 
     public AsioTransport,
     public ISecureTransport {
 public:
     AsioSecureTransport();
     
     Response send_request(
         std::string_view host,
         std::string_view port,
         std::string_view method,
         std::string_view path,
         std::string_view body,
         const std::unordered_map<std::string, std::string>& headers) override;
         
     void configure_ssl(const SSLConfig& config) override;
     
 private:
     asio::ssl::context ssl_context_;
     SSLConfig ssl_config_;
 };
 
 } // namespace keycloak::http
 