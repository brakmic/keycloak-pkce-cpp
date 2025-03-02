/**
 * @file ssl_config.hpp
 * @brief SSL/TLS configuration structures
 * @version 1.0
 * 
 * Defines configuration structures for SSL/TLS connections
 */

 #pragma once
 #include <string>
 
 namespace keycloak::http {
 
 /**
  * @struct SSLConfig
  * @brief SSL/TLS connection configuration
  */
 struct SSLConfig {
     bool verify_peer{true};         ///< Whether to verify the server certificate
     std::string ca_cert_path;       ///< Path to CA certificate file
     std::string client_cert_path;   ///< Path to client certificate file
     std::string client_key_path;    ///< Path to client private key file
 };
 
 /**
  * @class ISecureTransport
  * @brief Interface for transports with SSL/TLS support
  */
 class ISecureTransport {
 public:
     virtual ~ISecureTransport() = default;
     
     /**
      * @brief Configure SSL/TLS options for the transport
      * @param config SSL configuration
      */
     virtual void configure_ssl(const SSLConfig& config) = 0;
 };
 
 /**
  * @brief Factory function for creating secure transport instances
  * @param config SSL configuration
  * @return Unique pointer to a secure transport implementation
  */
 std::unique_ptr<ISecureTransport> create_default_secure_transport(const SSLConfig& config = {});
 
 } // namespace keycloak::http
 