/**
 * @file proxy_config.hpp
 * @brief Proxy configuration structures and interfaces
 * @version 1.0
 * 
 * Defines configuration structures and interfaces for HTTP proxy support
 */

 #pragma once
 #include <string>
 #include <cstdint>
 
 namespace keycloak::http {
 
 /**
  * @struct ProxyConfig
  * @brief HTTP proxy server configuration
  */
 struct ProxyConfig {
     std::string host;       ///< Proxy server hostname or IP address
     uint16_t port{0};       ///< Proxy server port
     
     /**
      * @brief Check if proxy is configured
      * @return true if proxy configuration is valid
      */
     bool is_enabled() const { return !host.empty() && port > 0; }
 };
 
 /**
  * @class IProxyAware
  * @brief Interface for transports with proxy support
  */
 class IProxyAware {
 public:
     virtual ~IProxyAware() = default;
     
     /**
      * @brief Configure proxy settings for the transport
      * @param config Proxy configuration
      */
     virtual void set_proxy(const ProxyConfig& config) = 0;
 };
 
 } // namespace keycloak::http
 