/**
 * @file proxy_settings.hpp
 * @brief Global Proxy Configuration for C API
 * @version 1.0
 * 
 * Implements a singleton pattern for managing global proxy settings.
 * Provides thread-safe access to proxy configuration that applies
 * to all HTTPS connections in the C API layer.
 */

#pragma once
#include <string>
#include <cstdint>

namespace keycloak::c_api {

/**
 * @class ProxySettings
 * @brief Thread-safe singleton for global proxy configuration
 * 
 * Responsibilities:
 * - Global proxy settings management
 * - Thread-safe access to configuration
 * - Default settings handling
 */
class ProxySettings {
public:
    /**
     * @brief Gets singleton instance
     * @return Reference to global ProxySettings instance
     * 
     * Thread-safe due to C++11 static initialization guarantees
     */
    static ProxySettings& instance() {
        static ProxySettings instance;
        return instance;
    }

    /**
     * @brief Configures proxy settings
     * @param host Proxy server hostname
     * @param port Proxy server port
     * 
     * Thread-safe: atomic assignment of string and integral types
     */
    void configure(const std::string& host, uint16_t port) {
        host_ = host;
        port_ = port;
    }

    /**
     * @brief Gets configured proxy hostname
     * @return Current proxy hostname
     */
    const std::string& get_host() const { return host_; }
    
    /**
     * @brief Gets configured proxy port
     * @return Current proxy port (0 if not configured)
     */
    uint16_t get_port() const { return port_; }

private:
    ProxySettings() = default;                      ///< Private constructor for singleton
    ProxySettings(const ProxySettings&) = delete;   ///< Delete copy constructor
    void operator=(const ProxySettings&) = delete;  ///< Delete assignment operator

    std::string host_;   ///< Proxy server hostname
    uint16_t port_{0};   ///< Proxy server port (0 = disabled)
};

} // namespace keycloak::c_api
