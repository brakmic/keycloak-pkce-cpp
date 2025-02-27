/**
 * @file config_wrapper.hpp
 * @brief Configuration Wrapper for C API
 * @version 1.0
 * 
 * Provides C++-side management of configuration data passed through the C API.
 * Handles conversion between C structures and C++ configuration objects.
 * Ensures proper memory management and validation of configuration data.
 */

#pragma once
#include <string>
#include "kc_pkce.h"
#include "keycloak/config/library_config.hpp"

namespace keycloak::c_api {

/**
 * @class ConfigWrapper
 * @brief Wraps C++ LibraryConfig for C API use
 * 
 * Responsibilities:
 * - Configuration data conversion
 * - JSON file loading
 * - Validation of C API input
 * - Memory ownership management
 */
class ConfigWrapper {
public:
    /**
     * @brief Creates empty configuration wrapper
     * Initializes underlying C++ LibraryConfig with defaults
     */
    explicit ConfigWrapper();

    /**
     * @brief Loads configuration from JSON file
     * @param path Path to configuration file
     * @throws std::runtime_error if file operations fail
     * @throws nlohmann::json::exception if JSON parsing fails
     * 
     * JSON structure must match C++ library requirements
     */
    void load_from_file(const std::string& path);

    /**
     * @brief Sets Keycloak configuration from C structure
     * @param config C API Keycloak configuration
     * @throws std::invalid_argument if config is null or invalid
     * 
     * Converts and validates:
     * - Server settings
     * - Authentication parameters
     * - OAuth2 scopes
     */
    void set_keycloak_config(const kc_pkce_keycloak_config_t* config);

    /**
     * @brief Sets SSL configuration from C structure
     * @param config C API SSL configuration
     * @throws std::invalid_argument if config is null
     * 
     * Converts and validates:
     * - Certificate paths
     * - Verification settings
     */
    void set_ssl_config(const kc_pkce_ssl_config_t* config);

    /**
     * @brief Retrieves wrapped C++ configuration
     * @return Const reference to LibraryConfig
     */
    const config::LibraryConfig& get_config() const { return config_; }

private:
    config::LibraryConfig config_;  ///< Underlying C++ configuration
};

} // namespace keycloak::c_api
