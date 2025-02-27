/**
 * @file config_loader.hpp
 * @brief Configuration Loading and Management for Demo Application
 * @version 1.0
 * 
 * Provides configuration loading from multiple sources:
 * - JSON configuration files
 * - Environment variables
 * - Command-line arguments
 * 
 * Includes validation and path resolution utilities.
 */

#pragma once
#include "app_config.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include "keycloak/utils/logging.hpp"
#include <cxxopts.hpp>

namespace app::config {

/**
 * @class ConfigLoader
 * @brief Utility class for loading and managing application configuration
 */
class ConfigLoader {
public:
    /**
     * @brief Loads configuration from JSON file
     * @param path Path to configuration file
     * @return Populated AppConfig instance
     * @throws std::runtime_error if file operations fail
     * @throws nlohmann::json::exception if JSON parsing fails
     */
    static AppConfig load_from_file(const std::filesystem::path& path);
    /**
     * @brief Loads configuration from environment variables
     * @return AppConfig populated from environment variables
     * 
     * Supported variables:
     * - SERVER_HOST: Binding address
     * - SERVER_PORT: Server port
     * - SERVER_PROTOCOL: http/https
     * - PROXY_HOST: Proxy server hostname
     * - PROXY_PORT: Proxy server port
     */
    static AppConfig load_from_env();
    /**
     * @brief Merges configurations with override rules
     * @param target Configuration to update
     * @param source Source of new values
     */
    static void merge(AppConfig& target, const AppConfig& source);
    /**
     * @brief Applies command-line arguments to configuration
     * @param config Configuration to update
     * @param args Parsed command-line arguments
     */
    static void apply_command_line_args(AppConfig& config, const cxxopts::ParseResult& args);
    /**
     * @brief Validates configuration completeness
     * @param config Configuration to validate
     * @throws std::runtime_error if validation fails
     */
    static void validate_config(const AppConfig& config);

private:
    /**
     * @brief Resolves and validates file paths
     * @param path Input path to resolve
     * @param verify_exists Check if path exists
     * @return Absolute filesystem path
     * @throws std::runtime_error if verification fails
     */
    static std::filesystem::path resolve_path(const std::string& path, bool verify_exists = true);
};

} // namespace app::config
