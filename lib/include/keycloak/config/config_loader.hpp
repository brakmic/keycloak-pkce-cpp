/**
 * @file config_loader.hpp
 * @brief Configuration Loader for Keycloak PKCE Library
 * @version 1.0
 * 
 * Provides functionality to load and validate JSON configuration files for the Keycloak PKCE library.
 * Handles parsing of authentication settings, PKCE parameters, state store configuration,
 * and cookie settings.
 */

#pragma once
#include <filesystem>
#include <fstream>
#include "keycloak/config/library_config.hpp"
#include "keycloak/utils/logging.hpp"

namespace keycloak::config {

class ConfigLoader {
public:
    /**
     * @brief Loads and validates library configuration from a JSON file
     * @param path Filesystem path to the configuration file
     * @return Validated LibraryConfig instance
     * @throws std::runtime_error if file not found, cannot be opened, or contains invalid configuration
     * @throws nlohmann::json::exception if JSON parsing fails
     * 
     * Expected JSON structure:
     * {
     *   "keycloak": {
     *     "host": "required",
     *     "realm": "required",
     *     "client_id": "required"
     *   },
     *   "pkce": {
     *     "cookies": {},
     *     "state_store": {
     *       "expiry_duration": required,
     *       "enable_cryptographic_verification": required,
     *       "max_entries": required
     *     }
     *   }
     * }
     */
    static LibraryConfig load_from_file(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) {
            throw std::runtime_error("Library configuration file not found: " + path.string());
        }

        std::ifstream file(path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open library config: " + path.string());
        }

        try {
            nlohmann::json j;
            file >> j;
            validate_config(j);
            return j.get<LibraryConfig>();
        } catch (const nlohmann::json::exception& e) {
            throw std::runtime_error("Failed to parse library config: " + std::string(e.what()));
        }
    }

private:
/**
    * @brief Validates the structure and required fields of the configuration JSON
    * @param j JSON object containing the configuration
    * @throws std::runtime_error if required sections or fields are missing
    * 
    * Validates:
    * - Presence of keycloak and pkce sections
    * - Required keycloak fields (host, realm, client_id)
    * - Required pkce subsections (cookies, state_store)
    * - Required state_store parameters
    */
  static void validate_config(const nlohmann::json& j) {
      if (!j.contains("keycloak")) {
          throw std::runtime_error("Missing 'keycloak' section");
      }
      if (!j.contains("pkce")) {
          throw std::runtime_error("Missing 'pkce' section");
      }

      const auto& k = j["keycloak"];
      if (!k.contains("host") || k["host"].empty()) {
          throw std::runtime_error("Keycloak host cannot be empty");
      }
      if (!k.contains("realm") || k["realm"].empty()) {
          throw std::runtime_error("Keycloak realm cannot be empty");
      }
      if (!k.contains("client_id") || k["client_id"].empty()) {
          throw std::runtime_error("Keycloak client_id cannot be empty");
      }

      const auto& p = j["pkce"];
      if (!p.contains("cookies")) {
          throw std::runtime_error("Missing 'pkce.cookies' section");
      }
      if (!p.contains("state_store")) {
          throw std::runtime_error("Missing 'pkce.state_store' section");
      }
      const auto& s = p["state_store"];
      if (!s.contains("expiry_duration")) {
          throw std::runtime_error("Missing 'pkce.state_store.expiry_duration'");
      }
      if (!s.contains("enable_cryptographic_verification")) {
          throw std::runtime_error("Missing 'pkce.state_store.enable_cryptographic_verification'");
      }
      if (!s.contains("max_entries")) {
          throw std::runtime_error("Missing 'pkce.state_store.max_entries'");
      }
  }
};

} // namespace keycloak::config
