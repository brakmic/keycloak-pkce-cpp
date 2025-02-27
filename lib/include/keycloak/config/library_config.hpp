/**
 * @file library_config.hpp
 * @brief Core Configuration Structures for Keycloak PKCE Library
 * @version 1.0
 * 
 * Defines the configuration structures and types used throughout the library.
 * Includes JSON serialization support, duration handling, and comprehensive
 * configuration options for Keycloak authentication, PKCE flow, cookies,
 * and state management.
 */

#pragma once
#include <string>
#include <chrono>
#include <nlohmann/json.hpp>
#include <fmt/format.h>

namespace keycloak::config {

/**
 * @brief Duration type with chrono integration and JSON serialization
 * 
 * Wraps std::chrono::seconds with JSON serialization support and
 * implicit conversion capabilities for seamless integration with
 * configuration parsing.
 */
class Duration {
private:
    int64_t seconds_{0};

public:
    Duration() = default;
    /**
     * @brief Constructs duration from seconds
     * @param seconds Number of seconds
     */
    Duration(int64_t seconds) : seconds_(seconds) {}
    
    /**
     * @brief Implicit conversion to std::chrono::seconds
     * @return Chrono duration equivalent
     */
    operator std::chrono::seconds() const { 
        return std::chrono::seconds(seconds_); 
    }

    /**
     * @brief Explicit conversion to chrono duration
     * @return std::chrono::seconds representation
     */
    std::chrono::seconds to_duration() const { 
        return std::chrono::seconds(seconds_); 
    }
    
    /**
     * @brief Returns raw second count for serialization
     * @return Number of seconds as int64_t
     */
    int64_t count() const { return seconds_; }
};

// Validation and conversion
inline std::chrono::seconds to_chrono(Duration seconds) {
    return std::chrono::seconds(seconds);
}

inline void to_json(nlohmann::json& j, const Duration& d) {
    j = d;
}

inline void from_json(const nlohmann::json& j, Duration& d) {
    if (j.is_number()) {
        d = j.get<int64_t>();
    } else if (j.is_string()) {
        d = std::stoll(j.get<std::string>());
    } else {
        throw std::invalid_argument("Duration must be integer or string");
    }
}

/**
 * @brief SSL/TLS Configuration
 * 
 * Defines SSL verification and certificate settings for secure
 * communication with Keycloak server.
 */
struct SSLConfig {
    bool verify_peer{false};    ///< Enable peer certificate verification
    std::string ca_cert_path;   ///< Path to CA certificate file

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SSLConfig, 
        verify_peer, ca_cert_path)
};

/**
 * @brief PKCE State Store Configuration
 * 
 * Controls the behavior of the PKCE state store, including
 * security settings and resource limitations.
 */
struct StateStoreConfig {
    Duration expiry_duration{300};                  ///< State token expiry (seconds)
    bool enable_cryptographic_verification{true};   ///< Enable crypto verification   
    size_t max_entries{1000};                       ///< Maximum stored states        

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(StateStoreConfig,
        expiry_duration,
        enable_cryptographic_verification,
        max_entries)
};

/**
 * @brief Cookie Management Configuration
 * 
 * Defines settings for secure cookie handling including
 * security flags and token naming.
 */
struct CookieConfig {
    std::string path{"/"};                              ///< Cookie path
    bool http_only{true};                               ///< HttpOnly flag
    bool secure{true};                                  ///< Secure flag
    std::string domain;                                 ///< Cookie domain
    std::string same_site{"Lax"};                       ///< SameSite attribute
    int max_age{3600};                                  ///< Cookie lifetime (seconds)
    std::string access_token_name{"access_token"};      ///< Access token cookie name
    std::string refresh_token_name{"refresh_token"};    ///< Refresh token cookie name
    std::string id_token_name{"id_token"};              ///< ID token cookie name

    /**
     * @brief Generates cookie attributes string
     * @return Formatted cookie attributes for HTTP header
     */
    std::string get_attributes() const {
        return fmt::format(
            "; Path={}; Domain={}; Max-Age={}; SameSite={}{}{}",
            path, domain, max_age, same_site,
            secure ? "; Secure" : "",
            http_only ? "; HttpOnly" : ""
        );
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(CookieConfig,
        path, http_only, secure, domain, same_site, max_age,
        access_token_name, refresh_token_name, id_token_name)
};

/**
 * @brief Keycloak Server Configuration
 * 
 * Defines connection and authentication parameters for
 * the Keycloak server instance.
 */
struct KeycloakConfig {
    std::string protocol{"https"};      ///< Protocol (https/http)
    std::string host;                   ///< Keycloak server hostname
    uint16_t port{443};                 ///< Server port
    std::string realm;                  ///< Keycloak realm name
    std::string client_id;              ///< OAuth2 client ID
    std::vector<std::string> scopes{    ///< OAuth2 scopes
        "openid", "email", "profile"
    };
    SSLConfig ssl;                      ///< SSL configuration

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(KeycloakConfig,
        protocol, host, port, realm, client_id, scopes, ssl)
};

/**
 * @brief PKCE Flow Configuration
 * 
 * Groups PKCE-specific settings including state management
 * and cookie handling.
 */
struct PKCEConfig {
    StateStoreConfig state_store;   ///< State store settings
    CookieConfig cookies;           ///< Cookie settings

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(PKCEConfig,
        state_store, cookies)
};

/**
 * @brief Root Configuration Structure
 * 
 * Top-level configuration container combining all settings
 * for the Keycloak PKCE library.
 */
struct LibraryConfig {
    KeycloakConfig keycloak;    ///< Keycloak settings
    PKCEConfig pkce;            ///< PKCE settings

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(LibraryConfig,
        keycloak, pkce)
};

} // namespace keycloak::config
