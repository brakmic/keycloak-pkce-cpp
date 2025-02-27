#ifndef APP_SETTINGS_H
#define APP_SETTINGS_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Server configuration
 */
struct ServerConfig {
    const char* protocol;
    const char* host;
    uint16_t port;
};

/**
 * @brief Proxy configuration
 */
struct ProxyConfig {
    const char* host;
    uint16_t port;
};

/**
 * @brief Authentication configuration
 */
struct AuthConfig {
    const char* redirect_uri;
};

/**
 * @brief Logging configuration
 */
struct LogConfig {
    const char* app_level;
    bool console_logging;
    const char* log_pattern;
};

/**
 * @brief Path configuration
 */
struct PathConfig {
    const char* library_config;    // Path to library_config.json
    const char* civetweb_config;   // Path to civetweb.conf
};

/**
 * @brief Main application settings
 */
struct AppSettings {
    struct ServerConfig server;
    struct ProxyConfig proxy;
    struct AuthConfig auth;
    struct LogConfig logging;
    struct PathConfig paths;
};

/**
 * @brief Default application settings
 */
static const struct AppSettings DEFAULT_APP_SETTINGS = {
    .server = {
        .protocol = "https",
        .host = "localhost",
        .port = 18080
    },
    .proxy = {
        .host = "host.docker.internal",
        .port = 9443
    },
    .auth = {
        .redirect_uri = "https://pkce-client.local.com:18080/auth/keycloak/callback"
    },
    .logging = {
        .app_level = "debug",
        .console_logging = true,
        .log_pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v"
    },
    .paths = {
        // assume demo is in ./build/c/bin/pkce_demo_c
        // check scripts/setup_c_env.sh
        .library_config = "../config/library_config.json",
        .civetweb_config = "../config/civetweb.conf"
    }
};

#endif // APP_SETTINGS_H
