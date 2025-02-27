/**
 * @file main.cpp
 * @brief C++ Demo Application for Keycloak PKCE Authentication
 * @version 1.0
 * 
 * Demonstrates OAuth2 PKCE authentication flow with Keycloak using the Crow web framework.
 * Features:
 * - HTTPS/HTTP server support
 * - Command-line configuration
 * - Environment variable support
 * - Secure session management
 * - Protected route demonstration
 */

#include <memory>
#include <string>
#include <vector>
// #include <asio.hpp>
// #include <nlohmann/json.hpp>
#include <csignal>
#include <cxxopts.hpp>
#include <crow.h>
#include <sstream>

#include "app_context.hpp"
#include "routes/routes.hpp"
#include "config/config_loader.hpp"
#include "keycloak/config/config_loader.hpp"
#include "keycloak/utils/logging.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/utils/url_encode.hpp"

namespace kc = keycloak;
namespace kc_auth = keycloak::auth;
namespace kc_http = keycloak::http;
namespace app_cfg = app::config;
namespace kc_cfg = keycloak::config;
namespace lg = logging;

// Global instance
crow::SimpleApp* p_app = nullptr;

/**
 * @brief Signal handler for graceful shutdown
 * @param signum Signal number (SIGINT/SIGTERM)
 * 
 * Ensures clean shutdown of Crow web server on signal reception
 */
void signal_handler(int signum) {
    if (p_app) {
        lg::Logger::info("Received signal {}. Shutting down...", signum);
        p_app->stop();
    }
}

/**
 * @brief Sets security headers for HTTP responses
 * @param resp Crow response object to modify
 * 
 * Applies security best practices:
 * - Cache control headers
 * - XSS protection
 * - Frame options
 * - Content type options
 */
void set_security_headers(crow::response& resp) {
    resp.set_header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
    resp.set_header("Pragma", "no-cache");
    resp.set_header("Expires", "0");
    resp.set_header("X-Content-Type-Options", "nosniff");
    resp.set_header("X-Frame-Options", "DENY");
    resp.set_header("X-XSS-Protection", "1; mode=block");
}

/**
 * @brief Converts string log level to Crow log level enum
 * @param level String representation of log level
 * @return Corresponding Crow LogLevel
 */
crow::LogLevel convertToCrowLogLevel(const std::string& level) {
    static const std::unordered_map<std::string, crow::LogLevel> levels = {
        {"trace", crow::LogLevel::Debug},
        {"debug", crow::LogLevel::Debug},
        {"info", crow::LogLevel::Info},
        {"warning", crow::LogLevel::Warning},
        {"error", crow::LogLevel::Error},
        {"critical", crow::LogLevel::Critical}
    };
    return levels.count(level) ? levels.at(level) : crow::LogLevel::Info;
}

/**
 * @brief Main application entry point
 * 
 * Application flow:
 * 1. Parse command line arguments
 * 2. Load and validate configurations
 * 3. Initialize logging
 * 4. Set up PKCE authentication
 * 5. Configure routes:
 *    - /auth/keycloak: Initiates authentication
 *    - /auth/keycloak/callback: Handles OAuth callback
 *    - /protected: Secured resource
 *    - /auth/error: Error handling
 * 6. Start web server
 */
int main(int argc, char** argv) {
    try {
        // Parse command line options
        cxxopts::Options options("KeycloakPKCEDemo", "Keycloak PKCE authentication demo");
        options.add_options()
            ("c,config", "Path to configuration file", 
             cxxopts::value<std::string>()->default_value("../config/app_config.json"))
            ("k,keycloak-config", "Path to Keycloak configuration file",
             cxxopts::value<std::string>()->default_value("../config/library_config.json"))
            ("l,log-level", "Log level", cxxopts::value<std::string>())
            ("crow-log-level", "Crow log level", cxxopts::value<std::string>())
            ("d,disable-logging", "Disable all logging", 
             cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");

        auto args = options.parse(argc, argv);
        if (args.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // Load configurations
        auto app_config = app_cfg::ConfigLoader::load_from_file(
            args["config"].as<std::string>());
        auto lib_config = kc_cfg::ConfigLoader::load_from_file(
            args["keycloak-config"].as<std::string>());

        // Load environment variables and merge
        auto env_config = app_cfg::ConfigLoader::load_from_env();
        app_cfg::ConfigLoader::merge(app_config, env_config);

        // Apply command line arguments
        app_cfg::ConfigLoader::apply_command_line_args(app_config, args);

        // Initialize logging
        lg::Logger::init(app_config.logging.log_pattern);
        lg::Logger::setLevel(lg::Logger::fromString(app_config.logging.app_level));

        // Validate configurations
        lg::Logger::debug("Validating configurations...");
        app_cfg::ConfigLoader::validate_config(app_config);

        // Convert app proxy config to http client proxy config
        kc_http::HttpClient::ProxyConfig http_proxy_config;
        http_proxy_config.host = app_config.proxy.host;
        http_proxy_config.port = app_config.proxy.port;

        // Initialize authentication strategy
        auto auth_strategy = kc::KeycloakClient::create_pkce_strategy(
            lib_config,
            http_proxy_config,
            app_config.auth.redirect_uri,
            [](std::string_view level, std::string_view message) {
                lg::Logger::debug("[Keycloak] {}: {}", level, message);
            }
        );

        // Create application context
        auto app_context = std::make_shared<ApplicationContext>(auth_strategy);

        // Initialize Crow
        crow::SimpleApp app;
        p_app = &app;

        // Set up signal handling
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Configure routes
        app::routes::configure_routes(app, app_context);

        // Configure Crow logging
        app.loglevel(convertToCrowLogLevel(app_config.logging.crow_level));

        // Start server
        lg::Logger::info("Starting server on {}:{}", 
            app_config.server.host, app_config.server.port);

        if (app_config.server.protocol == "https") {
            app.ssl_file(
                app_config.server.ssl.cert_path,
                app_config.server.ssl.key_path
            );
        }

        app.bindaddr(app_config.server.host)
           .port(app_config.server.port)
           .run();

        return 0;

    } catch (const std::exception& e) {
        lg::Logger::critical("Fatal error: {}", e.what());
        return 1;
    }
}
