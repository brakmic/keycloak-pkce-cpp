#include <ranges>
#include "config_loader.hpp"

namespace app::config {

std::filesystem::path ConfigLoader::resolve_path(const std::string& path, bool verify_exists) {
    std::filesystem::path resolved_path(path);
    
    if (!resolved_path.is_absolute()) {
        resolved_path = std::filesystem::current_path() / resolved_path;
    }
    
    if (verify_exists && !std::filesystem::exists(resolved_path)) {
        throw std::runtime_error("Path does not exist: " + resolved_path.string());
    }
    
    return resolved_path;
}

AppConfig ConfigLoader::load_from_file(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("Configuration file not found: " + path.string());
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open configuration file: " + path.string());
    }

    try {
        nlohmann::json j;
        file >> j;
        return j.get<AppConfig>();
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse configuration file: " + std::string(e.what()));
    }
}

AppConfig ConfigLoader::load_from_env() {
    AppConfig config;
    
    if (auto val = std::getenv("SERVER_PROTOCOL")) 
        config.server.protocol = val;
    if (auto val = std::getenv("SERVER_HOST")) 
        config.server.host = val;
    if (auto val = std::getenv("SERVER_PORT")) 
        config.server.port = std::stoi(val);
    if (auto val = std::getenv("SERVER_SSL_CERT")) 
        config.server.ssl.cert_path = val;
    if (auto val = std::getenv("SERVER_SSL_KEY")) 
        config.server.ssl.key_path = val;
    if (auto val = std::getenv("SERVER_SSL_VERIFY")) 
        config.server.ssl.verify_peer = (std::string(val) == "true");

    if (auto val = std::getenv("PROXY_HOST")) 
        config.proxy.host = val;
    if (auto val = std::getenv("PROXY_PORT")) 
        config.proxy.port = std::stoi(val);

    if (auto val = std::getenv("AUTH_REDIRECT_URI")) 
        config.auth.redirect_uri = val;

    if (auto val = std::getenv("LOG_APP_LEVEL")) 
        config.logging.app_level = val;
    if (auto val = std::getenv("LOG_CROW_LEVEL")) 
        config.logging.crow_level = val;
    if (auto val = std::getenv("LOG_CONSOLE")) 
        config.logging.console_logging = (std::string(val) == "true");
    if (auto val = std::getenv("LOG_PATTERN")) 
        config.logging.log_pattern = val;

    return config;
}

void ConfigLoader::merge(AppConfig& target, const AppConfig& source) {
    if (!source.server.protocol.empty()) target.server.protocol = source.server.protocol;
    if (!source.server.host.empty()) target.server.host = source.server.host;
    if (source.server.port != 0) target.server.port = source.server.port;
    if (!source.server.ssl.cert_path.empty()) 
        target.server.ssl.cert_path = source.server.ssl.cert_path;
    if (!source.server.ssl.key_path.empty()) 
        target.server.ssl.key_path = source.server.ssl.key_path;
    
    if (!source.proxy.host.empty()) target.proxy.host = source.proxy.host;
    if (source.proxy.port != 0) target.proxy.port = source.proxy.port;
    
    if (!source.auth.redirect_uri.empty()) target.auth.redirect_uri = source.auth.redirect_uri;
    
    if (!source.logging.app_level.empty()) target.logging.app_level = source.logging.app_level;
    if (!source.logging.crow_level.empty()) target.logging.crow_level = source.logging.crow_level;
    target.logging.console_logging = source.logging.console_logging;
    if (!source.logging.log_pattern.empty()) 
        target.logging.log_pattern = source.logging.log_pattern;
}

void ConfigLoader::apply_command_line_args(AppConfig& config, const cxxopts::ParseResult& args) {
    if (args.count("host")) config.server.host = args["host"].as<std::string>();
    if (args.count("port")) config.server.port = args["port"].as<uint16_t>();
    if (args.count("protocol")) config.server.protocol = args["protocol"].as<std::string>();
    if (args.count("log-level") && !args["log-level"].as<std::string>().empty())
        config.logging.app_level = args["log-level"].as<std::string>();
    if (args.count("crow-log-level") && !args["crow-log-level"].as<std::string>().empty())
        config.logging.crow_level = args["crow-log-level"].as<std::string>();
    if (args.count("disable-logging"))
        config.logging.console_logging = !args["disable-logging"].as<bool>();
}

void ConfigLoader::validate_config(const AppConfig& config) {
    if (config.server.protocol != "http" && config.server.protocol != "https") {
        throw std::runtime_error("Server protocol must be 'http' or 'https'");
    }

    if (config.server.protocol == "https") {
        if (config.server.ssl.cert_path.empty()) {
            throw std::runtime_error("SSL certificate path required for HTTPS");
        }
        if (config.server.ssl.key_path.empty()) {
            throw std::runtime_error("SSL key path required for HTTPS");
        }
    }

    if (!config.proxy.host.empty() && config.proxy.port == 0) {
        throw std::runtime_error("Proxy port must be specified when host is set");
    }

    if (config.auth.redirect_uri.empty()) {
        throw std::runtime_error("Redirect URI is required");
    }

    const std::vector<std::string> valid_levels = {
        "trace", "debug", "info", "warning", "error", "critical"
    };
    
    if (!std::ranges::contains(valid_levels, config.logging.app_level)) {
        throw std::runtime_error("Invalid application log level: " + config.logging.app_level);
    }

    if (!std::ranges::contains(valid_levels, config.logging.crow_level)) {
        throw std::runtime_error("Invalid Crow log level: " + config.logging.crow_level);
    }
}

} // namespace app::config
