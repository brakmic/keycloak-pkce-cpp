#include <stdexcept>
#include "kc_pkce.h"
#include "config_wrapper.hpp"
#include "keycloak/config/config_loader.hpp"

namespace keycloak::c_api {

ConfigWrapper::ConfigWrapper() = default;

void ConfigWrapper::load_from_file(const std::string& path) {
    config_ = config::ConfigLoader::load_from_file(path);
}

void ConfigWrapper::set_keycloak_config(const kc_pkce_keycloak_config_t* config) {
    if (!config) {
        throw std::invalid_argument("Invalid Keycloak config");
    }
    
    auto& kc = config_.keycloak;
    kc.protocol = config->protocol ? config->protocol : "https";
    kc.host = config->host ? config->host : "";
    kc.port = config->port;
    kc.realm = config->realm ? config->realm : "";
    kc.client_id = config->client_id ? config->client_id : "";
    
    // Handle scopes:
    // If no scopes provided, use C++ library defaults
    if (!config->scopes || config->scope_count == 0) {
        kc.scopes = {"openid", "email", "profile"};  // Default from C++ library
    } else {
        kc.scopes.clear();
        for (size_t i = 0; i < config->scope_count; ++i) {
            if (config->scopes[i]) {
                kc.scopes.push_back(config->scopes[i]);
            }
        }
    }
}

void ConfigWrapper::set_ssl_config(const kc_pkce_ssl_config_t* ssl_config) {
    if (!ssl_config) {
        throw std::invalid_argument("Invalid SSL config");
    }
    
    auto& ssl = config_.keycloak.ssl;
    ssl.verify_peer = ssl_config->verify_peer;
    ssl.ca_cert_path = ssl_config->ca_cert_path ? ssl_config->ca_cert_path : "";
}

} // namespace keycloak::c_api
