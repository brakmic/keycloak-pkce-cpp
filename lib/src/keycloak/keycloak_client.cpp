#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <sstream>
#include "keycloak/keycloak_client.hpp"
#include "keycloak/auth/pkce_strategy.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/utils/url_encode.hpp"
#include "keycloak/utils/logging.hpp"

namespace keycloak {

using json = nlohmann::json;
using namespace keycloak::logging;

// Helper function to convert config::SSLConfig to http::SSLConfig
http::SSLConfig convert_ssl_config(const config::SSLConfig& config) {
    http::SSLConfig http_config;
    http_config.verify_peer = config.verify_peer;
    http_config.ca_cert_path = config.ca_cert_path;

    // Add verbose logging
    Logger::debug("SSL Config: verify_peer={}, ca_cert_path=\"{}\"",
        http_config.verify_peer,
        http_config.ca_cert_path.empty() ? "<empty>" : http_config.ca_cert_path);

    return http_config;
}

void KeycloakClient::init_endpoints() {
    auth_endpoint_ = "/realms/" + realm_ + "/protocol/openid-connect/auth";
    token_endpoint_ = "/realms/" + realm_ + "/protocol/openid-connect/token";
}

void KeycloakClient::log(std::string_view level, std::string_view message) const {
    if (logger_) {
        logger_(level, message);
    }
}

TokenResponse KeycloakClient::exchange_code(
    std::string_view code,
    std::string_view code_verifier,
    std::string_view redirect_uri,
    std::string_view client_id)
{
    TokenResponse result{};

    try {
        // Convert SSL config and create HTTP client
        http::SSLConfig http_ssl_config = convert_ssl_config(ssl_config_);
        auto http_client = http::HttpClient::create_https_client(http_ssl_config, proxy_config_);

        std::ostringstream body;
        body << "grant_type=authorization_code"
             << "&client_id=" << url_encode(client_id)
             << "&code=" << url_encode(code)
             << "&redirect_uri=" << url_encode(redirect_uri)
             << "&code_verifier=" << url_encode(code_verifier);

        log("debug", fmt::format("Token request details:\n"
                               "- Endpoint: {}\n"
                               "- Host: {}\n"
                               "- Port: {}\n"
                               "- Body: {}",
                               token_endpoint_, host_,
                               std::to_string(port_), body.str()));

        std::unordered_map<std::string, std::string> headers;
        headers.emplace("Content-Type", "application/x-www-form-urlencoded");
        headers.emplace("Accept", "application/json");

        auto response = http_client->post(
            host_, 
            std::to_string(port_),
            token_endpoint_, 
            body.str(), 
            headers);

        log("debug", fmt::format("Token response:\n"
                               "- Status: {}\n"
                               "- Body: {}", response.status_code, response.body));

        if(response.status_code != 200) {
            try {
                auto error_json = nlohmann::json::parse(response.body);
                result.error = error_json.value("error", "unknown_error");
                result.error_description = error_json.value("error_description", "Unknown error");
            } catch(...) {
                result.error = "http_error";
                result.error_description = "Token exchange failed with status " + 
                    std::to_string(response.status_code);
            }
            return result;
        }

        auto json_response = nlohmann::json::parse(response.body);
        
        // Extract tokens from response
        result.access_token = json_response["access_token"].get<std::string>();
        result.refresh_token = json_response["refresh_token"].get<std::string>();
        result.id_token = json_response["id_token"].get<std::string>();
        result.token_type = json_response["token_type"].get<std::string>();
        result.expires_in = json_response["expires_in"].get<int>();
        result.refresh_expires_in = json_response["refresh_expires_in"].get<int>();

    } catch(const std::exception& e) {
        log("error", fmt::format("Exception during token exchange: {}", e.what()));
        result.error = "exception";
        result.error_description = std::string("Token exchange failed: ") + e.what();
    }

    return result;
}

std::shared_ptr<auth::IAuthenticationStrategy> KeycloakClient::create_pkce_strategy(
    const config::LibraryConfig& config,
    const http::ProxyConfig& proxy_config,
    std::string_view redirect_uri,
    LogCallback logger)
{
    auto token_service = KeycloakClient::create(config.keycloak, proxy_config, logger);

    return auth::PKCEStrategy::create(
        token_service,
        config.keycloak.client_id,
        redirect_uri,
        config.pkce
    );
}

} // namespace keycloak
