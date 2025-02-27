#include "pkce_wrapper.hpp"
#include "proxy_settings.hpp"
#include "kc_pkce.h"
#include <stdexcept>

namespace keycloak::c_api {

PKCEWrapper::PKCEWrapper(const config::LibraryConfig& config)
    : config_(config)
{
    // Initialize proxy config from global settings
    http::HttpClient::ProxyConfig proxy_config;
    const auto& proxy_settings = ProxySettings::instance();
    
    if (!proxy_settings.get_host().empty()) {
        proxy_config.host = proxy_settings.get_host();
        proxy_config.port = proxy_settings.get_port();
    }

    client_ = KeycloakClient::create(
        config_.keycloak,
        proxy_config,
        nullptr
    );
}

void PKCEWrapper::set_redirect_uri(const std::string& uri) {
    redirect_uri_ = uri;
    strategy_ = auth::PKCEStrategy::create(
        client_,
        config_.keycloak.client_id,
        redirect_uri_,
        config_.pkce
    );
}

std::string PKCEWrapper::create_authorization_url() {
    if (!strategy_) {
        throw std::runtime_error("Strategy not initialized - set redirect URI first");
    }
    return strategy_->create_authorization_url();
}

TokenResponse PKCEWrapper::handle_callback(
    std::string_view code, 
    std::string_view state)
{
    if (!strategy_) {
        throw std::runtime_error("Strategy not initialized");
    }
    return strategy_->handle_callback(code, state);
}

bool PKCEWrapper::validate_session(const std::string& access_token) {
    if (!strategy_) return false;
    
    cookies_[config_.pkce.cookies.access_token_name] = access_token;
    return strategy_->validate_session(cookies_);
}

void PKCEWrapper::update_cookies(const char* name, const char* value) {
    if (name && value) {
        cookies_[name] = value;
    }
}

} // namespace keycloak::c_api
