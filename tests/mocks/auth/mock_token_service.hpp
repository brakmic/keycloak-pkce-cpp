#pragma once
#include "keycloak/auth/token_service.hpp"

namespace keycloak::test {

class MockTokenService : public auth::ITokenService {
public:
    explicit MockTokenService(const config::KeycloakConfig& config)
        : config_(config), scopes_(config.scopes) {}

    std::string get_authorization_endpoint() const override {
        return "https://mock.auth/realms/" + config_.realm + "/protocol/openid-connect/auth";
    }

    const std::vector<std::string>& get_scopes() const override {
        return scopes_;
    }

    TokenResponse exchange_code(
        std::string_view code [[maybe_unused]],
        std::string_view code_verifier [[maybe_unused]],
        std::string_view redirect_uri [[maybe_unused]],
        std::string_view client_id [[maybe_unused]]) override {
        TokenResponse response;
        response.access_token = "mock_access";
        response.refresh_token = "mock_refresh";
        response.id_token = "mock_id";
        response.token_type = "Bearer";
        response.expires_in = 300;  // 5 minutes
        response.refresh_expires_in = 1800;  // 30 minutes
        response.error = "";  // No error
        response.error_description = "";
        return response;
    }

private:
    const config::KeycloakConfig& config_;
    std::vector<std::string> scopes_;
};

} // namespace keycloak::test
