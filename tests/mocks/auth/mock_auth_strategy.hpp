#pragma once
#include "keycloak/types.hpp"
#include "keycloak/auth/strategy.hpp"

namespace keycloak::test {

class MockAuthStrategy : public auth::IAuthenticationStrategy {
public:
    explicit MockAuthStrategy(const config::CookieConfig& cookie_config)
        : cookie_config_(cookie_config) {}

    std::string create_authorization_url() override {
        return "https://mock.auth.url?"
               "response_type=code&"
               "client_id=test-client&"
               "redirect_uri=https://client.local/callback&"
               "state=mock_state&"
               "code_challenge=mock_challenge&"
               "code_challenge_method=S256&"
               "scope=openid";
    }

    TokenResponse handle_callback(
        std::string_view code, 
        std::string_view state) override {
        TokenResponse response;
        
        if (state == "mock_state" && code == "valid_code") {
            response.access_token = "mock_access";
            response.refresh_token = "mock_refresh";
            response.id_token = "mock_id";
            response.token_type = "Bearer";
            response.expires_in = 300;  // 5 minutes
            response.refresh_expires_in = 1800;  // 30 minutes
            return response;
        }

        response.error = "invalid_grant";
        response.error_description = "Invalid state or code";
        return response;
    }

    bool validate_session(
        const std::unordered_map<std::string, std::string>& cookies) override {
        auto it = cookies.find(cookie_config_.access_token_name);
        if (it == cookies.end()) return false;
        return it->second == "mock_access"; // Only validate against the mock token
    }

    const config::CookieConfig& get_cookie_config() const override {
        return cookie_config_;
    }

private:
    config::CookieConfig cookie_config_;
};

} // namespace keycloak::test
