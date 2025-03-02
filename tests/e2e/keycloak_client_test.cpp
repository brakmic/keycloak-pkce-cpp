#include <gtest/gtest.h>
#include <cpr/cpr.h>
#include <regex>
#include "keycloak/keycloak_client.hpp"
#include "keycloak/http/proxy_config.hpp"

class KeycloakClientE2ETest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.keycloak.protocol = "https";
        config_.keycloak.host = "keycloak.local.com";
        config_.keycloak.port = 9443;
        config_.keycloak.realm = "TestRealm";
        config_.keycloak.client_id = "test-client";
        config_.keycloak.scopes = {"openid", "profile", "email"};
        
        config_.keycloak.ssl.verify_peer = true;
        config_.keycloak.ssl.ca_cert_path = "certs/ca.pem";

        proxy_config_.host = "host.docker.internal";
        proxy_config_.port = 9443;

        redirect_uri_ = "https://pkce-client.local.com:18080/auth/keycloak/callback";
        strategy_ = keycloak::KeycloakClient::create_pkce_strategy(
            config_, proxy_config_, redirect_uri_);
    }

    // Parse callback URL helper method
    std::pair<std::string, std::string> parse_callback_url(const std::string& url) {
        std::regex code_regex("code=([^&]+)");
        std::regex state_regex("state=([^&]+)");

        std::smatch code_match, state_match;
        std::string code, state;

        if (std::regex_search(url, code_match, code_regex)) {
            code = code_match[1];
        }

        if (std::regex_search(url, state_match, state_regex)) {
            state = state_match[1];
        }

        return {code, state};
    }

    // Simulate user login helper method
    std::string simulate_user_login(const std::string& auth_url) {
        // Initialize session with SSL verification disabled for self-signed certs
        cpr::Session session;
        session.SetVerifySsl(false);
        session.SetUrl(cpr::Url{auth_url});

        // First request to get login form
        auto r = session.Get();
        if (r.status_code != 200) {
            return "";
        }

        // Extract CSRF token from the form
        std::regex csrf_regex("name=\"csrf\" value=\"([^\"]+)\"");
        std::smatch csrf_match;
        if (!std::regex_search(r.text, csrf_match, csrf_regex)) {
            return "";
        }
        std::string csrf_token = csrf_match[1];

        // Submit login form with CSRF token
        session.SetUrl(cpr::Url{r.url});
        session.SetPayload(cpr::Payload{
            {"username", "test-user"},
            {"password", "password"},
            {"csrf", csrf_token}
        });

        // Get the callback URL after successful login
        auto response = session.Post();
        if (response.status_code != 302) {
            return "";
        }

        return response.header["location"];
    }

    void TearDown() override {
        // Clean up any active sessions
        if (!strategy_->get_cookie_config().access_token_name.empty()) {
            std::unordered_map<std::string, std::string> cookies;
            strategy_->validate_session(cookies); // Force session cleanup
        }
    }

    keycloak::config::LibraryConfig config_;
    keycloak::http::ProxyConfig proxy_config_;
    std::string redirect_uri_;
    std::shared_ptr<keycloak::auth::IAuthenticationStrategy> strategy_;
};

TEST_F(KeycloakClientE2ETest, CompleteAuthenticationFlow) {
    // 1. Get authorization URL
    auto auth_url = strategy_->create_authorization_url();
    ASSERT_FALSE(auth_url.empty());
    ASSERT_TRUE(auth_url.find("response_type=code") != std::string::npos);
    ASSERT_TRUE(auth_url.find("client_id=test-client") != std::string::npos);

    // 2. Simulate user login and get callback URL
    auto callback_url = simulate_user_login(auth_url);
    ASSERT_FALSE(callback_url.empty());
    ASSERT_TRUE(callback_url.find("code=") != std::string::npos);
    ASSERT_TRUE(callback_url.find("state=") != std::string::npos);

    // 3. Extract code and state from callback URL
    auto [code, state] = parse_callback_url(callback_url);
    ASSERT_FALSE(code.empty());
    ASSERT_FALSE(state.empty());

    // 4. Handle callback
    auto tokens = strategy_->handle_callback(code, state);
    EXPECT_TRUE(tokens.is_success());
    EXPECT_FALSE(tokens.access_token.empty());
    EXPECT_FALSE(tokens.refresh_token.empty());
    EXPECT_FALSE(tokens.id_token.empty());

    // 5. Validate session
    std::unordered_map<std::string, std::string> cookies = {
        {strategy_->get_cookie_config().access_token_name, tokens.access_token}
    };
    EXPECT_TRUE(strategy_->validate_session(cookies));
}

TEST_F(KeycloakClientE2ETest, InvalidLoginCredentials) {
    auto auth_url = strategy_->create_authorization_url();
    ASSERT_FALSE(auth_url.empty());

    // Modify session to use wrong credentials
    cpr::Session session;
    session.SetVerifySsl(false);
    session.SetUrl(cpr::Url{auth_url});

    auto r = session.Get();
    ASSERT_EQ(r.status_code, 200);

    session.SetPayload(cpr::Payload{
        {"username", "wrong-user"},
        {"password", "wrong-password"}
    });

    auto response = session.Post();
    EXPECT_EQ(response.status_code, 401);
}

TEST_F(KeycloakClientE2ETest, InvalidStateParameter) {
    auto auth_url = strategy_->create_authorization_url();
    ASSERT_FALSE(auth_url.empty());

    auto callback_url = simulate_user_login(auth_url);
    ASSERT_FALSE(callback_url.empty());

    auto [code, _] = parse_callback_url(callback_url);
    ASSERT_FALSE(code.empty());

    // Try with invalid state
    auto tokens = strategy_->handle_callback(code, "invalid-state");
    EXPECT_FALSE(tokens.is_success());
}

TEST_F(KeycloakClientE2ETest, InvalidAccessToken) {
    std::unordered_map<std::string, std::string> cookies = {
        {strategy_->get_cookie_config().access_token_name, "invalid-token"}
    };
    EXPECT_FALSE(strategy_->validate_session(cookies));
}
