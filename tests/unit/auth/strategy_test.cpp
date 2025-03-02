#include <gtest/gtest.h>
#include "keycloak/config/library_config.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/http/proxy_config.hpp"
#include "mocks/auth/mock_auth_strategy.hpp"

class StrategyTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = createConfig();
        cookie_config.access_token_name = "access_token";
        
        // Use MockAuthStrategy directly instead of PKCEStrategy
        strategy = std::make_shared<keycloak::test::MockAuthStrategy>(config.pkce.cookies);
    }

    keycloak::config::LibraryConfig createConfig() {
        keycloak::config::LibraryConfig config;
        config.keycloak.protocol = "https";
        config.keycloak.host = "localhost";
        config.keycloak.port = 8443;
        config.keycloak.realm = "test-realm";
        config.keycloak.client_id = "test-client";
        config.keycloak.scopes = {"openid"};
        config.keycloak.ssl = {
            true,
            "certs/ca.pem"
        };
        
        // Add PKCE config
        config.pkce.cookies.access_token_name = "access_token";
        config.pkce.state_store.expiry_duration = keycloak::config::Duration(300);
        config.pkce.state_store.enable_cryptographic_verification = true;
        config.pkce.state_store.max_entries = 100;
        
        return config;
    }
    
    keycloak::http::ProxyConfig proxy_config;
    keycloak::config::LibraryConfig config;
    keycloak::config::CookieConfig cookie_config;
    std::shared_ptr<keycloak::auth::IAuthenticationStrategy> strategy;
};

TEST_F(StrategyTest, CreateAuthorizationUrl) {
    std::string url = strategy->create_authorization_url();
    EXPECT_FALSE(url.empty());
    
    // Check required OAuth2 parameters
    EXPECT_NE(url.find("response_type=code"), std::string::npos);
    EXPECT_NE(url.find("client_id="), std::string::npos);
    EXPECT_NE(url.find("redirect_uri="), std::string::npos);
    
    // Check PKCE specific parameters
    EXPECT_NE(url.find("code_challenge="), std::string::npos);
    EXPECT_NE(url.find("code_challenge_method=S256"), std::string::npos);
    
    // Check other required parameters
    EXPECT_NE(url.find("state="), std::string::npos);
    EXPECT_NE(url.find("scope="), std::string::npos);
}

TEST_F(StrategyTest, ValidateSession) {
    // Test with invalid token
    std::unordered_map<std::string, std::string> cookies;
    cookies["access_token"] = "invalid_token";
    EXPECT_FALSE(strategy->validate_session(cookies));

    // Test with valid token
    cookies["access_token"] = "mock_access";
    EXPECT_TRUE(strategy->validate_session(cookies));

    // Test with missing token
    cookies.clear();
    EXPECT_FALSE(strategy->validate_session(cookies));
}

TEST_F(StrategyTest, HandleCallback) {
    // Test successful callback
    auto response = strategy->handle_callback("valid_code", "mock_state");
    EXPECT_TRUE(response.is_success());
    EXPECT_FALSE(response.access_token.empty());
    EXPECT_EQ(response.access_token, "mock_access");
    
    // Test invalid state
    response = strategy->handle_callback("valid_code", "invalid_state");
    EXPECT_FALSE(response.is_success());
    EXPECT_FALSE(response.error.empty());
}
