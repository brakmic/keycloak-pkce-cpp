#include <gtest/gtest.h>
#include "keycloak/auth/pkce_strategy.hpp"
#include "keycloak/config/library_config.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/keycloak_client.hpp"
#include "mocks/auth/mock_auth_strategy.hpp"

class StrategyTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = createConfig();
        cookie_config.access_token_name = "access_token";
        strategy = std::make_shared<keycloak::test::MockAuthStrategy>(cookie_config);
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
            true,               // verify_peer
            "certs/ca.pem"     // ca_cert_path
        };
        return config;
    }
    
    keycloak::http::HttpClient::ProxyConfig proxy_config;
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
    std::unordered_map<std::string, std::string> cookies;
    cookies["access_token"] = "invalid_token";
    EXPECT_FALSE(strategy->validate_session(cookies));
}
