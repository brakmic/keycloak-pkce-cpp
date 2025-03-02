#include <gtest/gtest.h>
#include "keycloak/keycloak_client.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/http/proxy_config.hpp"

class TokenExchangeTest : public ::testing::Test {
protected:
    void SetUp() override {
        keycloak::config::KeycloakConfig config;
        config.protocol = "https";
        config.host = "keycloak.local.com";
        config.port = 9443;
        config.realm = "TestRealm";
        config.client_id = "test-client";
        config.scopes = {"openid", "profile", "email"};
        
        config.ssl.verify_peer = true;
        config.ssl.ca_cert_path = "certs/ca.pem";

        proxy_config_.host = "host.docker.internal";
        proxy_config_.port = 9443;

        token_service_ = std::make_shared<keycloak::KeycloakClient>(
            config, proxy_config_, nullptr);
    }

    keycloak::http::ProxyConfig proxy_config_;
    std::shared_ptr<keycloak::auth::ITokenService> token_service_;
};

TEST_F(TokenExchangeTest, InvalidCodeExchange) {
    const std::string invalid_code = "invalid_code";
    const std::string code_verifier = "test_verifier";
    const std::string redirect_uri = "https://pkce-client.local.com:18080/callback";
    const std::string client_id = "test-client";

    auto result = token_service_->exchange_code(
        invalid_code, code_verifier, redirect_uri, client_id);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_FALSE(result.error.empty());
}
