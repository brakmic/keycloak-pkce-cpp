#include <gtest/gtest.h>
#include "keycloak/auth/token_service.hpp"
#include "keycloak/config/library_config.hpp"
#include "mocks/auth/mock_token_service.hpp"

class TokenServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = {
            "https",        // protocol
            "localhost",    // host
            8443,          // port
            "test-realm",  // realm
            "test-client", // client_id
            {"openid"},    // scopes
            keycloak::config::SSLConfig{
                true,
                "certs/ca.pem"
            }
        };
        
        token_service = std::make_shared<keycloak::test::MockTokenService>(config);
    }

    keycloak::config::KeycloakConfig config;
    std::shared_ptr<keycloak::auth::ITokenService> token_service;
};

TEST_F(TokenServiceTest, GetAuthorizationEndpoint) {
    std::string endpoint = token_service->get_authorization_endpoint();
    EXPECT_FALSE(endpoint.empty());
    EXPECT_NE(endpoint.find("/realms/test-realm"), std::string::npos);
    EXPECT_NE(endpoint.find("/protocol/openid-connect/auth"), std::string::npos);
}

TEST_F(TokenServiceTest, GetScopes) {
    const auto& scopes = token_service->get_scopes();
    EXPECT_FALSE(scopes.empty());
    EXPECT_EQ(scopes[0], "openid");
}
