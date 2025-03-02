#include <gtest/gtest.h>
#include "keycloak/http/ssl_config.hpp"
#include "keycloak/http/proxy_config.hpp"
#include "mocks/http/mock_http_client.hpp"

class HttpClientTest : public ::testing::Test {
protected:
    keycloak::http::SSLConfig ssl_config;
    keycloak::http::ProxyConfig proxy_config;
};

TEST_F(HttpClientTest, BasicPostRequest) {
    auto response = keycloak::test::MockHttpClient::post(
        "httpbin.org",
        "443",
        "/post",
        "test=data",
        {{"Content-Type", "application/x-www-form-urlencoded"}},
        ssl_config,
        proxy_config
    );
    
    EXPECT_EQ(response.status_code, 200);
    EXPECT_FALSE(response.body.empty());
    EXPECT_EQ(response.headers.at("Content-Type"), "application/json");
}

TEST_F(HttpClientTest, InvalidHost) {
    auto response = keycloak::test::MockHttpClient::post(
        "invalid.host.local",
        "443",
        "/",
        "",
        {},
        ssl_config,
        proxy_config
    );
    
    EXPECT_EQ(response.status_code, 500);
    EXPECT_EQ(response.body, "Host not found");
}
