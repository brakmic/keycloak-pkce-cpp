#include <gtest/gtest.h>
#include "keycloak/http/http_client.hpp"

class HttpClientTest : public ::testing::Test {
protected:
    keycloak::http::HttpClient::SSLConfig ssl_config;
    keycloak::http::HttpClient::ProxyConfig proxy_config;
};

TEST_F(HttpClientTest, BasicPostRequest) {
    auto response = keycloak::http::HttpClient::post(
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
}

TEST_F(HttpClientTest, InvalidHost) {
    auto response = keycloak::http::HttpClient::post(
        "invalid.host.local",
        "443",
        "/",
        "",
        {},
        ssl_config,
        proxy_config
    );
    
    EXPECT_EQ(response.status_code, 500);
}
