#pragma once
#include "keycloak/http/http_client.hpp"
#include <unordered_map>
#include <string>
#include <utility>
#include <vector>

namespace keycloak::test {

class MockHttpClient {
public:
    static http::HttpClient::Response post(
        const std::string& host [[maybe_unused]],
        const std::string& port [[maybe_unused]],
        const std::string& path [[maybe_unused]],
        const std::string& body [[maybe_unused]],
        const std::unordered_map<std::string, std::string>& headers [[maybe_unused]],
        const http::HttpClient::SSLConfig& ssl_config [[maybe_unused]],
        const http::HttpClient::ProxyConfig& proxy_config [[maybe_unused]]
    ) {
        if (host == "httpbin.org") {
            http::HttpClient::Response response;
            response.status_code = 200;
            response.body = "{\"success\":true}";
            response.headers = {{"Content-Type", "application/json"}};
            return response;
        }

        http::HttpClient::Response response;
        response.status_code = 500;
        response.body = "Host not found";
        response.headers = {};
        return response;
    }
};

} // namespace keycloak::test
