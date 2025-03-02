#pragma once
#include "keycloak/http/http_client.hpp"
#include "keycloak/http/ssl_config.hpp"
#include "keycloak/http/proxy_config.hpp"
#include <unordered_map>
#include <string>
#include <utility>
#include <vector>

namespace keycloak::test {

class MockHttpClient {
public:
    static http::Response post(
        const std::string& host [[maybe_unused]],
        const std::string& port [[maybe_unused]],
        const std::string& path [[maybe_unused]],
        const std::string& body [[maybe_unused]],
        const std::unordered_map<std::string, std::string>& headers [[maybe_unused]],
        const http::SSLConfig& ssl_config [[maybe_unused]],
        const http::ProxyConfig& proxy_config [[maybe_unused]]
    ) {
        if (host == "httpbin.org") {
            http::Response response;
            response.status_code = 200;
            response.body = "{\"success\":true}";
            response.headers = {{"Content-Type", "application/json"}};
            return response;
        }

        http::Response response;
        response.status_code = 500;
        response.body = "Host not found";
        response.headers = {};
        return response;
    }
};

} // namespace keycloak::test
