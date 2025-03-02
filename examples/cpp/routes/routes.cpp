#include <string>
#include <vector>
#include <sstream>
#include <crow.h>
#include <fmt/format.h>

#include "app_context.hpp"
#include "routes.hpp"
#include "keycloak/utils/logging.hpp"


namespace lg = keycloak::logging;

namespace app::routes {

void set_security_headers(crow::response& resp) {
      resp.set_header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
      resp.set_header("Pragma", "no-cache");
      resp.set_header("Expires", "0");
      resp.set_header("X-Content-Type-Options", "nosniff");
      resp.set_header("X-Frame-Options", "DENY");
      resp.set_header("X-XSS-Protection", "1; mode=block");
  }

void configure_routes(crow::SimpleApp& app, std::shared_ptr<ApplicationContext> app_context)
    {
        /**
        * @route GET /auth/keycloak
        * @brief Initiates PKCE authentication flow
        * @returns 302 Redirect to Keycloak login
        * @throws 500 If authorization URL generation fails
        */
        CROW_ROUTE(app, "/auth/keycloak")
        ([app_context]() {
            try {
                lg::Logger::debug("=== Authorization Request ===");
                auto response = crow::response(302);
                response.set_header("Location", 
                    app_context->get_auth_strategy()->create_authorization_url());
                set_security_headers(response);
                return response;
            } catch (const std::exception& e) {
                lg::Logger::error("Authorization error: {}", e.what());
                return crow::response(500, "Internal server error");
            }
        });

        /**
        * @route GET /auth/keycloak/callback
        * @brief Handles OAuth2 callback from Keycloak
        * @param state CSRF token
        * @param code Authorization code
        * @returns 302 Redirect to protected resource or error page
        * @security Sets secure session cookies
        */
        CROW_ROUTE(app, "/auth/keycloak/callback")
        ([app_context](const crow::request& req) {
            lg::Logger::debug("=== Callback Request ===");
            
            auto params = req.url_params;
            std::string state = params.get("state");
            std::string code = params.get("code");
            
            if (params.get("error")) {
                auto error = params.get("error");
                lg::Logger::error("Keycloak error: {}", error);
                auto response = crow::response(302);
                response.set_header("Location", "/auth/error?error=" + url_encode(error));
                set_security_headers(response);
                return response;
            }
            
            if (state.empty() || code.empty()) {
                lg::Logger::warn("Missing state or code");
                auto response = crow::response(302);
                response.set_header("Location", "/auth/error?error=invalid_callback");
                set_security_headers(response);
                return response;
            }
            
            auto token_result = app_context->get_auth_strategy()->handle_callback(code, state);
            
            if (!token_result.is_success()) {
                lg::Logger::error("Token exchange failed: {}", token_result.error_description);
                auto response = crow::response(302);
                response.set_header("Location", 
                    "/auth/error?error=" + url_encode(token_result.error_description));
                set_security_headers(response);
                return response;
            }
            
            auto response = crow::response(302);
            response.set_header("Location", "/protected");
            set_security_headers(response);
            
            const auto& cookie_config = app_context->get_auth_strategy()->get_cookie_config();
            
            std::vector<std::string> cookies = {
                fmt::format("{}={}{}",
                    cookie_config.access_token_name,
                    url_encode(token_result.access_token),
                    cookie_config.get_attributes()),
                fmt::format("{}={}{}",
                    cookie_config.refresh_token_name,
                    url_encode(token_result.refresh_token),
                    cookie_config.get_attributes()),
                fmt::format("{}={}{}",
                    cookie_config.id_token_name,
                    url_encode(token_result.id_token),
                    cookie_config.get_attributes())
            };

            for (const auto& cookie : cookies) {
                response.add_header("Set-Cookie", cookie);
            }

            return response;
        });

        /**
        * @route GET /protected
        * @brief Demonstrates protected resource access
        * @returns 200 Success message if authenticated
        * @returns 302 Redirect to login if not authenticated
        * @security Requires valid session cookies
        */
        CROW_ROUTE(app, "/protected")
        ([app_context](const crow::request& req) {
            lg::Logger::debug("=== Protected Route ===");
            
            std::unordered_map<std::string, std::string> cookies;
            if (auto cookie_header = req.get_header_value("Cookie"); !cookie_header.empty()) {
                std::istringstream cookie_stream(cookie_header);
                std::string cookie;
                while (std::getline(cookie_stream, cookie, ';')) {
                    if (auto pos = cookie.find('='); pos != std::string::npos) {
                        auto key = cookie.substr(0, pos);
                        auto value = cookie.substr(pos + 1);
                        key.erase(0, key.find_first_not_of(" "));
                        key.erase(key.find_last_not_of(" ") + 1);
                        value.erase(0, value.find_first_not_of(" "));
                        value.erase(value.find_last_not_of(" ") + 1);
                        cookies[key] = value;
                    }
                }
            }
            
            if (!app_context->get_auth_strategy()->validate_session(cookies)) {
                lg::Logger::warn("Invalid session");
                auto response = crow::response(302);
                response.set_header("Location", "/auth/keycloak");
                set_security_headers(response);
                return response;
            }
            
            auto response = crow::response(200);
            response.body = "Protected resource accessed successfully!";
            set_security_headers(response);
            response.set_header("Content-Type", "text/plain");
            return response;
        });

        /**
        * @route GET /auth/error
        * @brief Displays authentication errors
        * @param error Error message
        * @returns 400 Error description
        */
        CROW_ROUTE(app, "/auth/error")
        ([](const crow::request& req) {
            auto params = req.url_params;
            std::string error = params.get("error") ? params.get("error") : "Unknown error";
            
            auto response = crow::response(400);
            response.body = "Authentication failed: " + error;
            set_security_headers(response);
            return response;
        });
    }
}