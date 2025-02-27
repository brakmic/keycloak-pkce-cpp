#pragma once

#include <crow.h>
#include "app_context.hpp"
#include "keycloak/utils/url_encode.hpp"
#include "keycloak/utils/logging.hpp"

namespace app::routes {

/**
 * @brief Sets security headers for HTTP responses
 * @param resp Crow response object to modify
 */
void set_security_headers(crow::response& resp);

/**
 * @brief Configures all application routes
 * @param app Crow application instance
 * @param app_context Application context with auth strategy
 */
void configure_routes(
    crow::SimpleApp& app, 
    std::shared_ptr<ApplicationContext> app_context
);

} // namespace app::routes
