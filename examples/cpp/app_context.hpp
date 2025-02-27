/**
 * @file app_context.hpp
 * @brief Application Context Management for Demo Application
 * @version 1.0
 * 
 * Manages application-wide resources and dependencies including:
 * - Authentication strategy
 * - Session management
 * - Configuration state
 */

#include <memory>
#include <keycloak/auth/strategy.hpp>

namespace kc_auth = keycloak::auth;

/**
 * @class ApplicationContext
 * @brief Central context manager for the demo application
 * 
 * Provides:
 * - Dependency injection container
 * - Authentication strategy access
 * - Thread-safe resource management
 */
class ApplicationContext {
public:

    /**
     * @brief Creates new application context
     * @param auth_strategy PKCE authentication strategy instance
     * @throws std::invalid_argument if auth_strategy is null
     * 
     * Initializes application context with required dependencies:
     * - Authentication strategy for OAuth2/PKCE flow
     * - Session management capabilities
     */
    explicit ApplicationContext(
        std::shared_ptr<kc_auth::IAuthenticationStrategy> auth_strategy)
        : auth_strategy_(auth_strategy)
    {}

    /**
     * @brief Retrieves the authentication strategy
     * @return Shared pointer to authentication strategy
     * 
     * Thread-safe access to the PKCE authentication implementation.
     * Used by route handlers to perform authentication operations.
     */
    std::shared_ptr<kc_auth::IAuthenticationStrategy> get_auth_strategy() const {
        return auth_strategy_;
    }

private:
    std::shared_ptr<kc_auth::IAuthenticationStrategy> auth_strategy_;   ///< PKCE auth implementation
};
