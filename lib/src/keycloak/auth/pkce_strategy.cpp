#include <fmt/format.h>
#include "keycloak/auth/pkce_strategy.hpp"
#include "keycloak/utils/url_encode.hpp"

namespace keycloak::auth {

std::string PKCEStrategy::create_authorization_url() {
    auto [code_verifier, code_challenge] = pkce::generate_pkce_pair();
    auto state = state_store_->create(code_verifier);

    // Join scopes with space separator
    const auto& scopes = token_service_->get_scopes();
    std::string scope_string = scopes.empty() ? "" : 
    std::accumulate(std::next(scopes.begin()), scopes.end(),
        scopes[0],
        [](const std::string& acc, const std::string& scope) {
            return fmt::format("{} {}", acc, scope);
        });

    return fmt::format("{}?"
        "response_type=code&"
        "client_id={}&"
        "redirect_uri={}&"
        "state={}&"
        "code_challenge={}&"
        "code_challenge_method=S256&"
        "scope={}",
        token_service_->get_authorization_endpoint(),
        url_encode(client_id_),
        url_encode(redirect_uri_),
        url_encode(state),
        url_encode(code_challenge),
        url_encode(scope_string));
}

TokenResponse PKCEStrategy::handle_callback(
    std::string_view code, 
    std::string_view state)
{
    auto code_verifier = state_store_->verify(state);
    if (code_verifier.empty()) {
        TokenResponse error;
        error.error = "invalid_state";
        error.error_description = "State verification failed";
        return error;
    }

    return token_service_->exchange_code(
        code,
        code_verifier,
        redirect_uri_,
        client_id_);
}

bool PKCEStrategy::validate_session(
    const std::unordered_map<std::string, std::string>& cookies)
{
    auto it = cookies.find(cookie_config_.access_token_name);
    return it != cookies.end() && !it->second.empty();
}

} // namespace keycloak::auth
