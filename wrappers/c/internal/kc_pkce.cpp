#include <memory>
#include <cstring>
#include <filesystem>
#include "kc_pkce.h"
#include "proxy_settings.hpp"
#include "pkce_wrapper.hpp"
#include "config_wrapper.hpp"

using namespace keycloak::c_api;

struct kc_pkce_context_s {
    std::unique_ptr<PKCEWrapper> impl;
};

struct kc_pkce_config_s {
    std::unique_ptr<ConfigWrapper> impl;
};

extern "C" {

KC_PKCE_API kc_pkce_error_t 
kc_pkce_create(kc_pkce_handle_t* handle, const kc_pkce_config_t config) {
    if (!handle || !config || !config->impl) 
        return KC_PKCE_ERROR_INVALID_HANDLE;
    
    try {
        // Create PKCE wrapper with library config
        auto context = new kc_pkce_context_s{
            std::make_unique<PKCEWrapper>(config->impl->get_config())
        };
        *handle = context;
        return KC_PKCE_SUCCESS;
    } catch (const std::bad_alloc&) {
        return KC_PKCE_ERROR_ALLOCATION;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_INITIALIZATION;
    }
}

KC_PKCE_API void 
kc_pkce_destroy(kc_pkce_handle_t handle) {
    delete handle;
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_config_create(kc_pkce_config_t* config) {
    if (!config) return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        auto cfg = new kc_pkce_config_s{
            std::make_unique<ConfigWrapper>()
        };
        *config = cfg;
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_ALLOCATION;
    }
}

KC_PKCE_API void 
kc_pkce_config_destroy(kc_pkce_config_t config) {
    delete config;
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_config_load_file(kc_pkce_config_t config, const char* path) {
    if (!config || !config->impl || !path) 
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        config->impl->load_from_file(path);
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_CONFIG;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_keycloak_config(kc_pkce_config_t config, 
                           const kc_pkce_keycloak_config_t* kc_config) 
{
    if (!config || !config->impl || !kc_config)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        config->impl->set_keycloak_config(kc_config);
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_CONFIG;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_ssl_config(kc_pkce_config_t config,
                       const kc_pkce_ssl_config_t* ssl_config)
{
    if (!config || !config->impl || !ssl_config)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        config->impl->set_ssl_config(ssl_config);
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_CONFIG;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_proxy_config(const kc_pkce_proxy_config_t* proxy_config)
{
    if (!proxy_config) return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        const char* host = "";
        if (proxy_config->host != nullptr) {
            host = proxy_config->host;
        }
        
        ProxySettings::instance().configure(
            std::string(host),
            proxy_config->port
        );
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_CONFIG;
    }
}

KC_PKCE_API kc_pkce_error_t
kc_pkce_get_scopes(kc_pkce_config_t config, const char*** scopes, size_t* scope_count) {
    if (!config || !config->impl || !scopes || !scope_count)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
        
    try {
        const auto& cfg = config->impl->get_config();
        const auto& scope_list = cfg.keycloak.scopes;
        
        *scope_count = scope_list.size();
        auto scope_array = new const char*[scope_list.size()];
        
        for (size_t i = 0; i < scope_list.size(); ++i) {
            scope_array[i] = strdup(scope_list[i].c_str());
        }
        
        *scopes = scope_array;
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_ALLOCATION;
    }
}

KC_PKCE_API void
kc_pkce_free_scopes(const char** scopes, size_t scope_count) {
    if (!scopes) return;
    
    for (size_t i = 0; i < scope_count; ++i) {
        free((void*)scopes[i]);
    }
    delete[] scopes;
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_redirect_uri(kc_pkce_handle_t handle, const char* redirect_uri) {
    if (!handle || !handle->impl || !redirect_uri)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        handle->impl->set_redirect_uri(redirect_uri);
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_create_auth_url(kc_pkce_handle_t handle, 
                        char* url_buffer, 
                        size_t buffer_size) 
{
    if (!handle || !handle->impl || !url_buffer || buffer_size == 0)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        auto url = handle->impl->create_authorization_url();
        if (url.length() >= buffer_size) {
            return KC_PKCE_ERROR_BUFFER_TOO_SMALL;
        }
        
        std::strncpy(url_buffer, url.c_str(), buffer_size - 1);
        url_buffer[buffer_size - 1] = '\0';
        return KC_PKCE_SUCCESS;
    } catch (const std::runtime_error&) {
        return KC_PKCE_ERROR_INVALID_STATE;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_AUTH;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_handle_callback(kc_pkce_handle_t handle, 
                       const char* code, 
                       const char* state,
                       kc_pkce_token_info_t* token_info) 
{
    if (!handle || !handle->impl || !code || !state || !token_info)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;

    // Always clear token info first
    std::memset(token_info, 0, sizeof(kc_pkce_token_info_t));
    
    try {
        auto response = handle->impl->handle_callback(code, state);
        
        if (response.is_success()) {
            token_info->access_token = response.access_token.empty() ? nullptr : 
                strdup(response.access_token.c_str());
            token_info->refresh_token = response.refresh_token.empty() ? nullptr : 
                strdup(response.refresh_token.c_str());
            token_info->id_token = response.id_token.empty() ? nullptr : 
                strdup(response.id_token.c_str());
            token_info->token_type = response.token_type.empty() ? nullptr : 
                strdup(response.token_type.c_str());
            token_info->expires_in = response.expires_in;
            return KC_PKCE_SUCCESS;
        } else {
            token_info->error = response.error.empty() ? nullptr : 
                strdup(response.error.c_str());
            token_info->error_description = response.error_description.empty() ? nullptr : 
                strdup(response.error_description.c_str());
            return KC_PKCE_ERROR_AUTH;
        }
    } catch (const std::runtime_error&) {
        return KC_PKCE_ERROR_INVALID_STATE;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_AUTH;
    }
}

KC_PKCE_API bool 
kc_pkce_validate_session(kc_pkce_handle_t handle, const char* access_token) {
    if (!handle || !handle->impl || !access_token)
        return false;
        
    try {
        return handle->impl->validate_session(access_token);
    } catch (const std::runtime_error&) {
        return false;  // Strategy not initialized
    } catch (const std::exception&) {
        return false;  // Other errors
    }
}

// Cookie Management Implementation
KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_cookie(kc_pkce_handle_t handle,
                   const char* name,
                   const char* value) 
{
    if (!handle || !handle->impl || !name || !value)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        handle->impl->update_cookies(name, value);
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    }
}

KC_PKCE_API kc_pkce_error_t 
kc_pkce_set_cookies(kc_pkce_handle_t handle, 
                    const kc_pkce_cookie_t* cookies, 
                    size_t cookie_count) 
{
    if (!handle || !handle->impl || !cookies || cookie_count == 0)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        for (size_t i = 0; i < cookie_count; ++i) {
            if (!cookies[i].name || !cookies[i].value)
                return KC_PKCE_ERROR_INVALID_ARGUMENT;
                
            handle->impl->update_cookies(cookies[i].name, cookies[i].value);
        }
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    }
}

// Configuration Validation Implementation
KC_PKCE_API kc_pkce_error_t 
kc_pkce_validate_config(kc_pkce_config_t config)
{
    if (!config || !config->impl)
        return KC_PKCE_ERROR_INVALID_ARGUMENT;
    
    try {
        const auto& cfg = config->impl->get_config();
        
        // Match C++ library validation rules
        if (cfg.keycloak.host.empty()) {
            return KC_PKCE_ERROR_VALIDATION;
        }
        if (cfg.keycloak.realm.empty()) {
            return KC_PKCE_ERROR_VALIDATION;
        }
        if (cfg.keycloak.client_id.empty()) {
            return KC_PKCE_ERROR_VALIDATION;
        }
        if (cfg.keycloak.ssl.verify_peer && cfg.keycloak.ssl.ca_cert_path.empty()) {
            return KC_PKCE_ERROR_VALIDATION;
        }
        
        return KC_PKCE_SUCCESS;
    } catch (const std::exception&) {
        return KC_PKCE_ERROR_CONFIG;
    }
}

// Memory Management Implementation
KC_PKCE_API void 
kc_pkce_free_token_info(kc_pkce_token_info_t* token_info) {
    if (!token_info) return;
    
    free(token_info->access_token);
    free(token_info->refresh_token);
    free(token_info->id_token);
    free(token_info->token_type);
    free(token_info->error);
    free(token_info->error_description);
    
    std::memset(token_info, 0, sizeof(kc_pkce_token_info_t));
}

// Error Handling Implementation
KC_PKCE_API const char* 
kc_pkce_get_error_message(kc_pkce_error_t error) {
    switch (error) {
        case KC_PKCE_SUCCESS:
            return "Success";
        case KC_PKCE_ERROR_INVALID_HANDLE:
            return "Invalid handle";
        case KC_PKCE_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case KC_PKCE_ERROR_ALLOCATION:
            return "Memory allocation failed";
        case KC_PKCE_ERROR_NETWORK:
            return "Network error";
        case KC_PKCE_ERROR_SSL:
            return "SSL error";
        case KC_PKCE_ERROR_AUTH:
            return "Authentication error";
        case KC_PKCE_ERROR_CONFIG:
            return "Configuration error";
        case KC_PKCE_ERROR_INVALID_STATE:
            return "Invalid state - strategy not initialized";
        case KC_PKCE_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case KC_PKCE_ERROR_VALIDATION:
            return "Configuration validation failed";
        case KC_PKCE_ERROR_INITIALIZATION:
            return "Initialization failed";
        default:
            return "Unknown error";
    }
}

} // extern "C"
