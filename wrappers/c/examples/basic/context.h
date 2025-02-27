#ifndef CONTEXT_H
#define CONTEXT_H

#include "civetweb.h"
#include "kc_pkce.h"
#include "app_settings.h"

/**
 * @brief Server context holding runtime state
 */
struct ServerContext {
    struct mg_context* ctx;
    kc_pkce_handle_t pkce;
    char auth_url[2048];
    const struct AppSettings* settings;
};

// Global context declaration
extern struct ServerContext g_context;

#endif // CONTEXT_H
