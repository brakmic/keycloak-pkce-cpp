/**
* @file main.c
* @brief Keycloak PKCE Authentication Demo
*
* This example demonstrates how to use the Keycloak PKCE library to implement
* the PKCE (Proof Key for Code Exchange) authentication flow with a CivetWeb
* HTTPS server.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/signal.h>
#include "context.h"
#include "routes.h"
#include "helpers.h"

// Global context for signal handling
struct ServerContext g_context = {0};

/**
* @brief Signal handler for graceful shutdown
*/
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    if (g_context.ctx) {
        mg_stop(g_context.ctx);
        g_context.ctx = NULL;
    }
    if (g_context.pkce) {
        kc_pkce_destroy(g_context.pkce);
        g_context.pkce = NULL;
    }
    exit(0);
}

static void setup_signal_handlers(void) {
    // Block all signals in all threads
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // Only allow signals in main thread
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    // Set up signal handlers
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

/**
* @brief Main entry point
*/
int main(void) {
    // Initialize signal handlers
    setup_signal_handlers();

    // Load application settings
    const struct AppSettings settings = DEFAULT_APP_SETTINGS;
    g_context.settings = &settings;

    // Create and load library configuration
    kc_pkce_config_t config = NULL;
    if (kc_pkce_config_create(&config) != KC_PKCE_SUCCESS) {
        printf("Failed to create config\n");
        return 1;
    }

    // Load config file
    if (kc_pkce_config_load_file(config, settings.paths.library_config)
        != KC_PKCE_SUCCESS) {
        printf("Failed to load library config from: %s\n", 
            settings.paths.library_config);
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Configure proxy from app settings
    kc_pkce_proxy_config_t proxy_config = {
        .host = settings.proxy.host,
        .port = settings.proxy.port
    };
    
    if (kc_pkce_set_proxy_config(&proxy_config) != KC_PKCE_SUCCESS) {
        printf("Failed to configure proxy\n");
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Create PKCE client instance (will use proxy settings from singleton)
    if (kc_pkce_create(&g_context.pkce, config) != KC_PKCE_SUCCESS) {
        printf("Failed to create PKCE client\n");
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Configure authentication callback URL
    if (kc_pkce_set_redirect_uri(g_context.pkce, settings.auth.redirect_uri)
        != KC_PKCE_SUCCESS) {
        printf("Failed to set redirect URI: %s\n", settings.auth.redirect_uri);
        kc_pkce_destroy(g_context.pkce);
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Generate authorization URL
    if (kc_pkce_create_auth_url(g_context.pkce, 
        g_context.auth_url, sizeof(g_context.auth_url)) != KC_PKCE_SUCCESS) {
        printf("Failed to create authorization URL\n");
        kc_pkce_destroy(g_context.pkce);
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Load CivetWeb configuration
    int num_options = 0;
    const char** options = load_civetweb_config(settings.paths.civetweb_config, 
                                            &num_options);
    if (!options) {
        printf("Failed to load CivetWeb config from: %s\n", 
            settings.paths.civetweb_config);
        kc_pkce_destroy(g_context.pkce);
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Debug: Print loaded options
    // printf("Loaded CivetWeb options:\n");
    // for (int i = 0; options[i] != NULL; i += 2) {
    //     printf("  %s = %s\n", options[i], options[i + 1]);
    // }

    // Initialize CivetWeb
    struct mg_callbacks callbacks = {0};
    callbacks.log_message = log_message;
    g_context.ctx = mg_start(&callbacks, NULL, options);
    if (!g_context.ctx) {
        char errmsg[256] = {0};
        mg_get_system_info(errmsg, sizeof(errmsg));
        printf("Failed to start server:\n%s\n", errmsg);
        free_civetweb_options(options);
        kc_pkce_destroy(g_context.pkce);
        kc_pkce_config_destroy(config);
        return 1;
    }

    // Register route handlers
    for (size_t i = 0; i < ROUTES_COUNT; i++) {
        mg_set_request_handler(g_context.ctx, ROUTES[i].uri, 
                            ROUTES[i].handler, NULL);
    }

    printf("Server started at %s://%s:%d\n", 
        settings.server.protocol,
        settings.server.host,
        settings.server.port);
    printf("Open this URL in your browser to start authentication:\n%s\n", 
        g_context.auth_url);

    // Main loop
    while (g_context.ctx) {
        usleep(100000);  // 100ms sleep
    }

    // Cleanup
    kc_pkce_destroy(g_context.pkce);
    kc_pkce_config_destroy(config);
    return 0;
}
