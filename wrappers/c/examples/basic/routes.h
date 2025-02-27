#ifndef ROUTES_H
#define ROUTES_H

#include "context.h"

/**
 * @brief Route handler function type
 */
typedef int (*route_handler_t)(struct mg_connection* conn, void* cbdata);

/**
 * @brief Route mapping structure
 */
struct Route {
    const char* uri;              // URI pattern to match
    route_handler_t handler;      // Handler function
    const char* methods;          // Allowed HTTP methods (NULL for all)
};

// Handler functions
int handle_root(struct mg_connection* conn, void* cbdata);
int handle_auth_init(struct mg_connection* conn, void* cbdata);
int handle_callback(struct mg_connection* conn, void* cbdata);
int handle_protected(struct mg_connection* conn, void* cbdata);
int handle_error(struct mg_connection* conn, void* cbdata);

// Utility functions
void set_security_headers(struct mg_connection* conn);

// Route table declaration
extern const struct Route ROUTES[];
extern const size_t ROUTES_COUNT;

#endif // ROUTES_H
