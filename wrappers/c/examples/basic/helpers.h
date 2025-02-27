#ifndef HELPERS_H
#define HELPERS_H

#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "b64.h"
#include "civetweb.h"

/**
 * @brief Load CivetWeb options from config file
 * 
 * @param filename Path to config file
 * @param num_options Pointer to store number of options
 * @return const char** Array of options strings or NULL on failure
 * 
 * @note The returned array must be freed using free_civetweb_options()
 */
 const char** load_civetweb_config(const char* filename, int* num_options);

 /**
  * @brief Free CivetWeb options array
  * 
  * @param options Array of options strings to free
  */
 void free_civetweb_options(const char** options);
 
 /**
  * @brief CivetWeb logging callback
  * 
  * Formats and writes log messages with timestamps
  * 
  * @param conn The connection (unused)
  * @param message The message to log
  * @return int 1 to indicate message was handled
  */
 int log_message(const struct mg_connection *conn, const char *message);
 
/**
 * @brief Decodes and parses the payload section of a JWT token
 * 
 * This function extracts the middle part (payload) of a JWT token,
 * decodes it from base64url format, and parses the resulting JSON.
 * The JWT format expected is: header.payload.signature
 * 
 * @param jwt     The complete JWT token string
 * @return cJSON* Pointer to parsed JSON object containing claims,
 *                or NULL if decoding/parsing fails
 * 
 * @note The returned cJSON object must be freed using cJSON_Delete()
 * @note Function assumes standard JWT format with three dot-separated parts
 * 
 * Example:
 *   cJSON* claims = decode_jwt_payload(jwt_token);
 *   if (claims) {
 *       // Process claims
 *       cJSON_Delete(claims);
 *   }
 */
cJSON* decode_jwt_payload(const char* jwt);

#endif // HELPERS_H
