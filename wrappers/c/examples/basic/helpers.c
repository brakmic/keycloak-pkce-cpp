#define CJSON_IMPLEMENTATION
#include "cJSON.h"
#define B64_IMPLEMENTATION
#include "b64.h"
#include "helpers.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief CivetWeb logging callback
 */
int log_message(const struct mg_connection *conn, const char *message) {
  (void)conn;  // Unused in this implementation
  time_t now;
  struct tm tm_now;
  char timestamp[32];
  
  // Get current time
  time(&now);
  localtime_r(&now, &tm_now);
  
  // Format timestamp: YYYY-MM-DD HH:MM:SS.mmm
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);
  
  // Simple log format with timestamp
  fprintf(stderr, "[%s] %s\n", timestamp, message ? message : "");
  fflush(stderr);
  
  return 1;  // Return 1 to indicate message was handled
}

/**
* @brief Load CivetWeb options from config file
* @param filename Path to config file
* @param num_options Pointer to store number of options
* @return Array of options strings or NULL on failure
*/
const char** load_civetweb_config(const char* filename, int* num_options) {
  FILE* conf_file = fopen(filename, "r");
  if (!conf_file) {
      printf("Failed to open config file: %s\n", filename);
      return NULL;
  }

  // Count valid options (non-comment, non-empty lines)
  char line[256];
  *num_options = 0;
  while (fgets(line, sizeof(line), conf_file)) {
      if (line[0] != '#' && line[0] != '\n') {
          (*num_options)++;
      }
  }

  // Allocate options array (key-value pairs + NULL terminator)
  const char** options = calloc((*num_options) * 2 + 1, sizeof(char*));
  if (!options) {
      fclose(conf_file);
      return NULL;
  }

  // Reset file position
  rewind(conf_file);

  // Parse options
  int opt_index = 0;
  while (fgets(line, sizeof(line), conf_file)) {
      // Skip comments and empty lines
      if (line[0] == '#' || line[0] == '\n') continue;

      // Remove newline
      line[strcspn(line, "\n")] = 0;

      const char* key = strtok(line, " =");
      char* value = strtok(NULL, "\n");

      // Skip if no key or value
      if (!key || !value) continue;

      // Trim leading whitespace from value
      while (*value == ' ') value++;

      options[opt_index++] = strdup(key);
      options[opt_index++] = strdup(value);
  }

  options[opt_index] = NULL;
  fclose(conf_file);
  return options;
}

void free_civetweb_options(const char** options) {
  if (!options) return;
  for (int i = 0; options[i]; i++) {
      free((void*)options[i]);
  }
  free((void*)options);
}

cJSON* decode_jwt_payload(const char* jwt) {
    char* payload = strchr(jwt, '.');
    if (!payload) return NULL;
    
    payload++; // skip the dot
    char* sig = strchr(payload, '.');
    if (!sig) return NULL;
    
    size_t len = sig - payload;
    char* decoded = (char*)b64_decode(payload, len);
    if (!decoded) return NULL;
    
    cJSON* json = cJSON_Parse(decoded);
    free(decoded);
    
    return json;
}
