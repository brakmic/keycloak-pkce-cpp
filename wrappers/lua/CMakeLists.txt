cmake_minimum_required(VERSION 3.18)
project(keycloak_pkce_lua)

# Create required directories
file(MAKE_DIRECTORY 
    ${CMAKE_BINARY_DIR}/lua
    ${CMAKE_BINARY_DIR}/lua/config
    ${CMAKE_BINARY_DIR}/lua/logs
    ${CMAKE_BINARY_DIR}/lua/certs/client
)

# Custom target for copying all required files
add_custom_target(copy_lua_files ALL
    # Copy Keycloak Lua scripts
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/keycloak_pkce.lua
        ${CMAKE_BINARY_DIR}/lua/keycloak_pkce.lua
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/standalone.lua
        ${CMAKE_BINARY_DIR}/lua/standalone.lua

    # Copy config files
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/library_config.json
        ${CMAKE_BINARY_DIR}/lua/config/library_config.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/civetweb.conf
        ${CMAKE_BINARY_DIR}/lua/config/civetweb.conf

    # Copy certificates for nginx / OpenResty
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.lua.pem
        ${CMAKE_BINARY_DIR}/lua/certs/client/pkce-client.lua.pem
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.lua.key
        ${CMAKE_BINARY_DIR}/lua/certs/client/pkce-client.lua.key

    # Copy certificates for lua-http
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/lua_http_server.pem
        ${CMAKE_BINARY_DIR}/lua/certs/client/lua_http_server.pem
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/lua_http_server.pkcs8.key
        ${CMAKE_BINARY_DIR}/lua/certs/client/lua_http_server.pkcs8.key   

    # Copy OpenResty config
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/nginx.conf
        ${CMAKE_BINARY_DIR}/lua/nginx.conf
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/mime.types
        ${CMAKE_BINARY_DIR}/lua/mime.types

    COMMENT "Copying Lua files and dependencies"
    VERBATIM
)

# Make sure C library is built before copying Lua files
add_dependencies(copy_lua_files kc_pkce)
