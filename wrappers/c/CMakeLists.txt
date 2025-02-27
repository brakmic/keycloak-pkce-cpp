cmake_minimum_required(VERSION 3.18)
project(keycloak_pkce_c)

# CivetWeb configuration (for C demo only)
set(CIVETWEB_ENABLE_CXX OFF CACHE BOOL "Disable CivetWeb C++ API")
set(CIVETWEB_ENABLE_SERVER_EXECUTABLE OFF CACHE BOOL "Disable CivetWeb server executable")
set(CIVETWEB_ENABLE_SSL ON CACHE BOOL "Enable SSL support")
set(CIVETWEB_BUILD_TESTING OFF CACHE BOOL "Disable CivetWeb testing")
set(DOWNLOAD_EXTRACT_TIMESTAMP TRUE CACHE BOOL "")

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0")
    set(CIVETWEB_SSL_OPENSSL_API_3_0 ON CACHE INTERNAL "")
    set(CIVETWEB_SSL_OPENSSL_API_1_1 OFF CACHE INTERNAL "")
else()
    set(CIVETWEB_SSL_OPENSSL_API_3_0 OFF CACHE INTERNAL "")
    set(CIVETWEB_SSL_OPENSSL_API_1_1 ON CACHE INTERNAL "")
endif()

add_subdirectory(${CMAKE_SOURCE_DIR}/external/civetweb civetweb)

# Suppress CivetWeb warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(civetweb-c-library PRIVATE -w)
endif()

# Create required directories
file(MAKE_DIRECTORY 
    ${CMAKE_BINARY_DIR}/c
    ${CMAKE_BINARY_DIR}/c/lib
    ${CMAKE_BINARY_DIR}/c/include
    ${CMAKE_BINARY_DIR}/c/config
    ${CMAKE_BINARY_DIR}/c/logs
    ${CMAKE_BINARY_DIR}/c/certs/client
)

# C API Library
add_library(kc_pkce SHARED)
add_library(KeycloakPKCE::C ALIAS kc_pkce)

file(GLOB_RECURSE WRAPPER_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/internal/*.cpp"
)

# Append external sources
list(APPEND EXTERNAL_SOURCES
    "${CMAKE_SOURCE_DIR}/external/b64.c/buffer.c"
    "${CMAKE_SOURCE_DIR}/external/b64.c/decode.c"
    "${CMAKE_SOURCE_DIR}/external/cJSON/cJSON.c"
)

target_sources(kc_pkce
    PRIVATE
        ${WRAPPER_SOURCES}
        ${EXTERNAL_SOURCES}
)

target_include_directories(kc_pkce
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/internal
        ${CMAKE_SOURCE_DIR}/lib/include
        ${CMAKE_SOURCE_DIR}/lib/src
        ${CMAKE_SOURCE_DIR}/external/spdlog/include
        ${CMAKE_SOURCE_DIR}/external/picosha2
        ${CMAKE_SOURCE_DIR}/external/asio/asio/include
)

target_link_libraries(kc_pkce
    PRIVATE 
        KeycloakPKCE::Lib
        fmt::fmt
        json
        spdlog::spdlog_header_only
        picosha2
)

# Set output directory for the C library
set_target_properties(kc_pkce
    PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c/lib"
)

# Example C program
add_executable(pkce_demo_c)

file(GLOB_RECURSE DEMO_C_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/examples/basic/*.c"
)

target_sources(pkce_demo_c PRIVATE ${DEMO_C_SOURCES})

set_target_properties(pkce_demo_c 
    PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c/bin"
)

target_include_directories(pkce_demo_c
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/external/civetweb/include
        ${CMAKE_SOURCE_DIR}/external/cJSON
        ${CMAKE_SOURCE_DIR}/external/b64.c
)

target_link_libraries(pkce_demo_c
    PRIVATE
        kc_pkce
        civetweb-c-library
)

# Copy configuration and certificates
add_custom_target(copy_c_files ALL
    # Copy header files
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/c/include

    # Copy config files
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/library_config.json
        ${CMAKE_BINARY_DIR}/c/config/library_config.json

    # Copy certificates
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.c.pem
        ${CMAKE_BINARY_DIR}/c/certs/client/pkce-client.c.pem
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.c.key
        ${CMAKE_BINARY_DIR}/c/certs/client/pkce-client.c.key

    COMMENT "Copying C files and dependencies"
    VERBATIM
)

# Ensure dependencies are built in correct order
add_dependencies(kc_pkce KeycloakPKCE::Lib)
add_dependencies(pkce_demo_c kc_pkce)
add_dependencies(copy_c_files pkce_demo_c)
