cmake_minimum_required(VERSION 3.18)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

project(KeycloakPKCE 
    LANGUAGES C CXX
    VERSION 1.0.0
    DESCRIPTION "Keycloak PKCE Authentication Library"
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define build types (Debug, Release, RelWithDebInfo, MinSizeRel)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Set compiler flags for different build types
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Debug flags with sanitizers
set(SANITIZER_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0 ${SANITIZER_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "-g3 -O0 ${SANITIZER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${SANITIZER_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} ${SANITIZER_FLAGS}")

# Release flags
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# RelWithDebInfo flags
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g3 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g3 -fno-omit-frame-pointer")

# MinSizeRel flags
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

# Coverage option
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
    include(cmake/CodeCoverage.cmake)
    append_coverage_compiler_flags()
endif()

# Header-only libraries
set(JSON_BuildTests OFF CACHE BOOL "Disable JSON tests")
set(JSON_Install OFF CACHE BOOL "Disable JSON installation")

add_library(json INTERFACE)
target_include_directories(json INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}/external/json/single_include
)

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/asio/include
)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)

add_library(picosha2 INTERFACE)
target_include_directories(picosha2 INTERFACE 
    ${CMAKE_CURRENT_SOURCE_DIR}/external/picosha2
)

# External dependencies
find_package(OpenSSL REQUIRED)
add_subdirectory(external/fmt)
add_subdirectory(external/spdlog)

# Testing dependencies
set(BUILD_GMOCK OFF CACHE BOOL "Disable GMock")
set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of GTest")
add_subdirectory(external/googletest EXCLUDE_FROM_ALL)

# CPR configuration for integration and E2E tests
set(CPR_BUILD_TESTS OFF CACHE BOOL "Disable CPR tests")
set(CPR_BUILD_TESTS_SSL OFF CACHE BOOL "Disable CPR SSL tests")
set(CPR_ENABLE_SSL ON CACHE BOOL "Enable SSL in CPR")
set(CPR_USE_SYSTEM_CURL ON CACHE BOOL "Use system CURL")
add_subdirectory(external/cpr EXCLUDE_FROM_ALL)

# Enable testing
enable_testing()

# C++ Library
add_library(keycloak_pkce SHARED)
add_library(KeycloakPKCE::Lib ALIAS keycloak_pkce)

file(GLOB_RECURSE LIB_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/src/**/*.cpp"
)

target_sources(keycloak_pkce PRIVATE ${LIB_SOURCES})

target_include_directories(keycloak_pkce
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/src
        ${CMAKE_CURRENT_SOURCE_DIR}/external/fmt/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/json/single_include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/picosha2
        ${CMAKE_CURRENT_SOURCE_DIR}/external/spdlog/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/asio/include
)

target_link_libraries(keycloak_pkce
    PRIVATE
        fmt::fmt
        spdlog::spdlog_header_only
        OpenSSL::SSL
        OpenSSL::Crypto
        json
        asio
        picosha2
)

target_compile_definitions(keycloak_pkce PRIVATE ASIO_STANDALONE)

# CivetWeb configuration
set(DOWNLOAD_EXTRACT_TIMESTAMP TRUE CACHE BOOL "")
set(CIVETWEB_ENABLE_CXX OFF CACHE BOOL "Disable CivetWeb C++ API")
set(CIVETWEB_ENABLE_SERVER_EXECUTABLE OFF CACHE BOOL "Disable CivetWeb server executable")
set(CIVETWEB_ENABLE_SSL ON CACHE BOOL "Enable SSL support")
set(CIVETWEB_BUILD_TESTING OFF CACHE BOOL "Disable CivetWeb testing")

# Set OpenSSL API version for CivetWeb
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0")
    set(CIVETWEB_SSL_OPENSSL_API_3_0 ON CACHE INTERNAL "")
    set(CIVETWEB_SSL_OPENSSL_API_1_1 OFF CACHE INTERNAL "")
else()
    set(CIVETWEB_SSL_OPENSSL_API_3_0 OFF CACHE INTERNAL "")
    set(CIVETWEB_SSL_OPENSSL_API_1_1 ON CACHE INTERNAL "")
endif()

add_subdirectory(external/civetweb)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(civetweb-c-library
        PRIVATE -w
    )
endif()

# C Wrapper Library
add_library(kc_pkce SHARED)
add_library(KeycloakPKCE::C ALIAS kc_pkce)

file(GLOB_RECURSE WRAPPER_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/wrappers/c/internal/*.cpp"
)

target_sources(kc_pkce PRIVATE ${WRAPPER_SOURCES})

target_include_directories(kc_pkce
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/wrappers/c/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/wrappers/c/internal
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/src
        ${CMAKE_CURRENT_SOURCE_DIR}/external/json/single_include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/fmt/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/spdlog/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/asio/asio/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/picosha2
)

target_link_libraries(kc_pkce PRIVATE KeycloakPKCE::Lib json)

# Example C program
file(GLOB_RECURSE DEMO_C_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/wrappers/c/examples/basic/*.c"
)

add_executable(pkce_demo_c ${DEMO_C_SOURCES})

set_target_properties(pkce_demo_c PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

target_include_directories(pkce_demo_c
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/external/civetweb/include
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pkce_demo_c
    PRIVATE
        KeycloakPKCE::C
        civetweb-c-library
        ${CMAKE_DL_LIBS}
)

# Tests
add_subdirectory(tests)

# Installation
include(GNUInstallDirs)

install(TARGETS keycloak_pkce kc_pkce
    EXPORT KeycloakPKCETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY wrappers/c/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

install(EXPORT KeycloakPKCETargets
    FILE KeycloakPKCETargets.cmake
    NAMESPACE KeycloakPKCE::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KeycloakPKCE
)

# Configuration files
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config/app_config.json
               ${CMAKE_CURRENT_BINARY_DIR}/config/app_config.json COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config/library_config.json
               ${CMAKE_CURRENT_BINARY_DIR}/config/library_config.json COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config/civetweb.conf
               ${CMAKE_CURRENT_BINARY_DIR}/config/civetweb.conf COPYONLY)

# Certificates
add_custom_target(copy_certificates_c_demo ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/certs/client"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/certs/client/pkce-client.pem"
        "${CMAKE_BINARY_DIR}/certs/client/pkce-client.pem"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/certs/client/pkce-client.key"
        "${CMAKE_BINARY_DIR}/certs/client/pkce-client.key"
    COMMENT "Copying PEM Certificates to build directory"
    VERBATIM
)

add_dependencies(pkce_demo_c copy_certificates_c_demo)

# Lua support
find_package(PkgConfig REQUIRED)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LUAJIT luajit)
    if(LUAJIT_FOUND)
        message(STATUS "Found LuaJIT: ${LUAJIT_VERSION}")
        add_subdirectory(wrappers/lua)
    else()
        message(STATUS "LuaJIT not found, skipping Lua bindings")
    endif()
endif()

# Python support
add_subdirectory(wrappers/python)
