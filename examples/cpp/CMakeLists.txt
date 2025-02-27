cmake_minimum_required(VERSION 3.18)
project(keycloak_pkce_cpp_demo)

# Crow settings
option(CROW_ENABLE_SSL "Enable SSL for Crow" ON)
option(CROW_BUILD_EXAMPLES "Build Crow examples" OFF)
option(CROW_BUILD_TESTS "Build Crow tests" OFF)

# Set ASIO include dir for Crow
set(ASIO_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/external/asio/asio/include)

# Create required directories
file(MAKE_DIRECTORY 
    ${CMAKE_BINARY_DIR}/cpp
    ${CMAKE_BINARY_DIR}/cpp/config
    ${CMAKE_BINARY_DIR}/cpp/logs
    ${CMAKE_BINARY_DIR}/cpp/certs/client
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add Crow from submodule with explicit binary dir
add_subdirectory(
    ${CMAKE_SOURCE_DIR}/external/Crow
    ${CMAKE_BINARY_DIR}/external/Crow
)

# C++ Demo executable
add_executable(pkce_demo_cpp)

file(GLOB_RECURSE DEMO_CPP_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

target_sources(pkce_demo_cpp PRIVATE ${DEMO_CPP_SOURCES})

set_target_properties(pkce_demo_cpp 
    PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/cpp/bin"
)

target_include_directories(pkce_demo_cpp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/routes
        ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${CMAKE_SOURCE_DIR}/lib/include
        ${CMAKE_SOURCE_DIR}/external/spdlog/include
        ${CMAKE_SOURCE_DIR}/external/cxxopts/include
        ${CMAKE_SOURCE_DIR}/external/json/include
        ${CMAKE_SOURCE_DIR}/external/asio/asio/include
        ${CMAKE_SOURCE_DIR}/external/Crow/include
)

target_link_libraries(pkce_demo_cpp
    PRIVATE
        KeycloakPKCE::Lib
        asio
        Crow
        fmt::fmt
        spdlog::spdlog_header_only
        json
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Copy configuration and certificates
add_custom_target(copy_cpp_files ALL
    # Copy config files
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/library_config.json
        ${CMAKE_BINARY_DIR}/cpp/config/library_config.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/app_config.json
        ${CMAKE_BINARY_DIR}/cpp/config/app_config.json

    # Copy certificates
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.cpp.crt
        ${CMAKE_BINARY_DIR}/cpp/certs/client/pkce-client.cpp.crt
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.cpp.key
        ${CMAKE_BINARY_DIR}/cpp/certs/client/pkce-client.cpp.key

    COMMENT "Copying C++ demo files and dependencies"
    VERBATIM
)

# Build dependencies in correct order
add_dependencies(pkce_demo_cpp KeycloakPKCE::Lib)
add_dependencies(copy_cpp_files pkce_demo_cpp)
