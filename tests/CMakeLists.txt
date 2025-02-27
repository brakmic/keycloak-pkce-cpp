set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Test categories
set(UNIT_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/unit)
set(INTEGRATION_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/integration)
set(E2E_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/e2e)
set(MOCKS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mocks)

# Test sources
set(UNIT_TEST_SOURCES
    ${UNIT_TEST_DIR}/pkce/pkce_test.cpp
    ${UNIT_TEST_DIR}/pkce/state_store_test.cpp
    ${UNIT_TEST_DIR}/auth/token_service_test.cpp
    ${UNIT_TEST_DIR}/auth/strategy_test.cpp
    ${UNIT_TEST_DIR}/http/http_client_test.cpp
)

set(INTEGRATION_TEST_SOURCES
    ${INTEGRATION_TEST_DIR}/auth_flow_test.cpp
    ${INTEGRATION_TEST_DIR}/token_exchange_test.cpp
)

set(E2E_TEST_SOURCES
    ${E2E_TEST_DIR}/keycloak_client_test.cpp
)

# Common dependencies for all test executables
set(TEST_COMMON_INCLUDES
    ${CMAKE_SOURCE_DIR}/lib/include
    ${CMAKE_SOURCE_DIR}/lib/src
    ${CMAKE_SOURCE_DIR}/external/json/single_include
    ${CMAKE_SOURCE_DIR}/external/fmt/include
    ${CMAKE_SOURCE_DIR}/external/spdlog/include
    ${CMAKE_SOURCE_DIR}/external/picosha2
    ${CMAKE_SOURCE_DIR}/external/asio/asio/include
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Unit tests
add_executable(unit_tests ${UNIT_TEST_SOURCES})
target_link_libraries(unit_tests
    PRIVATE
        keycloak_pkce
        GTest::gtest
        GTest::gtest_main
        fmt::fmt
        spdlog::spdlog_header_only
        OpenSSL::SSL
        OpenSSL::Crypto
        json
        picosha2
)

# Integration tests
add_executable(integration_tests ${INTEGRATION_TEST_SOURCES})
target_link_libraries(integration_tests
    PRIVATE
        keycloak_pkce
        GTest::gtest
        GTest::gtest_main
        cpr::cpr
        fmt::fmt
        spdlog::spdlog_header_only
        OpenSSL::SSL
        OpenSSL::Crypto
        json
        picosha2
)

# E2E tests
add_executable(e2e_tests ${E2E_TEST_SOURCES})
target_link_libraries(e2e_tests
    PRIVATE
        keycloak_pkce
        GTest::gtest
        GTest::gtest_main
        cpr::cpr
        fmt::fmt
        spdlog::spdlog_header_only
        OpenSSL::SSL
        OpenSSL::Crypto
        json
        picosha2
)

# Common include directories for all test targets
foreach(TARGET unit_tests integration_tests e2e_tests)
    target_include_directories(${TARGET}
        PRIVATE
            ${TEST_COMMON_INCLUDES}
    )
endforeach()

# Test discovery
include(GoogleTest)
gtest_discover_tests(unit_tests)
gtest_discover_tests(integration_tests)
gtest_discover_tests(e2e_tests)

# Custom targets for running tests
add_custom_target(run_unit_tests
    COMMAND unit_tests
    DEPENDS unit_tests
)

add_custom_target(run_integration_tests
    COMMAND integration_tests
    DEPENDS integration_tests
)

add_custom_target(run_e2e_tests
    COMMAND e2e_tests
    DEPENDS e2e_tests
)

add_custom_target(run_all_tests
    DEPENDS run_unit_tests run_integration_tests run_e2e_tests
)

# Coverage configuration
if(ENABLE_COVERAGE)
    include(${CMAKE_SOURCE_DIR}/cmake/CodeCoverage.cmake)
    append_coverage_compiler_flags()
    setup_target_for_coverage_gcovr_html(
        NAME coverage
        EXECUTABLE ctest -j ${PROCESSOR_COUNT}
        DEPENDENCIES run_all_tests
        BASE_DIRECTORY "${CMAKE_SOURCE_DIR}/lib"
        EXCLUDE "tests/*" "external/*"
    )
endif()
