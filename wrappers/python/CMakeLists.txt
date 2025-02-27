cmake_minimum_required(VERSION 3.18)
project(keycloak_pkce_python)

# Create build directories for Python artifacts
file(MAKE_DIRECTORY 
    ${CMAKE_BINARY_DIR}/python
    ${CMAKE_BINARY_DIR}/python/config
    ${CMAKE_BINARY_DIR}/python/logs
    ${CMAKE_BINARY_DIR}/python/certs/client
)

# Custom target to copy Python files and dependencies
add_custom_target(copy_python_files ALL
    # 1) Copy Python scripts
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/keycloak_pkce.py
        ${CMAKE_BINARY_DIR}/python/keycloak_pkce.py
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/standalone.py
        ${CMAKE_BINARY_DIR}/python/standalone.py

    # 2) Copy the library_config.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config/library_config.json
        ${CMAKE_BINARY_DIR}/python/config/library_config.json

    # 3) Copy the SSL certificates
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.py.pem
        ${CMAKE_BINARY_DIR}/python/certs/client/pkce-client.py.pem
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/certs/client/pkce-client.py.key
        ${CMAKE_BINARY_DIR}/python/certs/client/pkce-client.py.key

    COMMENT "Copying Python files and dependencies for PKCE demo"
    VERBATIM
)

# Ensure the C library (kc_pkce) is built before copying the Python files
add_dependencies(copy_python_files kc_pkce)
