if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(WARNING "Code coverage results with an optimised (non-Debug) build may be misleading")
endif()

if(NOT ENABLE_COVERAGE)
    return()
endif()

find_program(GCOV_PATH gcov)
find_program(LCOV_PATH lcov)
find_program(GENHTML_PATH genhtml)
find_program(GCOVR_PATH gcovr PATHS ${CMAKE_SOURCE_DIR}/scripts/test)

if(NOT GCOV_PATH)
    message(FATAL_ERROR "gcov not found! Please install gcov.")
endif()

if(NOT GCOVR_PATH)
    message(FATAL_ERROR "gcovr not found! Please install gcovr.")
endif()

function(append_coverage_compiler_flags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage" PARENT_SCOPE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage" PARENT_SCOPE)
endfunction()

function(setup_target_for_coverage_gcovr_html)
    cmake_parse_arguments(COVERAGE "" "NAME;EXECUTABLE;BASE_DIRECTORY" "DEPENDENCIES;EXCLUDE" ${ARGN})
    
    add_custom_target(${COVERAGE_NAME}
        COMMAND ${GCOVR_PATH} --html --html-details
                -r ${COVERAGE_BASE_DIRECTORY} ${COVERAGE_EXCLUDE}
                --object-directory=${PROJECT_BINARY_DIR}
                -o ${COVERAGE_NAME}/index.html
        COMMAND ${COVERAGE_EXECUTABLE}
        
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        DEPENDS ${COVERAGE_DEPENDENCIES}
        COMMENT "Running gcovr to produce HTML code coverage report."
    )
    
    add_custom_command(TARGET ${COVERAGE_NAME} POST_BUILD
        COMMAND ;
        COMMENT "Open ./${COVERAGE_NAME}/index.html in your browser to view the coverage report."
    )
endfunction()
