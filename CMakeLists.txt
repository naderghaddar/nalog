cmake_minimum_required(VERSION 3.16)

project(secscan VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SECSCAN_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

add_library(secscan_lib
    src/cli.cpp
    src/parser.cpp
    src/analyzer.cpp
    src/utils.cpp
)

target_include_directories(secscan_lib
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(secscan_lib PRIVATE /W4 /permissive-)
    if(SECSCAN_WARNINGS_AS_ERRORS)
        target_compile_options(secscan_lib PRIVATE /WX)
    endif()
else()
    target_compile_options(secscan_lib PRIVATE -Wall -Wextra -Wpedantic)
    if(SECSCAN_WARNINGS_AS_ERRORS)
        target_compile_options(secscan_lib PRIVATE -Werror)
    endif()
endif()

add_executable(secscan src/main.cpp)
target_link_libraries(secscan PRIVATE secscan_lib)

enable_testing()

add_executable(secscan_tests
    tests/test_main.cpp
)
target_link_libraries(secscan_tests PRIVATE secscan_lib)

add_test(NAME secscan_tests COMMAND secscan_tests)
