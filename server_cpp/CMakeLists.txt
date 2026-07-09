# Intentionally unused for now.
# The C++ server foundation tests are currently wired through the root CMakeLists.txt.

cmake_minimum_required(VERSION 3.20)

project(seftp_server_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(seftp_server_cpp INTERFACE)

target_include_directories(seftp_server_cpp
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

enable_testing()

find_package(GTest CONFIG REQUIRED)

add_executable(seftp_server_cpp_tests
        tests/protocol_constants_test.cpp
)

target_link_libraries(seftp_server_cpp_tests
        PRIVATE
        seftp_server_cpp
        GTest::gtest
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(seftp_server_cpp_tests)