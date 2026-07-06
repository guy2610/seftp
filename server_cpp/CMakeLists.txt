cmake_minimum_required(VERSION 3.20)

project(seftp_server_cpp LANGUAGES CXX)

add_library(seftp_server_core INTERFACE)

target_include_directories(seftp_server_core
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(seftp_server_core
        INTERFACE
        cxx_std_17
)