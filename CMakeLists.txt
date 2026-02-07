cmake_minimum_required(VERSION 3.21)
project(SEFFP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(seffp_client
    client/src/client_tirgul.cpp
    client/src/crypto/crypto.cpp
    client/src/net/net.cpp
    client/src/util/files.cpp
    client/src/logger/logger.cpp
)

target_include_directories(seffp_client PRIVATE
    client/src
    client/src/crypto
    client/src/net
    client/src/protocol
    client/src/util
    client/src/logger
)

if (WIN32)
    target_link_libraries(seffp_client PRIVATE ws2_32)
    target_compile_definitions(seffp_client PRIVATE _WIN32_WINNT=0x0A00)
endif()

find_package(boost_system CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
target_link_libraries(seffp_client PRIVATE Boost::system Boost::asio)

find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(seffp_client PRIVATE cryptopp::cryptopp)

set(TRANSFER_INFO_SRC "${CMAKE_SOURCE_DIR}/client/SEFFP-CLIENT/transfer.info")
add_custom_command(TARGET seffp_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${TRANSFER_INFO_SRC}"
            "$<TARGET_FILE_DIR:seffp_client>/transfer.info"
    VERBATIM
)

include(CTest)
enable_testing()

if (BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)

    add_executable(seffp_tests
        tests/test_dummy.cpp
	tests/proto_le_helpers_test.cpp
	tests/proto_request_base_test.cpp
	tests/proto_response_parsers_test.cpp
	tests/proto_request_builders_test.cpp
	tests/net_test.cpp
    )
    target_link_libraries(seffp_tests PRIVATE GTest::gtest_main)

    if (WIN32)
        target_compile_definitions(seffp_tests PRIVATE _WIN32_WINNT=0x0A00)
    endif()

    include(GoogleTest)
    gtest_discover_tests(seffp_tests)
endif()