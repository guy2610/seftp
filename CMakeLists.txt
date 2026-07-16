cmake_minimum_required(VERSION 3.21)
project(SEFTP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(seftp_client
    client/src/client_main.cpp
    client/src/crypto/crypto.cpp
    client/src/net/net.cpp
    client/src/util/files.cpp
    client/src/logger/logger.cpp
    client/src/ui/console_ui.cpp
    client/src/persistence/client_persistence.cpp

)

target_include_directories(seftp_client PRIVATE
    client/src
    client/src/crypto
    client/src/net
    client/src/protocol
    client/src/util
    client/src/logger
)

if (WIN32)
    target_link_libraries(seftp_client PRIVATE ws2_32)
    target_compile_definitions(seftp_client PRIVATE _WIN32_WINNT=0x0A00)
endif()

find_package(boost_system CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
target_link_libraries(seftp_client PRIVATE Boost::system Boost::asio)

find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(seftp_client PRIVATE cryptopp::cryptopp)

set(TRANSFER_INFO_SRC "${CMAKE_SOURCE_DIR}/client/SEFTP-CLIENT/transfer.info")
add_custom_command(TARGET seftp_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${TRANSFER_INFO_SRC}"
            "$<TARGET_FILE_DIR:seftp_client>/transfer.info"
    VERBATIM
)

include(CTest)
enable_testing()

if (BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)

    add_executable(seftp_tests
        tests/client/test_dummy.cpp
	tests/client/proto_le_helpers_test.cpp
	tests/client/proto_request_base_test.cpp
	tests/client/proto_response_parsers_test.cpp
	tests/client/proto_request_builders_test.cpp
	tests/client/net_test.cpp
	tests/client/util_test.cpp
	tests/client/files_test.cpp
	tests/client/logger_test.cpp
	tests/client/crypto_test.cpp
	tests/client/persistence_test.cpp

	client/src/net/net.cpp	
	client/src/util/files.cpp
	client/src/logger/logger.cpp
	client/src/crypto/crypto.cpp
       client/src/persistence/client_persistence.cpp

    )
  target_include_directories(seftp_tests PRIVATE
       client/src
       client/src/crypto
       client/src/net
       client/src/protocol
       client/src/util
       client/src/logger
       client/src/persistence
)
    target_link_libraries(seftp_tests PRIVATE GTest::gtest_main Boost::system Boost::asio cryptopp::cryptopp)
   if (WIN32)
      target_link_libraries(seftp_tests PRIVATE ws2_32)
   endif()

    if (WIN32)
        target_compile_definitions(seftp_tests PRIVATE _WIN32_WINNT=0x0A00)
    endif()

    include(GoogleTest)
    gtest_discover_tests(seftp_tests)

    add_executable(seftp_server_cpp_tests
            server_cpp/tests/protocol_constants_test.cpp
            server_cpp/tests/request_frame_test.cpp
            server_cpp/tests/response_frame_test.cpp
            server_cpp/tests/router_test.cpp
            server_cpp/tests/session_test.cpp
            server_cpp/tests/frame_io_test.cpp
    )
    target_include_directories(seftp_server_cpp_tests PRIVATE
            server_cpp/include
    )

    target_link_libraries(seftp_server_cpp_tests PRIVATE
            GTest::gtest_main
            Boost::system
            Boost::asio
    )

    gtest_discover_tests(seftp_server_cpp_tests)
endif()