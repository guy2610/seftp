cmake_minimum_required(VERSION 3.21)
project(SEFFP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(seffp_client
    client/src/client_tirgul.cpp
    client/src/crypto/crypto.cpp
    client/src/net/net.cpp
    client/src/util/files.cpp
)

target_include_directories(seffp_client PRIVATE
    client/src
    client/src/crypto
    client/src/net
    client/src/protocol
    client/src/util
)
# Make Crypto++ headers available for includes like "cryptlib.h"
if (DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    target_include_directories(seffp_client PRIVATE
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include/cryptopp"
    )
endif()


if (WIN32)
    target_link_libraries(seffp_client PRIVATE ws2_32)
endif()

find_package(boost_system CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
target_link_libraries(seffp_client PRIVATE Boost::system Boost::asio)

find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(seffp_client PRIVATE cryptopp::cryptopp)

# Copy runtime config next to the built exe (working dir = exe dir)
set(TRANSFER_INFO_SRC "${CMAKE_SOURCE_DIR}/client/SEFFP-CLIENT/transfer.info")
add_custom_command(TARGET seffp_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${TRANSFER_INFO_SRC}"
            "$<TARGET_FILE_DIR:seffp_client>/transfer.info"
    VERBATIM
)
