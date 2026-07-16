#include "seftp_server/frame_io.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

namespace {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

using seftp::server::frameio::FrameIoError;
using seftp::server::frameio::read_request_frame;
using seftp::server::frameio::write_response_frame;

using seftp::server::protocol::Byte;
using seftp::server::protocol::ParseError;
using seftp::server::protocol::RequestCode;
using seftp::server::protocol::ResponseCode;
using seftp::server::protocol::ResponseFrame;
using seftp::server::protocol::build_response_frame;
using seftp::server::protocol::kClientIdSize;
using seftp::server::protocol::kCodeSize;
using seftp::server::protocol::kDefaultMaxPayloadSize;
using seftp::server::protocol::kPayloadSizeFieldSize;
using seftp::server::protocol::kRequestHeaderSize;
using seftp::server::protocol::kVersionSize;

struct ConnectedSockets {
    asio::io_context io_context;
    tcp::acceptor acceptor;
    tcp::socket client;
    tcp::socket server;

    ConnectedSockets()
        : acceptor(
              io_context,
              tcp::endpoint(tcp::v4(), 0)
          ),
          client(io_context),
          server(io_context) {
        std::thread accept_thread([this] {
            acceptor.accept(server);
        });

        client.connect(
            tcp::endpoint(
                asio::ip::address_v4::loopback(),
                acceptor.local_endpoint().port()
            )
        );

        accept_thread.join();
    }
};

std::vector<Byte> make_request_bytes(
    std::uint16_t raw_code,
    const std::vector<Byte>& payload = {}
) {
    std::vector<Byte> bytes;
    bytes.reserve(kRequestHeaderSize + payload.size());

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        bytes.push_back(static_cast<Byte>(i));
    }

    bytes.push_back(7);

    bytes.push_back(
        static_cast<Byte>(raw_code & 0xFF)
    );
    bytes.push_back(
        static_cast<Byte>((raw_code >> 8) & 0xFF)
    );

    const auto payload_size =
        static_cast<std::uint32_t>(payload.size());

    for (std::size_t i = 0; i < kPayloadSizeFieldSize; ++i) {
        bytes.push_back(
            static_cast<Byte>(
                (payload_size >> (8 * i)) & 0xFF
            )
        );
    }

    bytes.insert(
        bytes.end(),
        payload.begin(),
        payload.end()
    );

    return bytes;
}

std::array<Byte, kRequestHeaderSize>
make_header_with_declared_payload_size(
    std::uint16_t raw_code,
    std::uint32_t payload_size
) {
    std::array<Byte, kRequestHeaderSize> header{};

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        header[i] = static_cast<Byte>(i);
    }

    const std::size_t version_offset = kClientIdSize;
    const std::size_t code_offset =
        version_offset + kVersionSize;
    const std::size_t payload_size_offset =
        code_offset + kCodeSize;

    header[version_offset] = 7;

    header[code_offset] =
        static_cast<Byte>(raw_code & 0xFF);
    header[code_offset + 1] =
        static_cast<Byte>((raw_code >> 8) & 0xFF);

    for (std::size_t i = 0; i < kPayloadSizeFieldSize; ++i) {
        header[payload_size_offset + i] =
            static_cast<Byte>(
                (payload_size >> (8 * i)) & 0xFF
            );
    }

    return header;
}

TEST(FrameIoTest, ReadsValidRequestFrame) {
    ConnectedSockets sockets;

    const std::vector<Byte> payload{
        0x10,
        0x20,
        0x30,
        0x40
    };

    const auto bytes = make_request_bytes(
        static_cast<std::uint16_t>(RequestCode::Upload),
        payload
    );

    asio::write(
        sockets.client,
        asio::buffer(bytes)
    );

    const auto result =
        read_request_frame(sockets.server);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_FALSE(result.parse_error.has_value());
    EXPECT_FALSE(result.io_error.has_value());

    EXPECT_EQ(result.frame->version, 7);
    EXPECT_EQ(result.frame->code, RequestCode::Upload);
    EXPECT_EQ(result.frame->payload, payload);

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        EXPECT_EQ(
            result.frame->client_id[i],
            static_cast<Byte>(i)
        );
    }
}

TEST(FrameIoTest, HandlesPartialHeaderAndPayloadWrites) {
    ConnectedSockets sockets;

    const std::vector<Byte> payload{
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE
    };

    const auto bytes = make_request_bytes(
        static_cast<std::uint16_t>(RequestCode::Upload),
        payload
    );

    asio::write(
        sockets.client,
        asio::buffer(bytes.data(), 5)
    );

    asio::write(
        sockets.client,
        asio::buffer(bytes.data() + 5, 8)
    );

    asio::write(
        sockets.client,
        asio::buffer(
            bytes.data() + 13,
            kRequestHeaderSize - 13
        )
    );

    asio::write(
        sockets.client,
        asio::buffer(
            bytes.data() + kRequestHeaderSize,
            2
        )
    );

    asio::write(
        sockets.client,
        asio::buffer(
            bytes.data() + kRequestHeaderSize + 2,
            payload.size() - 2
        )
    );

    const auto result =
        read_request_frame(sockets.server);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_FALSE(result.parse_error.has_value());
    EXPECT_FALSE(result.io_error.has_value());

    EXPECT_EQ(result.frame->code, RequestCode::Upload);
    EXPECT_EQ(result.frame->payload, payload);
}

TEST(FrameIoTest, ReturnsConnectionClosedWhenSocketClosesDuringHeader) {
    ConnectedSockets sockets;

    const std::array<Byte, 5> partial_header{
        0x01,
        0x02,
        0x03,
        0x04,
        0x05
    };

    asio::write(
        sockets.client,
        asio::buffer(partial_header)
    );

    boost::system::error_code shutdown_error;
    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    const auto result =
        read_request_frame(sockets.server);

    EXPECT_FALSE(result.frame.has_value());
    EXPECT_FALSE(result.parse_error.has_value());

    ASSERT_TRUE(result.io_error.has_value());
    EXPECT_EQ(
        *result.io_error,
        FrameIoError::ConnectionClosed
    );
}

TEST(FrameIoTest, ReturnsConnectionClosedWhenSocketClosesDuringPayload) {
    ConnectedSockets sockets;

    constexpr std::uint32_t declared_payload_size = 5;

    const auto header =
        make_header_with_declared_payload_size(
            static_cast<std::uint16_t>(RequestCode::Upload),
            declared_payload_size
        );

    const std::array<Byte, 2> partial_payload{
        0xAA,
        0xBB
    };

    asio::write(
        sockets.client,
        asio::buffer(header)
    );

    asio::write(
        sockets.client,
        asio::buffer(partial_payload)
    );

    boost::system::error_code shutdown_error;
    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    const auto result =
        read_request_frame(sockets.server);

    EXPECT_FALSE(result.frame.has_value());
    EXPECT_FALSE(result.parse_error.has_value());

    ASSERT_TRUE(result.io_error.has_value());
    EXPECT_EQ(
        *result.io_error,
        FrameIoError::ConnectionClosed
    );
}

TEST(FrameIoTest, WritesCompleteResponseFrame) {
    ConnectedSockets sockets;

    const ResponseFrame frame{
        7,
        ResponseCode::ServerError,
        {0x10, 0x20, 0x30}
    };

    const auto expected =
        build_response_frame(frame);

    const auto write_error =
        write_response_frame(
            sockets.server,
            frame
        );

    ASSERT_FALSE(write_error.has_value());

    std::vector<Byte> received(expected.size());

    boost::system::error_code read_error;
    asio::read(
        sockets.client,
        asio::buffer(received),
        read_error
    );

    ASSERT_FALSE(read_error);
    EXPECT_EQ(received, expected);
}

TEST(FrameIoTest, RejectsOversizedDeclaredPayloadBeforeReadingPayload) {
    ConnectedSockets sockets;

    const auto oversized =
        static_cast<std::uint32_t>(
            kDefaultMaxPayloadSize + 1
        );

    const auto header =
        make_header_with_declared_payload_size(
            static_cast<std::uint16_t>(RequestCode::Upload),
            oversized
        );

    asio::write(
        sockets.client,
        asio::buffer(header)
    );

    const auto result =
        read_request_frame(sockets.server);

    EXPECT_FALSE(result.frame.has_value());
    EXPECT_FALSE(result.io_error.has_value());

    ASSERT_TRUE(result.parse_error.has_value());
    EXPECT_EQ(
        *result.parse_error,
        ParseError::PayloadTooLarge
    );
}

}  // namespace