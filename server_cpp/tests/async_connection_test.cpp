#include "seftp_server/async_connection.hpp"
#include "seftp_server/protocol.hpp"

#include <boost/asio.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace {

using tcp = boost::asio::ip::tcp;
namespace protocol = seftp::server::protocol;

struct ConnectedSockets {
    tcp::socket client;
    tcp::socket server;
};

ConnectedSockets make_connected_sockets(boost::asio::io_context& io_context) {
    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    tcp::socket client(io_context);
    client.connect(acceptor.local_endpoint());

    tcp::socket server(io_context);
    acceptor.accept(server);

    return {
        std::move(client),
        std::move(server)
    };
}

std::array<protocol::Byte, protocol::kRequestHeaderSize>
make_header(std::uint32_t payload_size) {
    std::array<
        protocol::Byte,
        protocol::kRequestHeaderSize
    > header{};

    const auto offset = protocol::kPayloadSizeOffset;

    header[offset] =
        static_cast<protocol::Byte>(payload_size & 0xFFu);

    header[offset + 1] =
        static_cast<protocol::Byte>((payload_size >> 8) & 0xFFu);

    header[offset + 2] =
        static_cast<protocol::Byte>((payload_size >> 16) & 0xFFu);

    header[offset + 3] =
        static_cast<protocol::Byte>((payload_size >> 24) & 0xFFu);

    return header;
}

TEST(
    AsyncConnectionTest,
    SharedOwnershipKeepsConnectionAliveWhileHeaderReadIsPending
) {
    boost::asio::io_context io_context;

    auto sockets = make_connected_sockets(io_context);

    auto connection =
        std::make_shared<seftp::server::AsyncConnection>(
            std::move(sockets.server)
        );

    std::weak_ptr<seftp::server::AsyncConnection> weak_connection =
        connection;

    connection->start();

    // Remove the AsyncServer-style external owner.
    // The pending read callback should now be the owner keeping the
    // AsyncConnection alive.
    connection.reset();

    EXPECT_FALSE(weak_connection.expired());

    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();

    // The read callback has completed and no new async operation was
    // started, so its captured shared_ptr should have been released.
    EXPECT_TRUE(weak_connection.expired());
}

TEST(
    AsyncConnectionTest,
    HeaderWithPayloadStartsASecondAsyncRead
) {
    boost::asio::io_context io_context;

    auto sockets = make_connected_sockets(io_context);

    auto connection =
        std::make_shared<seftp::server::AsyncConnection>(
            std::move(sockets.server)
        );

    std::weak_ptr<seftp::server::AsyncConnection> weak_connection =
        connection;

    connection->start();
    connection.reset();

    constexpr std::uint32_t kPayloadSize = 3;

    const auto header = make_header(kPayloadSize);

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(header)
    );

    // Process the completed header read without blocking waiting for
    // the payload.
    ASSERT_EQ(io_context.run_one(), 1u);

    // The header callback should have started read_payload().
    // Its callback captures another shared_ptr, so the connection
    // should still be alive while waiting for payload bytes.
    EXPECT_FALSE(weak_connection.expired());

    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();

    // Closing the client completes the pending payload read with an
    // error. No further async operation remains.
    EXPECT_TRUE(weak_connection.expired());
}

TEST(
    AsyncConnectionTest,
    CompletePayloadReadFinishesTheAsyncRequest
) {
    boost::asio::io_context io_context;

    auto sockets = make_connected_sockets(io_context);

    auto connection =
        std::make_shared<seftp::server::AsyncConnection>(
            std::move(sockets.server)
        );

    std::weak_ptr<seftp::server::AsyncConnection> weak_connection =
        connection;

    connection->start();
    connection.reset();

    constexpr std::uint32_t kPayloadSize = 3;

    const auto header = make_header(kPayloadSize);

    const std::array<protocol::Byte, kPayloadSize> payload{
        0x11,
        0x22,
        0x33
    };

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(header)
    );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(payload)
    );

    io_context.run();

    // read_header -> read_payload -> process_frame completed.
    //
    // The frame itself intentionally contains otherwise-zero protocol
    // fields; parser correctness is covered by request_frame_test.cpp.
    // This test is about the async transport/lifetime chain.
    EXPECT_TRUE(weak_connection.expired());
}

TEST(
    AsyncConnectionTest,
    OversizedPayloadIsRejectedBeforeStartingPayloadRead
) {
    boost::asio::io_context io_context;

    auto sockets = make_connected_sockets(io_context);

    auto connection =
        std::make_shared<seftp::server::AsyncConnection>(
            std::move(sockets.server)
        );

    std::weak_ptr<seftp::server::AsyncConnection> weak_connection =
        connection;

    connection->start();
    connection.reset();

    const auto oversized_payload =
        static_cast<std::uint32_t>(
            protocol::kDefaultMaxPayloadSize
        ) + 1u;

    const auto header =
        make_header(oversized_payload);

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(header)
    );

    // Wait until the pending header read actually completes.
    // The header callback should reject the oversized payload and
    // must not start another asynchronous read.
    ASSERT_EQ(io_context.run_one(), 1u);

    EXPECT_TRUE(weak_connection.expired());
}

} // namespace