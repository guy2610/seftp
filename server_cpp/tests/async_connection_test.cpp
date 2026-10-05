#include "seftp_server/async_connection.hpp"
#include "seftp_server/protocol.hpp"

#include <boost/asio.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <chrono>

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

constexpr std::uint8_t kTestVersion = 3;

std::vector<protocol::Byte> make_request(
    protocol::RequestCode code
) {
    std::vector<protocol::Byte> bytes(
        protocol::kRequestHeaderSize,
        0
    );

    std::size_t offset = protocol::kClientIdSize;

    bytes[offset] = kTestVersion;
    offset += protocol::kVersionSize;

    const auto raw_code =
        static_cast<std::uint16_t>(code);

    bytes[offset] =
        static_cast<protocol::Byte>(
            raw_code & 0xFFu
        );

    bytes[offset + 1] =
        static_cast<protocol::Byte>(
            (raw_code >> 8) & 0xFFu
        );

    // payload_size remains zero because the vector
    // was initialized with zeroes.

    return bytes;
}

struct ReceivedResponse {
    std::uint8_t version;
    std::uint16_t code;
    std::uint32_t payload_size;
};

ReceivedResponse read_response(tcp::socket& client) {
    std::array<
        protocol::Byte,
        protocol::kResponseHeaderSize
    > header{};

    boost::asio::read(
        client,
        boost::asio::buffer(header)
    );

    const std::uint16_t code =
          static_cast<std::uint16_t>(header[1])
        | (static_cast<std::uint16_t>(header[2]) << 8);

    const std::uint32_t payload_size =
          static_cast<std::uint32_t>(header[3])
        | (static_cast<std::uint32_t>(header[4]) << 8)
        | (static_cast<std::uint32_t>(header[5]) << 16)
        | (static_cast<std::uint32_t>(header[6]) << 24);

    return {
        header[0],
        code,
        payload_size
    };
}

    void run_until_response_available(
        boost::asio::io_context& io_context,
        tcp::socket& client
    ) {
    using namespace std::chrono_literals;

    const auto deadline =
        std::chrono::steady_clock::now() + 1s;

    while (client.available() < protocol::kResponseHeaderSize) {
        ASSERT_LT(
            std::chrono::steady_clock::now(),
            deadline
        ) << "Timed out waiting for server response";

        io_context.run_one_for(10ms);
    }
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

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(500);

    while (
        !weak_connection.expired() &&
        std::chrono::steady_clock::now() < deadline
    ) {
        io_context.run_one_for(
            std::chrono::milliseconds(10)
        );
    }

    EXPECT_TRUE(weak_connection.expired());
}

    TEST(
    AsyncConnectionTest,
    ClientHelloReceivesServerHello
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    connection->start();

    const auto request =
        make_request(
            protocol::RequestCode::ClientHello
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(request)
    );

    run_until_response_available(
    io_context,
    sockets.client
);

    const auto response =
        read_response(sockets.client);

    EXPECT_EQ(response.version, kTestVersion);

    EXPECT_EQ(
        response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerHello
        )
    );

    EXPECT_EQ(response.payload_size, 0u);

    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();
}
    TEST(
    AsyncConnectionTest,
    ApplicationRequestBeforeHandshakeReceivesServerError
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    connection->start();

    const auto request =
        make_request(
            protocol::RequestCode::Upload
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(request)
    );

    run_until_response_available(
    io_context,
    sockets.client
);

    const auto response =
        read_response(sockets.client);

    EXPECT_EQ(
        response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerError
        )
    );

    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();
}
    TEST(
    AsyncConnectionTest,
    HandlesMultipleRequestsOnSameConnection
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    connection->start();

    // Request #1: ClientHello
    const auto hello =
        make_request(
            protocol::RequestCode::ClientHello
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(hello)
    );

    run_until_response_available(
    io_context,
    sockets.client
);

    const auto hello_response =
        read_response(sockets.client);

    EXPECT_EQ(
        hello_response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerHello
        )
    );

    // The write callback should already have called
    // read_header(), so the same connection is now
    // waiting for request #2.

    const auto ack =
        make_request(
            protocol::RequestCode::ClientHandshakeAck
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(ack)
    );

    run_until_response_available(
    io_context,
    sockets.client
);

    const auto ack_response =
        read_response(sockets.client);

    EXPECT_EQ(
        ack_response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::MessageReceived
        )
    );

    // Session should now be HandshakeComplete.
    const auto upload =
        make_request(
            protocol::RequestCode::Upload
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(upload)
    );

    run_until_response_available(
    io_context,
    sockets.client
);

    const auto upload_response =
        read_response(sockets.client);

    EXPECT_EQ(
        upload_response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::MessageReceived
        )
    );

    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();
}
    TEST(
    AsyncConnectionTest,
    ConcurrentConnectionsKeepIndependentSessionState
) {
    boost::asio::io_context io_context;

    auto sockets_a =
        make_connected_sockets(io_context);

    auto sockets_b =
        make_connected_sockets(io_context);

    auto connection_a =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets_a.server));

    auto connection_b =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets_b.server));

    connection_a->start();
    connection_b->start();

    const auto hello_a =
        make_request(
            protocol::RequestCode::ClientHello
        );

    const auto upload_b =
        make_request(
            protocol::RequestCode::Upload
        );

    boost::asio::write(
        sockets_a.client,
        boost::asio::buffer(hello_a)
    );

    boost::asio::write(
        sockets_b.client,
        boost::asio::buffer(upload_b)
    );

    run_until_response_available(
        io_context,
        sockets_a.client
    );

    run_until_response_available(
        io_context,
        sockets_b.client
    );

    const auto response_a =
        read_response(sockets_a.client);

    const auto response_b =
        read_response(sockets_b.client);

    EXPECT_EQ(
        response_a.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerHello
        )
    );

    EXPECT_EQ(
        response_b.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerError
        )
    );

    // A progressed to AwaitingHandshakeAck.
    // B must still be AwaitingClientHello.
    const auto ack_a =
        make_request(
            protocol::RequestCode::ClientHandshakeAck
        );

    const auto hello_b =
        make_request(
            protocol::RequestCode::ClientHello
        );

    boost::asio::write(
        sockets_a.client,
        boost::asio::buffer(ack_a)
    );

    boost::asio::write(
        sockets_b.client,
        boost::asio::buffer(hello_b)
    );

    run_until_response_available(
        io_context,
        sockets_a.client
    );

    run_until_response_available(
        io_context,
        sockets_b.client
    );

    const auto second_response_a =
        read_response(sockets_a.client);

    const auto second_response_b =
        read_response(sockets_b.client);

    EXPECT_EQ(
        second_response_a.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::MessageReceived
        )
    );

    EXPECT_EQ(
        second_response_b.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerHello
        )
    );

    boost::system::error_code ec;

    sockets_a.client.close(ec);
    sockets_b.client.close(ec);

    io_context.run();
}
    


    TEST(
    AsyncConnectionTest,
    HeaderReadTimeoutReleasesConnection
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(
            std::move(sockets.server),
            std::chrono::milliseconds(20)
        );

    std::weak_ptr<seftp::server::AsyncConnection>
        weak_connection = connection;

    connection->start();
    connection.reset();

    // Client stays connected but sends nothing.
    //
    // The timer should expire, close the server socket,
    // and cause the pending async_read to complete with
    // an error.
    io_context.run();

    EXPECT_TRUE(weak_connection.expired());

    boost::system::error_code ec;
    sockets.client.close(ec);
}


TEST(
    AsyncConnectionTest,
    PayloadReadTimeoutReleasesConnection
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(
            std::move(sockets.server),
            std::chrono::milliseconds(20)
        );

    std::weak_ptr<seftp::server::AsyncConnection>
        weak_connection = connection;

    connection->start();
    connection.reset();

    constexpr std::uint32_t kPayloadSize = 3;

    const auto header =
        make_header(kPayloadSize);

    // Send the complete header but intentionally never
    // send the three payload bytes.
    boost::asio::write(
        sockets.client,
        boost::asio::buffer(header)
    );

    // Header read succeeds and starts read_payload().
    // Then the payload timer should expire.
    io_context.run();

    EXPECT_TRUE(weak_connection.expired());

    boost::system::error_code ec;
    sockets.client.close(ec);
}


TEST(
    AsyncConnectionTest,
    RequestBeforeTimeoutReceivesResponseNormally
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(
            std::move(sockets.server),
            std::chrono::milliseconds(100)
        );

    std::weak_ptr<seftp::server::AsyncConnection>
        weak_connection = connection;

    connection->start();
    connection.reset();

    const auto request =
        make_request(
            protocol::RequestCode::ClientHello
        );

    boost::asio::write(
        sockets.client,
        boost::asio::buffer(request)
    );

    run_until_response_available(
        io_context,
        sockets.client
    );

    const auto response =
        read_response(sockets.client);

    EXPECT_EQ(
        response.code,
        static_cast<std::uint16_t>(
            protocol::ResponseCode::ServerHello
        )
    );

    EXPECT_FALSE(weak_connection.expired());

    // End the connection explicitly instead of waiting
    // for the timeout of the next request.
    boost::system::error_code ec;
    sockets.client.close(ec);

    io_context.run();

    EXPECT_TRUE(weak_connection.expired());
}
    TEST(
    AsyncConnectionTest,
    StopWhileHeaderReadIsPendingReleasesConnection
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    std::weak_ptr<seftp::server::AsyncConnection>
        weak_connection = connection;

    connection->start();

    // Header read + timeout are now pending.
    connection->stop();
    connection.reset();

    // stop() closes the socket and cancels the timer.
    // Their callbacks still need to be dispatched.
    io_context.run();

    EXPECT_TRUE(weak_connection.expired());

    boost::system::error_code ec;
    sockets.client.close(ec);
}


TEST(
    AsyncConnectionTest,
    StopIsIdempotent
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    connection->start();

    // Multiple stop calls must be harmless.
    EXPECT_NO_THROW(connection->stop());
    EXPECT_NO_THROW(connection->stop());
    EXPECT_NO_THROW(connection->stop());

    connection.reset();

    io_context.run();

    boost::system::error_code ec;
    sockets.client.close(ec);
}


TEST(
    AsyncConnectionTest,
    StopPreventsPendingRequestFromBeingProcessed
) {
    boost::asio::io_context io_context;

    auto sockets =
        make_connected_sockets(io_context);

    auto connection =
        std::make_shared<
            seftp::server::AsyncConnection
        >(std::move(sockets.server));

    connection->start();

    const auto request =
        make_request(
            protocol::RequestCode::ClientHello
        );

    // Put a valid request on the TCP stream.
    boost::asio::write(
        sockets.client,
        boost::asio::buffer(request)
    );

    // Stop before the io_context gets a chance to run
    // the server-side read completion handler.
    connection->stop();

    io_context.run();

    // The connection must not have processed the request
    // and produced a response after stop().
    boost::system::error_code ec;

    const auto available =
        sockets.client.available(ec);

    if (!ec) {
        EXPECT_EQ(available, 0u);
    }

    sockets.client.close(ec);
}
} // namespace