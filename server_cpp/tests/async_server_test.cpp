#include "seftp_server/async_server.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <array>
#include <memory>
#include "seftp_server/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using tcp = boost::asio::ip::tcp;

    namespace protocol = seftp::server::protocol;

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

        return bytes;
    }

    bool run_until_response_available(
        boost::asio::io_context& io_context,
        tcp::socket& client,
        std::chrono::milliseconds timeout =
            std::chrono::milliseconds(500)
    ) {
        const auto deadline =
            std::chrono::steady_clock::now() + timeout;

        while (
            client.available() < protocol::kResponseHeaderSize &&
            std::chrono::steady_clock::now() < deadline
        ) {
            io_context.run_one_for(
                std::chrono::milliseconds(10)
            );
        }

        return client.available() >=
               protocol::kResponseHeaderSize;
    }

TEST(
    AsyncServerTest,
    StopClosesAcceptor
) {
    boost::asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    seftp::server::AsyncServer server(acceptor);

    server.start();

    EXPECT_TRUE(acceptor.is_open());

        server.stop();

        // stop() is serialized through the server strand.
        // Run the queued work before observing the result.
        io_context.run();

        EXPECT_FALSE(acceptor.is_open());
}


TEST(
    AsyncServerTest,
    StopIsIdempotent
) {
    boost::asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    seftp::server::AsyncServer server(acceptor);

    server.start();

    EXPECT_NO_THROW(server.stop());
    EXPECT_NO_THROW(server.stop());
    EXPECT_NO_THROW(server.stop());

    io_context.run();

    EXPECT_FALSE(acceptor.is_open());
}


TEST(
    AsyncServerTest,
    StopClosesActiveConnection
) {
    boost::asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    seftp::server::AsyncServer server(acceptor);

    server.start();

    tcp::socket client(io_context);
    client.connect(acceptor.local_endpoint());

    // Complete the server-side accept callback.
    ASSERT_EQ(io_context.run_one(), 1u);

    std::array<char, 1> buffer{};

    bool client_read_completed = false;
    boost::system::error_code client_read_error;

    client.async_read_some(
        boost::asio::buffer(buffer),
        [&](const boost::system::error_code& ec,
            std::size_t) {
            client_read_completed = true;
            client_read_error = ec;
        }
    );

    server.stop();

    // Completes:
    // - cancelled accept
    // - cancelled connection timer
    // - server-side pending read
    // - client-side read due to peer closing
    io_context.run();

    EXPECT_TRUE(client_read_completed);
    EXPECT_TRUE(client_read_error);

    EXPECT_TRUE(
        client_read_error == boost::asio::error::eof ||
        client_read_error ==
            boost::asio::error::connection_reset
    );
}


TEST(
    AsyncServerTest,
    StopClosesMultipleActiveConnections
) {
    boost::asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    seftp::server::AsyncServer server(acceptor);

    server.start();

    tcp::socket client_a(io_context);
    tcp::socket client_b(io_context);

    client_a.connect(acceptor.local_endpoint());
    client_b.connect(acceptor.local_endpoint());

    // Accept A.
    ASSERT_EQ(io_context.run_one(), 1u);

    // The accept callback started another async_accept.
    // B is already waiting in the listen backlog.
    ASSERT_EQ(io_context.run_one(), 1u);

    std::array<char, 1> buffer_a{};
    std::array<char, 1> buffer_b{};

    bool a_finished = false;
    bool b_finished = false;

    boost::system::error_code error_a;
    boost::system::error_code error_b;

    client_a.async_read_some(
        boost::asio::buffer(buffer_a),
        [&](const boost::system::error_code& ec,
            std::size_t) {
            a_finished = true;
            error_a = ec;
        }
    );

    client_b.async_read_some(
        boost::asio::buffer(buffer_b),
        [&](const boost::system::error_code& ec,
            std::size_t) {
            b_finished = true;
            error_b = ec;
        }
    );

    server.stop();

    io_context.run();

    EXPECT_TRUE(a_finished);
    EXPECT_TRUE(b_finished);

    EXPECT_TRUE(error_a);
    EXPECT_TRUE(error_b);
}
    TEST(
    AsyncServerTest,
    RejectsConnectionWhenActiveConnectionLimitIsReached
) {
        boost::asio::io_context io_context;

        tcp::acceptor acceptor(
            io_context,
            tcp::endpoint(
                boost::asio::ip::address_v4::loopback(),
                0
            )
        );

        seftp::server::AsyncServer server(
            acceptor,
            1
        );

        server.start();

        tcp::socket client_a(io_context);
        client_a.connect(acceptor.local_endpoint());

        // Accept A and start its AsyncConnection.
        ASSERT_EQ(io_context.run_one(), 1u);

        tcp::socket client_b(io_context);
        client_b.connect(acceptor.local_endpoint());

        // Accept callback sees that A already occupies
        // the only available slot and closes B.
        ASSERT_EQ(io_context.run_one(), 1u);

        // A must still be fully functional.
        const auto hello =
            make_request(
                protocol::RequestCode::ClientHello
            );

        boost::asio::write(
            client_a,
            boost::asio::buffer(hello)
        );

        EXPECT_TRUE(
            run_until_response_available(
                io_context,
                client_a
            )
        );

        // B should observe the peer closing its connection.
        std::array<char, 1> buffer{};
        bool b_finished = false;
        boost::system::error_code b_error;

        client_b.async_read_some(
            boost::asio::buffer(buffer),
            [&](const boost::system::error_code& ec,
                std::size_t) {
                b_finished = true;
                b_error = ec;
            }
        );

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(500);

        while (
            !b_finished &&
            std::chrono::steady_clock::now() < deadline
        ) {
            io_context.run_one_for(
                std::chrono::milliseconds(10)
            );
        }

        EXPECT_TRUE(b_finished);
        EXPECT_TRUE(b_error);

        server.stop();
        io_context.run();
    }

TEST(
    AsyncServerTest,
    AcceptsNewConnectionAfterPreviousConnectionEnds
) {
    boost::asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(
            boost::asio::ip::address_v4::loopback(),
            0
        )
    );

    seftp::server::AsyncServer server(
        acceptor,
        1
    );

    server.start();

    tcp::socket client_a(io_context);
    client_a.connect(acceptor.local_endpoint());

    ASSERT_EQ(io_context.run_one(), 1u);

    // End A.
    boost::system::error_code ignored;
    client_a.close(ignored);

    // Complete A's pending read.
    ASSERT_EQ(
        io_context.run_one_for(
            std::chrono::milliseconds(500)
        ),
        1u
    );

    // Drain the cancelled timer callback as well.
    io_context.poll();

    // A's AsyncConnection should now have no strong owner.
    // The next accept will prune its expired weak_ptr.

    tcp::socket client_c(io_context);
    client_c.connect(acceptor.local_endpoint());

    ASSERT_EQ(
        io_context.run_one_for(
            std::chrono::milliseconds(500)
        ),
        1u
    );

    const auto hello =
        make_request(
            protocol::RequestCode::ClientHello
        );

    boost::asio::write(
        client_c,
        boost::asio::buffer(hello)
    );

    EXPECT_TRUE(
        run_until_response_available(
            io_context,
            client_c
        )
    );

    server.stop();
    io_context.run();
}
} // namespace
