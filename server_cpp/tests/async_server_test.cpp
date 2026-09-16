#include "seftp_server/async_server.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <array>
#include <memory>

namespace {

using tcp = boost::asio::ip::tcp;

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

    EXPECT_FALSE(acceptor.is_open());

    // Dispatch the cancelled async_accept handler.
    io_context.run();
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

} // namespace