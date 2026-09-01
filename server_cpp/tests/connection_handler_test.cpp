#include "seftp_server/connection_handler.hpp"
#include "seftp_server/protocol.hpp"
#include "seftp_server/response_frame.hpp"
#include "seftp_server/router.hpp"
#include "seftp_server/session.hpp"

#include <future>
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

using seftp::server::connection_handler::ConnectionResult;
using seftp::server::connection_handler::handle_one_request;
    using seftp::server::connection_handler::handle_connection;

using seftp::server::protocol::Byte;
using seftp::server::protocol::RequestCode;
using seftp::server::protocol::ResponseCode;
using seftp::server::protocol::ResponseFrame;

using seftp::server::protocol::kClientIdSize;
using seftp::server::protocol::kPayloadSizeFieldSize;
using seftp::server::protocol::kRequestHeaderSize;
using seftp::server::protocol::kResponseHeaderSize;

using seftp::server::router::SessionState;
using seftp::server::session::Session;

constexpr std::uint8_t kTestVersion = 7;

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

    // client_id
    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        bytes.push_back(static_cast<Byte>(i));
    }

    // version
    bytes.push_back(kTestVersion);

    // request code - little endian
    bytes.push_back(
        static_cast<Byte>(raw_code & 0xFF)
    );
    bytes.push_back(
        static_cast<Byte>((raw_code >> 8) & 0xFF)
    );

    // payload size - little endian
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

void send_request(
    tcp::socket& client,
    RequestCode code,
    const std::vector<Byte>& payload = {}
) {
    const auto bytes = make_request_bytes(
        static_cast<std::uint16_t>(code),
        payload
    );

    asio::write(
        client,
        asio::buffer(bytes)
    );
}

std::vector<Byte> read_empty_response(
    tcp::socket& client
) {
    std::vector<Byte> bytes(kResponseHeaderSize);

    asio::read(
        client,
        asio::buffer(bytes)
    );

    return bytes;
}

std::vector<Byte> expected_empty_response(
    ResponseCode code
) {
    return seftp::server::protocol::build_response_frame(
        ResponseFrame{
            kTestVersion,
            code,
            {}
        }
    );
}

TEST(ConnectionHandlerTest, ClientHelloSendsServerHello) {
    ConnectedSockets sockets;
    Session session;

    send_request(
        sockets.client,
        RequestCode::ClientHello
    );

    const auto result =
        handle_one_request(
            sockets.server,
            session
        );

    EXPECT_EQ(
        result,
        ConnectionResult::ResponseSent
    );

    EXPECT_EQ(
        session.state(),
        SessionState::AwaitingHandshakeAck
    );

    const auto response =
        read_empty_response(sockets.client);

    EXPECT_EQ(
        response,
        expected_empty_response(
            ResponseCode::ServerHello
        )
    );
}

TEST(ConnectionHandlerTest, RejectsApplicationRequestBeforeHandshake) {
    ConnectedSockets sockets;
    Session session;

    send_request(
        sockets.client,
        RequestCode::Upload
    );

    const auto result =
        handle_one_request(
            sockets.server,
            session
        );

    EXPECT_EQ(
        result,
        ConnectionResult::ResponseSent
    );

    EXPECT_EQ(
        session.state(),
        SessionState::AwaitingClientHello
    );

    const auto response =
        read_empty_response(sockets.client);

    EXPECT_EQ(
        response,
        expected_empty_response(
            ResponseCode::ServerError
        )
    );
}

TEST(ConnectionHandlerTest, HandshakeAckAfterClientHelloCompletesHandshake) {
    ConnectedSockets sockets;
    Session session;

    // First request: ClientHello
    send_request(
        sockets.client,
        RequestCode::ClientHello
    );

    ASSERT_EQ(
        handle_one_request(
            sockets.server,
            session
        ),
        ConnectionResult::ResponseSent
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::ServerHello
        )
    );

    ASSERT_EQ(
        session.state(),
        SessionState::AwaitingHandshakeAck
    );

    // Second request: ClientHandshakeAck
    send_request(
        sockets.client,
        RequestCode::ClientHandshakeAck
    );

    ASSERT_EQ(
        handle_one_request(
            sockets.server,
            session
        ),
        ConnectionResult::ResponseSent
    );

    EXPECT_EQ(
        session.state(),
        SessionState::HandshakeComplete
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::MessageReceived
        )
    );
}

TEST(ConnectionHandlerTest, ApplicationRequestAfterHandshakeGetsMessageReceived) {
    ConnectedSockets sockets;
    Session session;

    // Complete the simplified handshake first.
    send_request(
        sockets.client,
        RequestCode::ClientHello
    );

    ASSERT_EQ(
        handle_one_request(
            sockets.server,
            session
        ),
        ConnectionResult::ResponseSent
    );

    read_empty_response(sockets.client);

    send_request(
        sockets.client,
        RequestCode::ClientHandshakeAck
    );

    ASSERT_EQ(
        handle_one_request(
            sockets.server,
            session
        ),
        ConnectionResult::ResponseSent
    );

    read_empty_response(sockets.client);

    ASSERT_EQ(
        session.state(),
        SessionState::HandshakeComplete
    );

    // Now send an application request.
    send_request(
        sockets.client,
        RequestCode::Upload
    );

    const auto result =
        handle_one_request(
            sockets.server,
            session
        );

    EXPECT_EQ(
        result,
        ConnectionResult::ResponseSent
    );

    EXPECT_EQ(
        session.state(),
        SessionState::HandshakeComplete
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::MessageReceived
        )
    );
}

TEST(ConnectionHandlerTest, MalformedRequestReturnsProtocolError) {
    ConnectedSockets sockets;
    Session session;

    constexpr std::uint16_t unknown_code = 9999;

    const auto bytes =
        make_request_bytes(unknown_code);

    asio::write(
        sockets.client,
        asio::buffer(bytes)
    );

    const auto result =
        handle_one_request(
            sockets.server,
            session
        );

    EXPECT_EQ(
        result,
        ConnectionResult::ProtocolError
    );

    EXPECT_EQ(
        session.state(),
        SessionState::AwaitingClientHello
    );
}

TEST(ConnectionHandlerTest, ClosedConnectionReturnsConnectionLost) {
    ConnectedSockets sockets;
    Session session;

    boost::system::error_code error;

    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        error
    );

    const auto result =
        handle_one_request(
            sockets.server,
            session
        );

    EXPECT_EQ(
        result,
        ConnectionResult::ConnectionLost
    );

    EXPECT_EQ(
        session.state(),
        SessionState::AwaitingClientHello
    );
}

    TEST(ConnectionHandlerTest, HandlesMultipleRequestsOnSameConnection) {
    ConnectedSockets sockets;

    auto server_result = std::async(
        std::launch::async,
        [&sockets] {
            return handle_connection(sockets.server);
        }
    );

    // Request #1: ClientHello
    send_request(
        sockets.client,
        RequestCode::ClientHello
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::ServerHello
        )
    );

    // Request #2: handshake acknowledgement
    send_request(
        sockets.client,
        RequestCode::ClientHandshakeAck
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::MessageReceived
        )
    );

    // Request #3: application request.
    // This succeeds only if the same Session survived
    // the previous two requests.
    send_request(
        sockets.client,
        RequestCode::Upload
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::MessageReceived
        )
    );

    boost::system::error_code shutdown_error;

    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    EXPECT_EQ(
        server_result.get(),
        ConnectionResult::ConnectionLost
    );
}

    TEST(ConnectionHandlerTest, ContinuesAfterRejectedRequest) {
    ConnectedSockets sockets;

    auto server_result = std::async(
        std::launch::async,
        [&sockets] {
            return handle_connection(sockets.server);
        }
    );

    // Valid frame, but invalid for current session state.
    send_request(
        sockets.client,
        RequestCode::Upload
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::ServerError
        )
    );

    // The connection should still be alive,
    // and the session should still expect ClientHello.
    send_request(
        sockets.client,
        RequestCode::ClientHello
    );

    EXPECT_EQ(
        read_empty_response(sockets.client),
        expected_empty_response(
            ResponseCode::ServerHello
        )
    );

    boost::system::error_code shutdown_error;

    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    EXPECT_EQ(
        server_result.get(),
        ConnectionResult::ConnectionLost
    );
}

    TEST(ConnectionHandlerTest, StopsOnProtocolError) {
    ConnectedSockets sockets;

    auto server_result = std::async(
        std::launch::async,
        [&sockets] {
            return handle_connection(sockets.server);
        }
    );

    constexpr std::uint16_t unknown_code = 9999;

    const auto bytes =
        make_request_bytes(unknown_code);

    asio::write(
        sockets.client,
        asio::buffer(bytes)
    );

    EXPECT_EQ(
        server_result.get(),
        ConnectionResult::ProtocolError
    );
}

    TEST(ConnectionHandlerTest, ReturnsConnectionLostWhenClientClosesConnection) {
    ConnectedSockets sockets;

    boost::system::error_code shutdown_error;

    sockets.client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    EXPECT_EQ(
        handle_connection(sockets.server),
        ConnectionResult::ConnectionLost
    );
}

    

}