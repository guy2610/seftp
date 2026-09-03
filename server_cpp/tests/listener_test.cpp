#include "seftp_server/listener.hpp"
#include "seftp_server/protocol.hpp"
#include "seftp_server/response_frame.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <future>
#include <variant>
#include <vector>

namespace {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

using seftp::server::connection_handler::ConnectionResult;

using seftp::server::listener::AcceptFailed;
using seftp::server::listener::ListenerResult;
using seftp::server::listener::accept_one_connection;

using seftp::server::protocol::Byte;
using seftp::server::protocol::RequestCode;
using seftp::server::protocol::ResponseCode;
using seftp::server::protocol::ResponseFrame;

using seftp::server::protocol::kClientIdSize;
using seftp::server::protocol::kPayloadSizeFieldSize;
using seftp::server::protocol::kRequestHeaderSize;
using seftp::server::protocol::kResponseHeaderSize;

constexpr std::uint8_t kTestVersion = 7;

std::vector<Byte> make_request_bytes(
    RequestCode code,
    const std::vector<Byte>& payload = {}
) {
    std::vector<Byte> bytes;
    bytes.reserve(kRequestHeaderSize + payload.size());

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        bytes.push_back(static_cast<Byte>(i));
    }

    bytes.push_back(kTestVersion);

    const auto raw_code =
        static_cast<std::uint16_t>(code);

    bytes.push_back(
        static_cast<Byte>(raw_code & 0xFF)
    );

    bytes.push_back(
        static_cast<Byte>((raw_code >> 8) & 0xFF)
    );

    const auto payload_size =
        static_cast<std::uint32_t>(payload.size());

    for (
        std::size_t i = 0;
        i < kPayloadSizeFieldSize;
        ++i
    ) {
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

TEST(ListenerTest, ReturnsAcceptFailedWhenAcceptorIsClosed) {
    asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(tcp::v4(), 0)
    );

    boost::system::error_code close_error;
    acceptor.close(close_error);

    const ListenerResult result =
        accept_one_connection(acceptor);

    EXPECT_TRUE(
        std::holds_alternative<AcceptFailed>(result)
    );
}

TEST(ListenerTest, ReturnsConnectionResultAfterAcceptedClientCloses) {
    asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(tcp::v4(), 0)
    );

    const auto endpoint =
        acceptor.local_endpoint();

    auto server_result = std::async(
        std::launch::async,
        [&acceptor] {
            return accept_one_connection(acceptor);
        }
    );

    tcp::socket client(io_context);

    client.connect(
        tcp::endpoint(
            asio::ip::address_v4::loopback(),
            endpoint.port()
        )
    );

    boost::system::error_code shutdown_error;
    client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    const ListenerResult result =
        server_result.get();

    ASSERT_TRUE(
        std::holds_alternative<ConnectionResult>(result)
    );

    EXPECT_EQ(
        std::get<ConnectionResult>(result),
        ConnectionResult::ConnectionLost
    );
}

TEST(ListenerTest, AcceptsClientAndHandlesRequest) {
    asio::io_context io_context;

    tcp::acceptor acceptor(
        io_context,
        tcp::endpoint(tcp::v4(), 0)
    );

    const auto endpoint =
        acceptor.local_endpoint();

    auto server_result = std::async(
        std::launch::async,
        [&acceptor] {
            return accept_one_connection(acceptor);
        }
    );

    tcp::socket client(io_context);

    client.connect(
        tcp::endpoint(
            asio::ip::address_v4::loopback(),
            endpoint.port()
        )
    );

    const auto request =
        make_request_bytes(RequestCode::ClientHello);

    asio::write(
        client,
        asio::buffer(request)
    );

    std::vector<Byte> response(
        kResponseHeaderSize
    );

    asio::read(
        client,
        asio::buffer(response)
    );

    EXPECT_EQ(
        response,
        expected_empty_response(
            ResponseCode::ServerHello
        )
    );

    boost::system::error_code shutdown_error;
    client.shutdown(
        tcp::socket::shutdown_send,
        shutdown_error
    );

    const ListenerResult result =
        server_result.get();

    ASSERT_TRUE(
        std::holds_alternative<ConnectionResult>(result)
    );

    EXPECT_EQ(
        std::get<ConnectionResult>(result),
        ConnectionResult::ConnectionLost
    );
}

} // namespace