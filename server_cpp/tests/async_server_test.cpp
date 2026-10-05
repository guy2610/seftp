#include "seftp_server/async_server.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <array>
#include <memory>
#include "seftp_server/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <vector>
#include <thread>

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

    bool wait_for_response_available(
    tcp::socket& client,
    std::chrono::milliseconds timeout =
        std::chrono::milliseconds(1000)
) {
        const auto deadline =
            std::chrono::steady_clock::now() + timeout;

        while (std::chrono::steady_clock::now() < deadline) {
            boost::system::error_code ec;

            const auto available = client.available(ec);

            if (ec) {
                return false;
            }

            if (available >= protocol::kResponseHeaderSize) {
                return true;
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(1)
            );
        }

        return false;
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

    TEST(
    AsyncServerTest,
        HandlesMultipleClientsWithMultiThreadedIoContext
) {
        boost::asio::io_context server_io_context;
        boost::asio::io_context client_io_context;

        tcp::acceptor acceptor(
            server_io_context,
            tcp::endpoint(
                boost::asio::ip::address_v4::loopback(),
                0
            )
        );

        seftp::server::AsyncServer server(
            acceptor,
            16
        );

        server.start();

        constexpr std::size_t kWorkerCount = 4;
        constexpr std::size_t kClientCount = 8;

        std::vector<std::thread> workers;
        workers.reserve(kWorkerCount);

        for (std::size_t i = 0; i < kWorkerCount; ++i) {
            workers.emplace_back(
                [&server_io_context]() {
                    server_io_context.run();
                }
            );
        }

        std::vector<tcp::socket> clients;
        clients.reserve(kClientCount);

        const auto hello =
            make_request(
                protocol::RequestCode::ClientHello
            );

        for (std::size_t i = 0; i < kClientCount; ++i) {
            clients.emplace_back(client_io_context);

            clients.back().connect(
                acceptor.local_endpoint()
            );

            boost::asio::write(
                clients.back(),
                boost::asio::buffer(hello)
            );
        }

        for (auto& client : clients) {
            EXPECT_TRUE(
                wait_for_response_available(client)
            );
        }

        for (auto& client : clients) {
            boost::system::error_code ec;

            std::array<
                protocol::Byte,
                protocol::kResponseHeaderSize
            > header{};

            const auto bytes_read =
                boost::asio::read(
                    client,
                    boost::asio::buffer(header),
                    ec
                );

            EXPECT_FALSE(ec);
            EXPECT_EQ(
                bytes_read,
                protocol::kResponseHeaderSize
            );

            if (!ec &&
                bytes_read == protocol::kResponseHeaderSize) {

                const std::uint16_t response_code =
                    static_cast<std::uint16_t>(header[1])
                    |
                    (
                        static_cast<std::uint16_t>(header[2])
                        << 8
                    );

                EXPECT_EQ(
                    response_code,
                    static_cast<std::uint16_t>(
                        protocol::ResponseCode::ServerHello
                    )
                );
                }
        }

        server.stop();

        for (auto& client : clients) {
            boost::system::error_code ignored;
            client.close(ignored);
        }

        for (auto& worker : workers) {
            worker.join();
        }
    }

    bool send_request_and_expect_response(
        tcp::socket& client,
        protocol::RequestCode request_code,
        protocol::ResponseCode expected_response) {
        const auto req = make_request(request_code);
        boost::system::error_code ec;

        const auto bytes_written =
            boost::asio::write(
                client,
                boost::asio::buffer(req),
                ec
            );

        if (ec || bytes_written != req.size()) {
            return false;
        }

        std::array< protocol::Byte,protocol::kResponseHeaderSize> header{};

        if (!wait_for_response_available(client)) {
            return false;
        }

        const auto bytes_read =
            boost::asio::read(
                client,
                boost::asio::buffer(header),
                ec
            );

        if (!ec &&
            bytes_read == protocol::kResponseHeaderSize) {

            const std::uint16_t response_code =
                static_cast<std::uint16_t>(header[1]) | (static_cast<std::uint16_t>(header[2]) << 8);
            return response_code == static_cast<std::uint16_t>(expected_response);

            }
        return false;
    }
    TEST(
    AsyncServerTest,
    HandlesConcurrentMultiRequestClientsAcrossWorkerThreads
) {
        boost::asio::io_context server_io_context;
        constexpr std::size_t kWorkerCount = 4;
        constexpr std::size_t kClientCount = 8;
        constexpr std::size_t kUploadsPerClient = 5;
        std::vector<std::thread> workers;

        std::vector<int> client_results(kClientCount,0);

        tcp::acceptor acceptor(
            server_io_context,
            tcp::endpoint(
                boost::asio::ip::address_v4::loopback(),
                0
            )
        );

        seftp::server::AsyncServer server(
            acceptor,
            16
        );

        server.start();

        workers.reserve(kWorkerCount);

        for (std::size_t i = 0; i < kWorkerCount; ++i) {
            workers.emplace_back(
                [&server_io_context]() {
                    server_io_context.run();
                }
            );
        }

        const auto server_endpoint = acceptor.local_endpoint();
        std::vector<std::thread> clients_threads;
        clients_threads.reserve(kClientCount);

        for (std::size_t i = 0; i < kClientCount; ++i) {
            clients_threads.emplace_back(
                [&,i,server_endpoint]() {
                    boost::asio::io_context client_io_context;
                    tcp::socket client(client_io_context);
                    boost::system::error_code ec;
                    client.connect(server_endpoint, ec);

                    if (ec) {
                        client_results[i] = 0;
                        return;
                    }

                    bool ok = true;

                    ok = ok && send_request_and_expect_response(
                        client,
                        protocol::RequestCode::ClientHello,
                        protocol::ResponseCode::ServerHello
                    );

                    ok = ok && send_request_and_expect_response(
                        client,
                        protocol::RequestCode::ClientHandshakeAck,
                        protocol::ResponseCode::MessageReceived
                    );

                    for (std::size_t upload = 0;
                         upload < kUploadsPerClient;
                         ++upload) {
                        ok = ok && send_request_and_expect_response(
                            client,
                            protocol::RequestCode::Upload,
                            protocol::ResponseCode::MessageReceived);
                    }
                    client_results[i]= ok ? 1 :0;
                });
        }
        for (auto& client_thread : clients_threads) {
            client_thread.join();
        }
        server.stop();

        for (auto& worker : workers) {
            worker.join();
        }

        for (const auto& result : client_results) {
            EXPECT_EQ(result,1);
        }

    }
} // namespace
