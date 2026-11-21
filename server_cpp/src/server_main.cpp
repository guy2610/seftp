#include <boost/asio.hpp>

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <thread>
#include <vector>

#include "seftp_server/async_server.hpp"

constexpr std::uint16_t kServerPort = 1234;
constexpr std::size_t kIoThreadCount = 4;
inline const std::string kDbPath = "DB.db";

int main() {
    try {
        std::shared_ptr<seftp::server::persistence::DbExecutor> db_executor =
            std::make_shared<seftp::server::persistence::DbExecutor>(kDbPath);
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(),
                                                kServerPort);
        boost::asio::ip::tcp::acceptor acceptor(io_context, endpoint);
        seftp::server::log_line("Server listening on port " + std::to_string(kServerPort));
        seftp::server::AsyncServer server(acceptor, db_executor);
        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        server.start();
        signals.async_wait([&](const boost::system::error_code& ec, int signal_number) {
            if (ec) {
                seftp::server::log_error("Error in signal set " + ec.message());
                return;
            }
            seftp::server::log_line("Received signal " + std::to_string(signal_number) +
                                    ", shutting down");
            server.stop();
        });

        std::vector<std::thread> workers;
        workers.reserve(kIoThreadCount);

        for (std::size_t i = 0; i < kIoThreadCount; ++i) {
            workers.emplace_back([&io_context]() {
                io_context.run();
            });
        }
        for (auto& worker : workers) {
            worker.join();
        }
        return 0;
    } catch (const std::exception& e) {
        seftp::server::log_error("Server error: " + std::string(e.what()));
        return 1;
    }
}