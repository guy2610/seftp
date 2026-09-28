#include <boost/asio.hpp>

#include <cstdint>
#include <exception>
#include <iostream>
#include <csignal>
#include <thread>
#include <vector>
#include <cstddef>

#include "seftp_server/async_server.hpp"

constexpr std::uint16_t kServerPort = 1234;
constexpr std::size_t kIoThreadCount = 4;

int main() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(),kServerPort);
        boost::asio::ip::tcp::acceptor acceptor(io_context,endpoint);
        std::cout << "Server listening on port "<< kServerPort << std::endl;
        seftp::server::AsyncServer server(acceptor);
        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        server.start();
        signals.async_wait(
            [&](const boost::system::error_code& ec, int signal_number) {
                if (ec) {
                    std::cerr << "Error in signal set " << ec.message() << std::endl;
                    return;
                }
                std::cout << "Received signal "<< signal_number<< ", shutting down\n";
                server.stop();
            });

        std::vector<std::thread> workers;
        workers.reserve(kIoThreadCount);

        for (std::size_t i = 0; i < kIoThreadCount; ++i) {
            workers.emplace_back(
                [&io_context]() {
                    io_context.run();
                });
        }
        for (auto& worker : workers) {
            worker.join();
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
}