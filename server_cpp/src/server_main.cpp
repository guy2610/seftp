#include <boost/asio.hpp>

#include <cstdint>
#include <exception>
#include <iostream>

#include "seftp_server/async_server.hpp"

constexpr std::uint16_t kServerPort = 1234;
int main() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(),kServerPort);
        boost::asio::ip::tcp::acceptor acceptor(io_context,endpoint);
        std::cout << "Server listening on port "<< kServerPort << std::endl;
        seftp::server::AsyncServer server(acceptor);
        server.start();
        io_context.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
}