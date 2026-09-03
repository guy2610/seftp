#include "seftp_server/server.hpp"

#include <boost/asio.hpp>

#include <cstdint>
#include <exception>
#include <iostream>

constexpr std::uint16_t kServerPort = 1234;
int main() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4::loopback(),kServerPort);
        boost::asio::ip::tcp::acceptor acceptor(io_context,endpoint);
        std::cout << "Server listening on port "<< kServerPort << std::endl;
        const auto result = seftp::server::run_server(acceptor);
        if (result == seftp::server::ServerResult::AcceptFailed) {
            std::cerr << "Server accept failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
}