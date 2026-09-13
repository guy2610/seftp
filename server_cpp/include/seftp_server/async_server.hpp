#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <iostream>

namespace seftp::server {
    class AsyncServer {
    public:
        explicit AsyncServer(boost::asio::ip::tcp::acceptor& acceptor): acceptor_(acceptor) {}

        void start() {
            accept_next();
        }
        private:
        void accept_next() {
            acceptor_.async_accept(
                [this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
                    if (ec) {
                        std::cerr << "Accept failed: " << ec.message() << '\n';
                        return;
                    }
                    std::cout << "Client connected\n";
                    accept_next();
                });
        }
        boost::asio::ip::tcp::acceptor& acceptor_;
    };
}
