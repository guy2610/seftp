#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <iostream>
#include <memory>
#include <utility>

#include "seftp_server/async_connection.hpp"

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
                    auto connections = std::make_shared<AsyncConnection>(std::move(socket));
                    connections->start();
                    accept_next();
                });
        }
        boost::asio::ip::tcp::acceptor& acceptor_;
    };
}
