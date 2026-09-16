#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <iostream>
#include <memory>
#include <utility>
#include <algorithm>
#include <vector>

#include "seftp_server/async_connection.hpp"

namespace seftp::server {
    class AsyncServer {
    public:
        explicit AsyncServer(boost::asio::ip::tcp::acceptor& acceptor): acceptor_(acceptor) {}

        void start() {
            if (stopped_) {
                return;
            }
            accept_next();
        }
        void stop() {
            if (stopped_) {
                return;
            }
            stopped_ = true;

            boost::system::error_code ignored;
            acceptor_.close(ignored);

            for (auto& weak_connection : connections_) {
                if (auto connection = weak_connection.lock()) {
                    connection->stop();
                }
            }
            connections_.clear();

        }
        private:
        boost::asio::ip::tcp::acceptor& acceptor_;
        std::vector<std::weak_ptr<AsyncConnection>> connections_;
        bool stopped_{false};

        void accept_next() {
            if (stopped_) {
                return;
            }
            acceptor_.async_accept(
                [this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
                    if (ec) {
                        if (stopped_) {
                            return;
                        }
                        std::cerr << "Accept failed: " << ec.message() << '\n';
                        return;
                    }
                    if (stopped_) {
                        boost::system::error_code ignored;
                        socket.close(ignored);
                        return;
                    }
                    auto connection = std::make_shared<AsyncConnection>(std::move(socket));
                    prune_expired_connections();
                    connections_.push_back(connection);
                    connection->start();
                    accept_next();
                });
        }

        void prune_expired_connections() {
            connections_.erase(
                std::remove_if(
                    connections_.begin(),
                    connections_.end(),
                    [](const auto& connection) {
                        return connection.expired();
                    }
                ),
                connections_.end()
            );
        }

    };
}
