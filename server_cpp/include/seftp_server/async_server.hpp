#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <memory>
#include <utility>
#include <algorithm>
#include <vector>
#include <cstddef>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

#include "seftp_server/async_connection.hpp"
#include "seftp_server/logging.hpp"

namespace seftp::server {
    inline constexpr std::size_t kDefaultMaxActiveConnections = 128;
    inline constexpr auto kAcceptRetryDelay = std::chrono::milliseconds(100);
    class AsyncServer {
    public:
        explicit AsyncServer(boost::asio::ip::tcp::acceptor& acceptor,
            std::size_t max_active_connections = kDefaultMaxActiveConnections):
        acceptor_(acceptor),
        max_active_connections_(max_active_connections),
        strand_(boost::asio::make_strand(acceptor_.get_executor())),
        accept_retry_timer_(acceptor_.get_executor()){}

        void start() {
            boost::asio::post(strand_,
                [this]() {
                    this->start_impl();
                });
        }
        void stop() {
            boost::asio::dispatch(strand_,
                [this]() {
                    this->stop_impl();
                });
        }
        private:
        boost::asio::ip::tcp::acceptor& acceptor_;
        std::vector<std::weak_ptr<AsyncConnection>> connections_;
        std::size_t max_active_connections_;
        boost::asio::strand<boost::asio::ip::tcp::acceptor::executor_type> strand_;
        boost::asio::steady_timer accept_retry_timer_;
        bool stopped_{false};

        void accept_next() {
            if (stopped_) {
                return;
            }
            acceptor_.async_accept(boost::asio::bind_executor(strand_,
                [this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
                    if (ec) {
                        if (stopped_) {
                            return;
                        }
                        log_error("Accept failed: " + ec.message());
                        schedule_accept_retry();
                        return;
                    }
                    if (stopped_) {
                        boost::system::error_code ignored;
                        socket.close(ignored);
                        return;
                    }

                    prune_expired_connections();
                    if (connections_.size()>=max_active_connections_) {
                        boost::system::error_code ignored;
                        socket.close(ignored);
                        accept_next();
                        return;
                    }
                    auto connection = std::make_shared<AsyncConnection>(std::move(socket));
                    connections_.push_back(connection);
                    connection->start();
                    accept_next();
                }));
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
        void stop_impl() {
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
            accept_retry_timer_.cancel();
        }

        void start_impl() {
            if (stopped_) {
                return;
            }
            accept_next();
        }

        void schedule_accept_retry() {
            accept_retry_timer_.expires_after(kAcceptRetryDelay);
            accept_retry_timer_.async_wait(boost::asio::bind_executor(strand_,
                [this](const boost::system::error_code& ec) {
                    if (ec) {
                        if (stopped_) {
                            return;
                        }
                        log_error("Accept retry wait failed: " + ec.message());
                        return;
                    }
                    if (stopped_) {
                        return;
                    }
                        accept_next();
                        return;
                }));
        }
    };
}
