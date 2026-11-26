#pragma once

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include "seftp_server/async_connection.hpp"
#include "seftp_server/db_executor.hpp"
#include "seftp_server/logging.hpp"

namespace seftp::server {
    using ConnectionId = std::uint64_t;
    inline constexpr std::size_t kDefaultMaxActiveConnections = 128;
    inline constexpr auto kAcceptRetryDelay = std::chrono::milliseconds(100);
    class AsyncServer {
    public:
        explicit AsyncServer(boost::asio::ip::tcp::acceptor& acceptor,
                             std::shared_ptr<persistence::DbExecutor> db_executor,
                             std::size_t max_active_connections = kDefaultMaxActiveConnections)
            : acceptor_(acceptor), max_active_connections_(max_active_connections),
              db_executor_(std::move(db_executor)),
              strand_(boost::asio::make_strand(acceptor_.get_executor())),
              accept_retry_timer_(acceptor_.get_executor()) {

            if (!db_executor_) {
                throw std::invalid_argument("db_executor is nullptr");
            }
        }

        void start() {
            boost::asio::post(strand_, [this]() {
                this->start_impl();
            });
        }
        void stop() {
            boost::asio::dispatch(strand_, [this]() {
                this->stop_impl();
            });
        }

        friend struct AsyncServerTestAccessor;

    private:
        boost::asio::ip::tcp::acceptor& acceptor_;
        std::unordered_map<ConnectionId, std::shared_ptr<AsyncConnection>> connections_;
        ConnectionId next_connection_id_{0};
        std::size_t max_active_connections_;
        std::shared_ptr<persistence::DbExecutor> db_executor_;
        boost::asio::strand<boost::asio::ip::tcp::acceptor::executor_type> strand_;
        boost::asio::steady_timer accept_retry_timer_;
        bool stopped_{false};
        bool started_{false};
        std::size_t accept_attempts_{0};

        void accept_next() {
            if (stopped_) {
                return;
            }
            ++accept_attempts_;
            acceptor_.async_accept(
                boost::asio::bind_executor(strand_, [this](const boost::system::error_code& ec,
                                                           boost::asio::ip::tcp::socket socket) {
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

                    if (connections_.size() >= max_active_connections_) {
                        boost::system::error_code ignored;
                        socket.close(ignored);
                        accept_next();
                        return;
                    }
                    auto connection = std::make_shared<AsyncConnection>(
                        std::move(socket), db_executor_, std::chrono::seconds(5),
                        [this, id = next_connection_id_]() {
                            this->on_connection_closed(id);
                        });
                    connections_.emplace(next_connection_id_++, connection);
                    connection->start();
                    accept_next();
                }));
        }

        void stop_impl() {
            if (stopped_) {
                return;
            }
            stopped_ = true;

            boost::system::error_code ignored;
            acceptor_.close(ignored);

            for (auto& [id, connection] : connections_) {
                if (connection) {
                    connection->stop();
                }
            }
            connections_.clear();
            accept_retry_timer_.cancel();
        }

        void start_impl() {
            if (stopped_ || started_) {
                return;
            }

            started_ = true;
            accept_next();
        }

        void on_connection_closed(ConnectionId id) {
            boost::asio::post(strand_, [this, id]() {
                this->connections_.erase(id);
            });
        }

        void schedule_accept_retry() {
            accept_retry_timer_.expires_after(kAcceptRetryDelay);
            accept_retry_timer_.async_wait(
                boost::asio::bind_executor(strand_, [this](const boost::system::error_code& ec) {
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
} // namespace seftp::server
