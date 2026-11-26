#pragma once

#include "seftp_server/db_executor.hpp"
#include "seftp_server/logging.hpp"
#include "seftp_server/protocol.hpp"
#include "seftp_server/request_frame.hpp"
#include "seftp_server/response_frame.hpp"
#include "seftp_server/session.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <chrono>

#include <algorithm>
#include <array>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace seftp::server {
    using CloseCallback = std::function<void()>;
    struct ConnectionOptions {
        std::chrono::milliseconds read_timeout{std::chrono::seconds(5)};

        std::chrono::milliseconds registration_timeout{std::chrono::seconds(10)};
    };
    class AsyncConnection : public std::enable_shared_from_this<AsyncConnection> {
    public:
        explicit AsyncConnection(boost::asio::ip::tcp::socket socket,
                                 std::shared_ptr<persistence::DbExecutor> db_executor,
                                 ConnectionOptions options = {}, CloseCallback on_close = {})
            : socket_(std::move(socket)), read_timer_(socket_.get_executor()),
              registration_timer_(socket_.get_executor()),
              strand_(boost::asio::make_strand(socket_.get_executor())),
              db_executor_(std::move(db_executor)), options_(std::move(options)),
              on_close_(std::move(on_close)) {}
        void start() {
            auto self = shared_from_this();
            boost::asio::post(strand_, [self]() {
                self->start_impl();
            });
        }
        void stop() {
            auto self = shared_from_this();
            boost::asio::dispatch(strand_, [self]() {
                self->stop_impl();
            });
        }

        friend struct AsyncConnectionTestAccessor;

    private:
        boost::asio::ip::tcp::socket socket_;
        std::array<protocol::Byte, protocol::kRequestHeaderSize> header_buffer_{};
        std::vector<protocol::Byte> frame_buffer_;
        session::Session session_;
        std::vector<protocol::Byte> write_buffer_;
        boost::asio::steady_timer read_timer_;
        boost::asio::steady_timer registration_timer_;
        boost::asio::strand<boost::asio::ip::tcp::socket::executor_type> strand_;
        std::shared_ptr<persistence::DbExecutor> db_executor_;
        ConnectionOptions options_;
        bool stopped_{false};
        std::uint64_t read_generation_{0};
        std::uint64_t registration_generation_{0};
        CloseCallback on_close_ = {};

        void read_header() {
            if (stopped_) {
                return;
            }
            auto self = shared_from_this();

            arm_read_timeout();

            boost::asio::async_read(
                socket_, boost::asio::buffer(header_buffer_),
                boost::asio::bind_executor(strand_, [self](const boost::system::error_code& ec,
                                                           std::size_t bytes_transferred) {
                    self->cancel_read_timeout();

                    if (ec) {
                        if (self->stopped_) {
                            return;
                        }

                        if (ec == boost::asio::error::eof && bytes_transferred == 0) {
                            self->stop();
                            return;
                        }

                        log_error("Read header failed: " + ec.message());
                        self->stop();
                        return;
                    }

                    if (self->stopped_) {
                        return;
                    }
                    log_line("Read " + std::to_string(bytes_transferred) + " header bytes");

                    const auto offset = protocol::kPayloadSizeOffset;
                    std::uint32_t payload_size =
                        static_cast<std::uint32_t>(self->header_buffer_[offset]) |
                        (static_cast<std::uint32_t>(self->header_buffer_[offset + 1]) << 8u) |
                        (static_cast<std::uint32_t>(self->header_buffer_[offset + 2]) << 16u) |
                        (static_cast<std::uint32_t>(self->header_buffer_[offset + 3]) << 24u);

                    if (payload_size > protocol::kDefaultMaxPayloadSize) {
                        log_line("Payload too large");
                        self->stop();
                        return;
                    }
                    self->frame_buffer_.resize(protocol::kRequestHeaderSize + payload_size);
                    std::copy(self->header_buffer_.begin(), self->header_buffer_.end(),
                              self->frame_buffer_.begin());

                    if (payload_size == 0) {
                        self->process_frame();
                        return;
                    }
                    self->read_payload(payload_size);
                }));
        }

        void read_payload(std::uint32_t payload_size) {
            if (stopped_) {
                return;
            }
            auto self = shared_from_this();
            arm_read_timeout();
            boost::asio::async_read(
                socket_,
                boost::asio::buffer(frame_buffer_.data() + protocol::kRequestHeaderSize,
                                    payload_size),
                boost::asio::bind_executor(strand_, [self](const boost::system::error_code& ec,
                                                           std::size_t bytes_transferred) {
                    self->cancel_read_timeout();
                    if (self->stopped_) {
                        return;
                    }
                    if (ec) {
                        log_line("Read payload failed: " + ec.message());
                        self->stop_impl();
                        return;
                    }
                    log_line("Read " + std::to_string(bytes_transferred) + " payload bytes");

                    self->process_frame();
                }));
        }
        void process_frame() {
            const auto result = protocol::parse_request_frame(frame_buffer_);

            if (result.error.has_value() || !result.frame.has_value()) {
                log_line("Frame parse failed");
                stop_impl();
                return;
            }

            log_line("Frame parsed successfully");
            const auto& request = *result.frame;
            const bool allowed = session_.apply_request(request.code);
            protocol::ResponseFrame response{
                request.version, protocol::ResponseCode::MessageReceived, {}};

            if (!allowed) {
                response.code = protocol::ResponseCode::ServerError;
            } else if (request.code == protocol::RequestCode::ClientHello) {
                response.code = protocol::ResponseCode::ServerHello;
            }
            write_response(response);
        }

        void write_response(const protocol::ResponseFrame& response) {
            if (stopped_) {
                return;
            }
            write_buffer_ = protocol::build_response_frame(response);
            auto self = shared_from_this();
            boost::asio::async_write(
                socket_, boost::asio::buffer(write_buffer_),
                boost::asio::bind_executor(strand_, [self](const boost::system::error_code& ec,
                                                           std::size_t bytes_transferred) {
                    if (self->stopped_) {
                        return;
                    }
                    if (ec) {
                        log_line("Write response failed: " + ec.message());
                        self->stop_impl();
                        return;
                    }
                    log_line(+"Wrote " + std::to_string(bytes_transferred) + " response bytes");
                    self->read_header();
                }));
        }
        void arm_read_timeout() {
            read_timer_.expires_after(options_.read_timeout);
            auto self = shared_from_this();
            const auto captured_generation = ++read_generation_;
            read_timer_.async_wait(boost::asio::bind_executor(
                strand_, [self, captured_generation](const boost::system::error_code& ec) {
                    self->handle_read_timeout(ec, captured_generation);
                }));
        }

        void cancel_read_timeout() {
            ++read_generation_;
            read_timer_.cancel();
        }

        void stop_impl() {
            if (stopped_) {
                return;
            }
            stopped_ = true;
            cancel_read_timeout();
            boost::system::error_code ignored;

            cancel_registration_timeout();

            static_cast<void>(
                socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored));

            static_cast<void>(socket_.close(ignored));

            if (on_close_) {
                on_close_();
            }
        }

        void start_impl() {
            if (stopped_) {
                return;
            }

            read_header();
        }

        void handle_read_timeout(const boost::system::error_code& ec,
                                 const std::uint64_t captured_generation) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            if (ec) {
                log_line("Arm read timeout failed: " + ec.message());
                return;
            }
            if (captured_generation != read_generation_) {
                return;
            }
            if (stopped_) {
                return;
            }

            log_line("Read timed out");
            stop_impl();
        }

        void arm_registration_timeout() {
            registration_timer_.expires_after(options_.registration_timeout);
            auto self = shared_from_this();
            const auto captured_generation = ++registration_generation_;
            registration_timer_.async_wait(boost::asio::bind_executor(
                strand_, [self, captured_generation](const boost::system::error_code& ec) {
                    self->handle_registration_timeout(ec, captured_generation);
                }));
        }

        void cancel_registration_timeout() {
            ++registration_generation_;
            registration_timer_.cancel();
        }
        void handle_registration_timeout(const boost::system::error_code& ec,
                                         std::uint64_t captured_generation) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            if (captured_generation != registration_generation_) {
                return;
            }
            if (stopped_) {
                return;
            }
            if (session_.state() != router::SessionState::RegistrationPending) {
                return;
            }
            if (ec) {
                log_line("Arm registration timeout failed: " + ec.message());
                stop_impl();
                return;
            }

            log_line("Registration timed out");
            stop_impl();
        }
        void handle_registration_completion(persistence::RegistrationCompletion completion,
                                            std::uint64_t captured_generation,
                                            protocol::Byte version) {
            if (stopped_) {
                return;
            }
            if (registration_generation_ != captured_generation) {
                return;
            }
            if (session_.state() != router::SessionState::RegistrationPending) {
                return;
            }
            cancel_registration_timeout();

            if (completion.status == persistence::CompletionStatus::Cancelled) {
                stop_impl();
                return;
            }
            if (!completion.result.has_value()) {
                log_error("status registration completed and dont have result");
                stop_impl();
                return;
            }

            protocol::ResponseFrame response_frame{
                version, protocol::ResponseCode::ServerError, {}};

            switch (completion.result->status) {
            case persistence::RegistrationStatus::Created:
                session_.finish_registration(true);
                response_frame.code = protocol::ResponseCode::RegistrationOk;
                response_frame.payload.assign(completion.result->client_id.begin(),
                                              completion.result->client_id.end());
                break;
            case persistence::RegistrationStatus::AlreadyExists:
                session_.finish_registration(false);
                response_frame.code = protocol::ResponseCode::RegistrationFailed;
                break;
            case persistence::RegistrationStatus::StorageError:
                session_.finish_registration(false);
                response_frame.code = protocol::ResponseCode::ServerError;
                break;
            default:
                stop_impl();
                return;
            }
            write_response(response_frame);
        }

        persistence::RegistrationCallback make_registration_callback(std::uint64_t generation,
                                                                     protocol::Byte version) {
            auto copy_strand = strand_;
            auto self = weak_from_this();
            return [copy_strand, self, generation,
                    version](persistence::RegistrationCompletion completion) {
                boost::asio::post(copy_strand, [self, generation, version, completion]() {
                    {
                        auto ptr = self.lock();
                        if (ptr) {
                            ptr->handle_registration_completion(completion, generation, version);
                        }
                    }
                });
            };
        }
    };
} // namespace seftp::server
