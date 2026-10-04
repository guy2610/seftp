#pragma once

#include "seftp_server/protocol.hpp"
#include "seftp_server/request_frame.hpp"
#include "seftp_server/session.hpp"
#include "seftp_server/response_frame.hpp"
#include "seftp_server/logging.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>

namespace seftp::server {
    class AsyncConnection : public std::enable_shared_from_this<AsyncConnection> {
        public:
        explicit AsyncConnection(boost::asio::ip::tcp::socket socket,
            std::chrono::milliseconds read_timeout = std::chrono::seconds(5)
            ): socket_(std::move(socket)),
            read_timer_(socket_.get_executor()),
            read_timeout_(read_timeout),
            strand_(boost::asio::make_strand(socket_.get_executor())){}
        void start() {
            auto self = shared_from_this();
            boost::asio::post(strand_,
                [self]() {
                    self->start_impl();
                });
        }
        void stop() {
            auto self = shared_from_this();
            boost::asio::dispatch(strand_,
                [self]() {
                    self->stop_impl();
                });
        }

        private:
        boost::asio::ip::tcp::socket socket_;
        std::array< protocol::Byte,protocol::kRequestHeaderSize > header_buffer_{};
        std::vector<protocol::Byte> frame_buffer_;
        session::Session session_;
        std::vector<protocol::Byte> write_buffer_;
        boost::asio::steady_timer read_timer_;
        std::chrono::milliseconds read_timeout_;
        boost::asio::strand<boost::asio::ip::tcp::socket::executor_type> strand_;
        bool stopped_{false};

        void read_header() {
            if (stopped_) {
                return;
            }
            auto self = shared_from_this();

            arm_read_timeout();

            boost::asio::async_read(
                socket_,
                boost::asio::buffer(header_buffer_),
                boost::asio::bind_executor(strand_,
                [self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    self->cancel_read_timeout();
                        if (ec) {
                            log_line("Read header failed: " + ec.message());
                            return;
                        }
                        if (self->stopped_) {
                            return;
                        }

                        log_line("Read "+ std::to_string(bytes_transferred) + " header bytes");

                        const auto offset = protocol::kPayloadSizeOffset;
                        std::uint32_t payload_size =
                            static_cast<std::uint32_t>(self->header_buffer_[offset])
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 1]) << 8)
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 2]) << 16)
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 3]) << 24);

                    if (payload_size > protocol::kDefaultMaxPayloadSize) {
                        log_line("Payload too large");
                        return;
                    }
                    self->frame_buffer_.resize(protocol::kRequestHeaderSize + payload_size);
                    std::copy(self->header_buffer_.begin(),self->header_buffer_.end(),self->frame_buffer_.begin());

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
                boost::asio::buffer(
                    frame_buffer_.data() + protocol::kRequestHeaderSize,
                    payload_size
                    ),boost::asio::bind_executor(strand_,
                    [self](const boost::system::error_code& ec,
                        std::size_t bytes_transferred) {
                        self->cancel_read_timeout();
                        if (ec) {
                            log_line("Read payload failed: " + ec.message());
                            return;
                        }
                        if (self->stopped_) {
                            return;
                        }

                        log_line(
                             "Read "
                            + std::to_string(bytes_transferred)
                            + " payload bytes");

                        self->process_frame();
                    }
                    ));
        }
        void process_frame() {
            const auto result = protocol::parse_request_frame(frame_buffer_);

            if (result.error.has_value() || !result.frame.has_value()) {
                log_line("Frame parse failed");
                return;
            }

            log_line("Frame parsed successfully");
            const auto& request = *result.frame;
            const bool allowed = session_.apply_request(request.code);
            protocol::ResponseFrame response{
                request.version,
                protocol::ResponseCode::MessageReceived,
                {}
            };

            if (!allowed) {
                response.code = protocol::ResponseCode::ServerError;
            }
            else if (request.code == protocol::RequestCode::ClientHello) {
                response.code =
                    protocol::ResponseCode::ServerHello;
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
                socket_,
                boost::asio::buffer(write_buffer_),boost::asio::bind_executor(strand_,
                [self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                    if (ec) {
                        log_line(
                             "Write response failed: "
                            + ec.message());
                        return;
                    }
                    if (self->stopped_) {
                        return;
                    }

                    log_line(
                        + "Wrote "
                        + std::to_string(bytes_transferred)
                        + " response bytes");
                    self->read_header();
                }
                ));
        }
        void arm_read_timeout() {
            read_timer_.expires_after(read_timeout_);
            auto self = shared_from_this();
            read_timer_.async_wait(boost::asio::bind_executor(strand_, [self](const boost::system::error_code& ec) {
             if (ec == boost::asio::error::operation_aborted) {
                 return;
             }
                if (ec) {
                    log_line(
                             "Arm read timeout failed: "
                            + ec.message());
                        return;
                }
                if (self->stopped_) {
                    return;
                }

                log_line("Read timed out");
                self->stop();
            }
            ));
        }
        void cancel_read_timeout() {
            read_timer_.cancel();
        }
        void stop_impl() {
            if (stopped_) {
                return;
            }
            stopped_ = true;
            read_timer_.cancel();
            boost::system::error_code ignored;

            socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);

            socket_.cancel(ignored);

            socket_.close(ignored);
        }

        void start_impl() {
            if (stopped_) {
                return;
            }

            read_header();
        }
    };
}
