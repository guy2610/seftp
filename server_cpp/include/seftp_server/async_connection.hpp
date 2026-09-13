#pragma once

#include "seftp_server/protocol.hpp"
#include "seftp_server/request_frame.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

namespace seftp::server {
    class AsyncConnection : public std::enable_shared_from_this<AsyncConnection> {
        public:
        explicit AsyncConnection(boost::asio::ip::tcp::socket socket): socket_(std::move(socket)) {}
        void start() {
            read_header();
        }
        private:
        boost::asio::ip::tcp::socket socket_;
        std::array< protocol::Byte,protocol::kRequestHeaderSize > header_buffer_{};
        std::vector<protocol::Byte> frame_buffer_;

        void read_header() {
            auto self = shared_from_this();

            boost::asio::async_read(
                socket_,
                boost::asio::buffer(header_buffer_),
                [self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                        if (ec) {
                            std::cerr << "Read header failed: "
                            << ec.message()
                            << '\n';
                            return;
                        }

                        std::cout<< "Read "<< bytes_transferred<< " header bytes\n";

                        const auto offset = protocol::kPayloadSizeOffset;
                        std::uint32_t payload_size =
                            static_cast<std::uint32_t>(self->header_buffer_[offset])
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 1]) << 8)
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 2]) << 16)
                            | (static_cast<std::uint32_t>(self->header_buffer_[offset + 3]) << 24);

                    if (payload_size > protocol::kDefaultMaxPayloadSize) {
                        std::cerr << "Payload too large\n";
                        return;
                    }
                    self->frame_buffer_.resize(protocol::kRequestHeaderSize + payload_size);
                    std::copy(self->header_buffer_.begin(),self->header_buffer_.end(),self->frame_buffer_.begin());

                    if (payload_size == 0) {
                        self->process_frame();
                        return;
                    }
                    self->read_payload(payload_size);

            });
        }

        void read_payload(std::uint32_t payload_size) {
            auto self = shared_from_this();
            boost::asio::async_read(
                socket_,
                boost::asio::buffer(
                    frame_buffer_.data() + protocol::kRequestHeaderSize,
                    payload_size
                    ),
                    [self](const boost::system::error_code& ec,
                        std::size_t bytes_transferred) {
                        if (ec) {
                            std::cerr
                                << "Read payload failed: "
                                << ec.message()
                                << '\n';
                            return;
                        }

                        std::cout
                            << "Read "
                            << bytes_transferred
                            << " payload bytes\n";

                        self->process_frame();
                    }
                    );
        }
        void process_frame() {
            const auto result = protocol::parse_request_frame(frame_buffer_);

            if (result.error.has_value()) {
                std::cerr << "Frame parse failed\n";
                return;
            }

            std::cout << "Frame parsed successfully\n";
        }
    };
}
