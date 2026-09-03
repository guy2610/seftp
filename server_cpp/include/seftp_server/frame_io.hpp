#pragma once

#include "seftp_server/request_frame.hpp"
#include "seftp_server/response_frame.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <boost/asio.hpp>

namespace seftp::server::frameio {

    enum class FrameIoError {
        ConnectionClosed,
        ReadFailed,
        WriteFailed,
    };

    struct ReadFrameResult {
        std::optional<protocol::RequestFrame> frame;
        std::optional<protocol::ParseError> parse_error;
        std::optional<FrameIoError> io_error;
    };

    inline ReadFrameResult read_request_frame(boost::asio::ip::tcp::socket& socket) {
        boost::system::error_code error;
        std::array<protocol::Byte, protocol::kRequestHeaderSize> header{};

        boost::asio::read(socket,boost::asio::buffer(header),error);

        if (error) {
            if (error == boost::asio::error::eof) {
                return {std::nullopt, std::nullopt, FrameIoError::ConnectionClosed};
            }
            return {std::nullopt, std::nullopt, FrameIoError::ReadFailed};
        }

        constexpr std::size_t payload_size_offset =
            protocol::kClientIdSize + protocol::kVersionSize + protocol::kCodeSize;

        std::uint32_t payload_size = 0;
        for (std::size_t i = 0; i < protocol::kPayloadSizeFieldSize; ++i) {
            payload_size |= static_cast<std::uint32_t>(header[payload_size_offset +i]) << (8*i);
        }

        if (payload_size > protocol::kDefaultMaxPayloadSize) {
            return {std::nullopt,protocol::ParseError::PayloadTooLarge,std::nullopt};
        }

        std::vector<protocol::Byte> bytes(protocol::kRequestHeaderSize + static_cast<std::size_t>(payload_size));
        std::copy(header.begin(), header.end(), bytes.begin());

        if (payload_size > 0) {
            error.clear();
            boost::asio::read(socket,boost::asio::buffer(bytes.data() + protocol::kRequestHeaderSize,payload_size),error);
        }

        if (error) {
            if (error == boost::asio::error::eof) {
                return {std::nullopt, std::nullopt, FrameIoError::ConnectionClosed};
            }
            return {std::nullopt, std::nullopt, FrameIoError::ReadFailed};
        }
        const auto parse_result = protocol::parse_request_frame(bytes);

        if (parse_result.error.has_value()) {
            return {std::nullopt,parse_result.error,std::nullopt};
        }
        return {parse_result.frame, std::nullopt,std::nullopt};
    }

    inline std::optional<FrameIoError> write_response_frame(boost::asio::ip::tcp::socket& socket,const protocol::ResponseFrame& frame) {
        boost::system::error_code error;

        const auto bytes = protocol::build_response_frame(frame);

        boost::asio::write(socket,boost::asio::buffer(bytes),error);

        if (!error) {
            return std::nullopt;
        }

        if (error == boost::asio::error::broken_pipe ||
            error == boost::asio::error::connection_reset ||
            error == boost::asio::error::not_connected ) {
            return FrameIoError::ConnectionClosed;
        }
        return FrameIoError::WriteFailed;
    }
}
