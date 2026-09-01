#pragma once

#include "seftp_server/protocol.hpp"
#include "seftp_server/session.hpp"
#include "seftp_server/frame_io.hpp"

#include <boost/asio/ip/tcp.hpp>

namespace seftp::server::connection_handler {

    enum class ConnectionResult {
        ResponseSent,
        ConnectionLost,
        ReadFailed,
        WriteFailed,
        ProtocolError,
    };

    inline ConnectionResult handle_one_request(boost::asio::ip::tcp::socket& socket, session::Session& session) {
        const auto read_result = frameio::read_request_frame(socket);

        if (read_result.io_error.has_value()) {
            if (*read_result.io_error ==
                frameio::FrameIoError::ConnectionClosed) {
                return ConnectionResult::ConnectionLost;
                }

            return ConnectionResult::ReadFailed;
        }

        if (read_result.parse_error.has_value()) {
            return ConnectionResult::ProtocolError;
        }

        if (!read_result.frame.has_value()) {
            return ConnectionResult::ProtocolError;
        }

        const auto& request = *read_result.frame;

        const bool allowed = session.apply_request(request.code);

        protocol::ResponseFrame response{
            request.version,
            protocol::ResponseCode::MessageReceived,
            {}
        };

        if (!allowed) {
            response.code = protocol::ResponseCode::ServerError;
        }
        else if (request.code == protocol::RequestCode::ClientHello) {
            response.code = protocol::ResponseCode::ServerHello;
        }

        const auto write_error = frameio::write_response_frame(socket, response);

        if (write_error.has_value()) {
            if (*write_error == frameio::FrameIoError::ConnectionClosed) {
                return ConnectionResult::ConnectionLost;
            }

            return ConnectionResult::WriteFailed;
        }

        return ConnectionResult::ResponseSent;
    }

}