#pragma once

#include "seftp_server/protocol.hpp"

#include <optional>

namespace seftp::server::router {

    enum class SessionState {
        AwaitingClientHello,
        AwaitingHandshakeAck,
        HandshakeComplete,
    };

    struct RouteDecision {
        bool allowed{};
        std::optional<protocol::ResponseCode> rejection_code;
    };

    inline RouteDecision route_request(SessionState state, protocol::RequestCode code) {
        switch (state) {
            case SessionState::AwaitingClientHello:
                if (code == protocol::RequestCode::ClientHello) {
                    return {true, std::nullopt};
                }
                return {false, protocol::ResponseCode::ServerError};

            case SessionState::AwaitingHandshakeAck:
                if (code == protocol::RequestCode::ClientHandshakeAck) {
                    return {true, std::nullopt};
                }
                return {false,protocol::ResponseCode::ServerError};

            case SessionState::HandshakeComplete:
                switch (code) {
                case protocol::RequestCode::Register:
                case protocol::RequestCode::SendPublicKey:
                case protocol::RequestCode::Reconnect:
                case protocol::RequestCode::Upload:
                        return {true, std::nullopt};

                case protocol::RequestCode::ClientHello:
                case protocol::RequestCode::ClientHandshakeAck:
                        return {false,protocol::ResponseCode::ServerError};
                }
        }

        return {false, protocol::ResponseCode::ServerError};
    }

}  // namespace seftp::server::router