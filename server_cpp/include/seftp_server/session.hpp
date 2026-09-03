#pragma once

#include "seftp_server/protocol.hpp"
#include "seftp_server/router.hpp"

namespace seftp::server::session {

    class Session {
    public:
        router::SessionState state() const {
            return state_;
        };

        bool apply_request(protocol::RequestCode code) {
            const auto decision = router::route_request(state_, code);
            if (!decision.allowed) {
                return false;
            }
            if (code == protocol::RequestCode::ClientHello && state_ == router::SessionState::AwaitingClientHello) {
                state_ = router::SessionState::AwaitingHandshakeAck;
            }
            else if (code == protocol::RequestCode::ClientHandshakeAck && state_ == router::SessionState::AwaitingHandshakeAck) {
                state_ = router::SessionState::HandshakeComplete;
            }

            return true;
        }

    private:
        router::SessionState state_{router::SessionState::AwaitingClientHello};
    };

}