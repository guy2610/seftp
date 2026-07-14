#include "seftp_server/router.hpp"

#include <array>
#include <optional>

#include <gtest/gtest.h>

namespace {

using seftp::server::protocol::RequestCode;
using seftp::server::protocol::ResponseCode;
using seftp::server::router::RouteDecision;
using seftp::server::router::SessionState;
using seftp::server::router::route_request;

void expect_allowed(const RouteDecision& decision) {
    EXPECT_TRUE(decision.allowed);
    EXPECT_FALSE(decision.rejection_code.has_value());
}

void expect_rejected(const RouteDecision& decision) {
    EXPECT_FALSE(decision.allowed);
    ASSERT_TRUE(decision.rejection_code.has_value());
    EXPECT_EQ(*decision.rejection_code, ResponseCode::ServerError);
}

TEST(RouterTest, AllowsClientHelloWhileAwaitingClientHello) {
    const auto decision = route_request(
        SessionState::AwaitingClientHello,
        RequestCode::ClientHello
    );

    expect_allowed(decision);
}

TEST(RouterTest, RejectsOtherRequestsWhileAwaitingClientHello) {
    constexpr std::array rejected_codes{
        RequestCode::Register,
        RequestCode::SendPublicKey,
        RequestCode::Reconnect,
        RequestCode::Upload,
        RequestCode::ClientHandshakeAck,
    };

    for (const auto code : rejected_codes) {
        const auto decision = route_request(
            SessionState::AwaitingClientHello,
            code
        );

        expect_rejected(decision);
    }
}

TEST(RouterTest, AllowsHandshakeAckWhileAwaitingHandshakeAck) {
    const auto decision = route_request(
        SessionState::AwaitingHandshakeAck,
        RequestCode::ClientHandshakeAck
    );

    expect_allowed(decision);
}

TEST(RouterTest, RejectsOtherRequestsWhileAwaitingHandshakeAck) {
    constexpr std::array rejected_codes{
        RequestCode::Register,
        RequestCode::SendPublicKey,
        RequestCode::Reconnect,
        RequestCode::Upload,
        RequestCode::ClientHello,
    };

    for (const auto code : rejected_codes) {
        const auto decision = route_request(
            SessionState::AwaitingHandshakeAck,
            code
        );

        expect_rejected(decision);
    }
}

TEST(RouterTest, AllowsApplicationRequestsAfterHandshake) {
    constexpr std::array allowed_codes{
        RequestCode::Register,
        RequestCode::SendPublicKey,
        RequestCode::Reconnect,
        RequestCode::Upload,
    };

    for (const auto code : allowed_codes) {
        const auto decision = route_request(
            SessionState::HandshakeComplete,
            code
        );

        expect_allowed(decision);
    }
}

TEST(RouterTest, RejectsHandshakeRequestsAfterHandshake) {
    constexpr std::array rejected_codes{
        RequestCode::ClientHello,
        RequestCode::ClientHandshakeAck,
    };

    for (const auto code : rejected_codes) {
        const auto decision = route_request(
            SessionState::HandshakeComplete,
            code
        );

        expect_rejected(decision);
    }
}

}  // namespace