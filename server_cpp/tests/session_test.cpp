#include "seftp_server/session.hpp"

#include <gtest/gtest.h>

namespace {

    using seftp::server::protocol::RequestCode;
    using seftp::server::router::SessionState;
    using seftp::server::session::Session;

    TEST(SessionTest, StartsAwaitingClientHello) {
        const Session session;

        EXPECT_EQ(session.state(), SessionState::AwaitingClientHello);
    }

    TEST(SessionTest, ClientHelloAdvancesToAwaitingHandshakeAck) {
        Session session;

        const bool accepted = session.apply_request(RequestCode::ClientHello);

        EXPECT_TRUE(accepted);
        EXPECT_EQ(session.state(), SessionState::AwaitingHandshakeAck);
    }

    TEST(SessionTest, HandshakeAckCompletesHandshakeAfterClientHello) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));

        const bool accepted = session.apply_request(RequestCode::ClientHandshakeAck);

        EXPECT_TRUE(accepted);
        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);
    }

    TEST(SessionTest, RejectsApplicationRequestBeforeClientHello) {
        Session session;

        const bool accepted = session.apply_request(RequestCode::Register);

        EXPECT_FALSE(accepted);
        EXPECT_EQ(session.state(), SessionState::AwaitingClientHello);
    }

    TEST(SessionTest, RejectsHandshakeAckBeforeClientHello) {
        Session session;

        const bool accepted = session.apply_request(RequestCode::ClientHandshakeAck);

        EXPECT_FALSE(accepted);
        EXPECT_EQ(session.state(), SessionState::AwaitingClientHello);
    }

    TEST(SessionTest, RejectedRequestDoesNotChangeAwaitingHandshakeAckState) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));

        const bool accepted = session.apply_request(RequestCode::Upload);

        EXPECT_FALSE(accepted);
        EXPECT_EQ(session.state(), SessionState::AwaitingHandshakeAck);
    }

    TEST(SessionTest, AllowsApplicationRequestsAfterHandshake) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));

        EXPECT_TRUE(session.apply_request(RequestCode::Register));
        EXPECT_TRUE(session.apply_request(RequestCode::SendPublicKey));
        EXPECT_TRUE(session.apply_request(RequestCode::Reconnect));
        EXPECT_TRUE(session.apply_request(RequestCode::Upload));

        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);
    }

    TEST(SessionTest, RejectsRepeatedClientHelloAfterHandshake) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));

        const bool accepted = session.apply_request(RequestCode::ClientHello);

        EXPECT_FALSE(accepted);
        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);
    }

    TEST(SessionTest, RejectsRepeatedHandshakeAckAfterHandshake) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));

        const bool accepted = session.apply_request(RequestCode::ClientHandshakeAck);

        EXPECT_FALSE(accepted);
        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);
    }

    TEST(SessionTest, CannotBeginRegistrationBeforeHandshake) {
        Session session;

        EXPECT_FALSE(session.begin_registration());
        EXPECT_EQ(session.state(), SessionState::AwaitingClientHello);

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));

        EXPECT_FALSE(session.begin_registration());
        EXPECT_EQ(session.state(), SessionState::AwaitingHandshakeAck);
    }

    TEST(SessionTest, RegistrationBeginsAfterHandshake) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));

        EXPECT_TRUE(session.begin_registration());
        EXPECT_EQ(session.state(), SessionState::RegistrationPending);
    }

    TEST(SessionTest, RejectsRegistrationWhilePending) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));
        ASSERT_TRUE(session.begin_registration());

        EXPECT_FALSE(session.begin_registration());
        EXPECT_EQ(session.state(), SessionState::RegistrationPending);
    }

    TEST(SessionTest, SuccessfulRegistrationAdvancesState) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));
        ASSERT_TRUE(session.begin_registration());

        EXPECT_TRUE(session.finish_registration(true));
        EXPECT_EQ(session.state(), SessionState::Registered);

        EXPECT_FALSE(session.begin_registration());
        EXPECT_FALSE(session.finish_registration(false));
        EXPECT_EQ(session.state(), SessionState::Registered);
    }

    TEST(SessionTest, FailedRegistrationAllowsRetry) {
        Session session;

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));
        ASSERT_TRUE(session.begin_registration());

        EXPECT_TRUE(session.finish_registration(false));
        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);

        EXPECT_TRUE(session.begin_registration());
        EXPECT_EQ(session.state(), SessionState::RegistrationPending);
    }

    TEST(SessionTest, CannotFinishRegistrationWithoutPendingRequest) {
        Session session;

        EXPECT_FALSE(session.finish_registration(true));
        EXPECT_EQ(session.state(), SessionState::AwaitingClientHello);

        ASSERT_TRUE(session.apply_request(RequestCode::ClientHello));
        ASSERT_TRUE(session.apply_request(RequestCode::ClientHandshakeAck));

        EXPECT_FALSE(session.finish_registration(true));
        EXPECT_FALSE(session.finish_registration(false));
        EXPECT_EQ(session.state(), SessionState::HandshakeComplete);
    }

} // namespace