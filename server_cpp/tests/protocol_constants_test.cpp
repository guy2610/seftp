#include "seftp_server/protocol.hpp"

#include <cstdint>

#include <gtest/gtest.h>

namespace {

using seftp::server::protocol::RequestCode;
using seftp::server::protocol::ResponseCode;

TEST(ProtocolConstantsTest, RequestFrameLayoutSizesAreStable) {
    using namespace seftp::server::protocol;

    EXPECT_EQ(kClientIdSize, 16u);
    EXPECT_EQ(kVersionSize, 1u);
    EXPECT_EQ(kCodeSize, 2u);
    EXPECT_EQ(kPayloadSizeFieldSize, 4u);
    EXPECT_EQ(kRequestHeaderSize, 23u);
}

TEST(ProtocolConstantsTest, ResponseFrameLayoutSizesAreStable) {
    using namespace seftp::server::protocol;

    EXPECT_EQ(kVersionSize, 1u);
    EXPECT_EQ(kCodeSize, 2u);
    EXPECT_EQ(kPayloadSizeFieldSize, 4u);
    EXPECT_EQ(kResponseHeaderSize, 7u);
}

TEST(ProtocolConstantsTest, RequestCodeRawValuesAreStable) {
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::Register), 825u);
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::SendPublicKey), 826u);
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::Reconnect), 827u);
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::Upload), 828u);
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::ClientHello), 829u);
    EXPECT_EQ(static_cast<std::uint16_t>(RequestCode::ClientHandshakeAck), 830u);
}

TEST(ProtocolConstantsTest, ResponseCodeRawValuesAreStable) {
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::CrcRetry), 900u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::CrcFinalFailure), 901u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::CrcFatalFailure), 902u);

    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::RegistrationOk), 1600u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::RegistrationFailed), 1601u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::PublicKeyAccepted), 1602u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::CrcOk), 1603u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::MessageReceived), 1604u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::ReconnectOk), 1605u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::ReconnectRejected), 1606u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::ServerError), 1607u);
    EXPECT_EQ(static_cast<std::uint16_t>(ResponseCode::ServerHello), 1608u);
}

}  // namespace