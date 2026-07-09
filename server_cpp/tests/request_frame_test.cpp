#include "seftp_server/request_frame.hpp"

#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

namespace {

    using seftp::server::protocol::RequestCode;
    using seftp::server::protocol::request_code_from_raw;

    TEST(RequestFrameTest, RequestCodeFromRawAcceptsKnownRequestCodes) {
        EXPECT_EQ(request_code_from_raw(825), RequestCode::Register);
        EXPECT_EQ(request_code_from_raw(826), RequestCode::SendPublicKey);
        EXPECT_EQ(request_code_from_raw(827), RequestCode::Reconnect);
        EXPECT_EQ(request_code_from_raw(828), RequestCode::Upload);
        EXPECT_EQ(request_code_from_raw(829), RequestCode::ClientHello);
        EXPECT_EQ(request_code_from_raw(830), RequestCode::ClientHandshakeAck);
    }

    TEST(RequestFrameTest, RequestCodeFromRawRejectsUnknownRequestCodes) {
        EXPECT_EQ(request_code_from_raw(0), std::nullopt);
        EXPECT_EQ(request_code_from_raw(824), std::nullopt);
        EXPECT_EQ(request_code_from_raw(831), std::nullopt);
        EXPECT_EQ(request_code_from_raw(1607), std::nullopt);
    }

}  // namespace