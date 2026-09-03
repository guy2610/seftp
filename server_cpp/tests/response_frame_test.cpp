#include "seftp_server/response_frame.hpp"

#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

namespace {

using seftp::server::protocol::Byte;
using seftp::server::protocol::ResponseCode;
using seftp::server::protocol::ResponseFrame;
using seftp::server::protocol::build_response_frame;
using seftp::server::protocol::kResponseHeaderSize;

TEST(ResponseFrameTest, BuildsFrameWithoutPayload) {
    const ResponseFrame frame{
        7,
        ResponseCode::RegistrationOk,
        {}
    };

    const auto bytes = build_response_frame(frame);

    ASSERT_EQ(bytes.size(), kResponseHeaderSize);

    EXPECT_EQ(bytes[0], 7);
    EXPECT_EQ(bytes[1], 0x40);
    EXPECT_EQ(bytes[2], 0x06);

    EXPECT_EQ(bytes[3], 0x00);
    EXPECT_EQ(bytes[4], 0x00);
    EXPECT_EQ(bytes[5], 0x00);
    EXPECT_EQ(bytes[6], 0x00);
}

TEST(ResponseFrameTest, BuildsFrameWithPayload) {
    const std::vector<Byte> payload{
        0x10,
        0x20,
        0x30,
        0x40
    };

    const ResponseFrame frame{
        7,
        ResponseCode::ServerError,
        payload
    };

    const auto bytes = build_response_frame(frame);

    ASSERT_EQ(
        bytes.size(),
        kResponseHeaderSize + payload.size()
    );

    EXPECT_EQ(bytes[0], 7);

    EXPECT_EQ(bytes[1], 0x47);
    EXPECT_EQ(bytes[2], 0x06);

    EXPECT_EQ(bytes[3], 0x04);
    EXPECT_EQ(bytes[4], 0x00);
    EXPECT_EQ(bytes[5], 0x00);
    EXPECT_EQ(bytes[6], 0x00);

    const std::vector<Byte> actual_payload(
        bytes.begin() + kResponseHeaderSize,
        bytes.end()
    );

    EXPECT_EQ(actual_payload, payload);
}

TEST(ResponseFrameTest, WritesResponseCodeAsLittleEndian) {
    const ResponseFrame frame{
        7,
        ResponseCode::ServerHello,
        {}
    };

    const auto bytes = build_response_frame(frame);

    ASSERT_GE(bytes.size(), 3u);

    EXPECT_EQ(bytes[1], 0x48);
    EXPECT_EQ(bytes[2], 0x06);
}

TEST(ResponseFrameTest, WritesPayloadSizeAsLittleEndian) {
    const std::vector<Byte> payload(258, 0xAB);

    const ResponseFrame frame{
        7,
        ResponseCode::MessageReceived,
        payload
    };

    const auto bytes = build_response_frame(frame);

    ASSERT_EQ(
        bytes.size(),
        kResponseHeaderSize + payload.size()
    );

    EXPECT_EQ(bytes[3], 0x02);
    EXPECT_EQ(bytes[4], 0x01);
    EXPECT_EQ(bytes[5], 0x00);
    EXPECT_EQ(bytes[6], 0x00);
}

TEST(ResponseFrameTest, PlacesPayloadImmediatelyAfterHeader) {
    const std::vector<Byte> payload{
        0xAA,
        0xBB,
        0xCC
    };

    const ResponseFrame frame{
        7,
        ResponseCode::CrcOk,
        payload
    };

    const auto bytes = build_response_frame(frame);

    ASSERT_EQ(
        bytes.size(),
        kResponseHeaderSize + payload.size()
    );

    EXPECT_EQ(bytes[kResponseHeaderSize], 0xAA);
    EXPECT_EQ(bytes[kResponseHeaderSize + 1], 0xBB);
    EXPECT_EQ(bytes[kResponseHeaderSize + 2], 0xCC);
}

}  // namespace