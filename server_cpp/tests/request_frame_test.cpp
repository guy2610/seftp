#include "seftp_server/request_frame.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

namespace {

using seftp::server::protocol::Byte;
using seftp::server::protocol::ParseError;
using seftp::server::protocol::RequestCode;
using seftp::server::protocol::kClientIdSize;
using seftp::server::protocol::kRequestHeaderSize;
using seftp::server::protocol::parse_request_frame;
using seftp::server::protocol::request_code_from_raw;

std::vector<Byte> make_request_frame(
    std::uint16_t raw_code,
    const std::vector<Byte>& payload = {}
) {
    std::vector<Byte> bytes;
    bytes.reserve(kRequestHeaderSize + payload.size());

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        bytes.push_back(static_cast<Byte>(i));
    }

    bytes.push_back(7);

    bytes.push_back(static_cast<Byte>(raw_code & 0xFF));
    bytes.push_back(static_cast<Byte>((raw_code >> 8) & 0xFF));

    const auto payload_size = static_cast<std::uint32_t>(payload.size());

    bytes.push_back(static_cast<Byte>(payload_size & 0xFF));
    bytes.push_back(static_cast<Byte>((payload_size >> 8) & 0xFF));
    bytes.push_back(static_cast<Byte>((payload_size >> 16) & 0xFF));
    bytes.push_back(static_cast<Byte>((payload_size >> 24) & 0xFF));

    bytes.insert(bytes.end(), payload.begin(), payload.end());

    return bytes;
}

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

TEST(RequestFrameParserTest, ParsesValidFrameWithoutPayload) {
    const auto bytes = make_request_frame(825);

    const auto result = parse_request_frame(bytes);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_FALSE(result.error.has_value());

    const auto& frame = *result.frame;

    EXPECT_EQ(frame.version, 7);
    EXPECT_EQ(frame.code, RequestCode::Register);
    EXPECT_TRUE(frame.payload.empty());

    for (std::size_t i = 0; i < kClientIdSize; ++i) {
        EXPECT_EQ(frame.client_id[i], static_cast<Byte>(i));
    }
}

TEST(RequestFrameParserTest, ParsesValidFrameWithPayload) {
    const std::vector<Byte> payload{0x10, 0x20, 0x30, 0x40};
    const auto bytes = make_request_frame(828, payload);

    const auto result = parse_request_frame(bytes);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_FALSE(result.error.has_value());

    EXPECT_EQ(result.frame->code, RequestCode::Upload);
    EXPECT_EQ(result.frame->payload, payload);
}

TEST(RequestFrameParserTest, RejectsIncompleteHeader) {
    const std::vector<Byte> bytes(kRequestHeaderSize - 1, 0);

    const auto result = parse_request_frame(bytes);

    EXPECT_FALSE(result.frame.has_value());
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(*result.error, ParseError::IncompleteHeader);
}

TEST(RequestFrameParserTest, RejectsUnknownRequestCode) {
    const auto bytes = make_request_frame(999);

    const auto result = parse_request_frame(bytes);

    EXPECT_FALSE(result.frame.has_value());
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(*result.error, ParseError::UnknownRequestCode);
}

TEST(RequestFrameParserTest, RejectsPayloadShorterThanDeclaredSize) {
    auto bytes = make_request_frame(828, {0xAA, 0xBB});

    constexpr std::size_t payload_size_offset =
        kClientIdSize + 1 + 2;

    bytes[payload_size_offset] = 3;

    const auto result = parse_request_frame(bytes);

    EXPECT_FALSE(result.frame.has_value());
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(*result.error, ParseError::PayloadSizeMismatch);
}

TEST(RequestFrameParserTest, RejectsPayloadLongerThanDeclaredSize) {
    auto bytes = make_request_frame(828, {0xAA, 0xBB});

    constexpr std::size_t payload_size_offset =
        kClientIdSize + 1 + 2;

    bytes[payload_size_offset] = 1;

    const auto result = parse_request_frame(bytes);

    EXPECT_FALSE(result.frame.has_value());
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(*result.error, ParseError::PayloadSizeMismatch);
}

TEST(RequestFrameParserTest, ReadsRequestCodeAsLittleEndian) {
    auto bytes = make_request_frame(825);

    constexpr std::size_t code_offset = kClientIdSize + 1;

    EXPECT_EQ(bytes[code_offset], 0x39);
    EXPECT_EQ(bytes[code_offset + 1], 0x03);

    const auto result = parse_request_frame(bytes);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_EQ(result.frame->code, RequestCode::Register);
}

TEST(RequestFrameParserTest, ReadsPayloadSizeAsLittleEndian) {
    std::vector<Byte> payload(258, 0xAB);
    const auto bytes = make_request_frame(828, payload);

    constexpr std::size_t payload_size_offset =
        kClientIdSize + 1 + 2;

    EXPECT_EQ(bytes[payload_size_offset], 0x02);
    EXPECT_EQ(bytes[payload_size_offset + 1], 0x01);
    EXPECT_EQ(bytes[payload_size_offset + 2], 0x00);
    EXPECT_EQ(bytes[payload_size_offset + 3], 0x00);

    const auto result = parse_request_frame(bytes);

    ASSERT_TRUE(result.frame.has_value());
    EXPECT_EQ(result.frame->payload.size(), 258u);
    EXPECT_EQ(result.frame->payload, payload);
}

}  // namespace