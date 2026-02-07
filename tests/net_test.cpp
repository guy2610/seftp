#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include "../client/src/net/net.hpp"

//helpers
using seftp::net::detail::read_response_frame_from;


static void push_u16_le(std::vector<uint8_t>& out, uint16_t v) {
	out.push_back(static_cast<uint8_t>(v & 0xFF));
	out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

static void push_u32_le(std::vector<uint8_t>& out, uint32_t v) {
	out.push_back(static_cast<uint8_t>(v & 0xFF));
	out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
	out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}
static std::vector<uint8_t> build_frame_bytes(uint8_t version, uint16_t code_u16, const std::vector<uint8_t>& payload) {
	std::vector<uint8_t> b;
	b.reserve(7 + payload.size());
	b.push_back(version);
	push_u16_le(b, code_u16);
	push_u32_le(b, static_cast<uint32_t>(payload.size()));
	b.insert(b.end(), payload.begin(), payload.end());
	return b;
}
struct FakeReader {
	std::vector<uint8_t> data;
	std::vector<size_t> chunks;
	size_t pos = 0;
	size_t call_idx = 0;
	size_t hard_eof_at = SIZE_MAX;

	size_t operator()(uint8_t* dst, size_t n) {
		if (pos >= data.size() || pos >= hard_eof_at) return 0;

		size_t cap = n;
		if (call_idx < chunks.size()) {
			cap = std::min(cap, chunks[call_idx]);
		}
		call_idx++;

		const size_t remaining = std::min(data.size(), hard_eof_at) - pos;
		const size_t take = std::min(cap, remaining);

		std::memcpy(dst, data.data() + pos, take);
		pos += take;
		return take;
	}
};
//Test
TEST(NetFraming, ReadsFullFrameOneShot) {

	std::vector<uint8_t> payload = { 1,2,3,4,5 };
	auto bytes = build_frame_bytes(seftp::proto::kVersion, static_cast<uint16_t>(seftp::proto::ResCode::RegisterOk), payload);

	FakeReader r;
	r.data = bytes;
    r.chunks = { bytes.size() };
    auto f = read_response_frame_from(r);
	EXPECT_EQ(f.version, seftp::proto::kVersion);
	EXPECT_EQ(f.code, seftp::proto::ResCode::RegisterOk);
	EXPECT_EQ(f.payload, payload);
}
TEST(NetFraming, HandlesPartialReadsHeaderAndBody) {
    std::vector<uint8_t> payload(100);
    for (int i = 0; i < 100; i++) payload[i] = static_cast<uint8_t>(i);

    auto bytes = build_frame_bytes(seftp::proto::kVersion, static_cast<uint16_t>(seftp::proto::ResCode::CrcResult), payload);

    FakeReader r;
    r.data = bytes;
    r.chunks = { 1,1,1,1,1,1,1,
                3,2,1,5,1,7,11,13,17,19,23,
                1000 };

    auto f = read_response_frame_from(r);

    EXPECT_EQ(f.version, seftp::proto::kVersion);
    EXPECT_EQ(f.code, seftp::proto::ResCode::CrcResult);
    EXPECT_EQ(f.payload, payload);
}

TEST(NetFraming, ThrowsOnEOFInHeader) {
    std::vector<uint8_t> payload = { 9,9,9 };
    auto bytes = build_frame_bytes(seftp::proto::kVersion, static_cast<uint16_t>(seftp::proto::ResCode::RegisterOk), payload);

    FakeReader r;
    r.data = bytes;
    r.hard_eof_at = 5;

    EXPECT_THROW((void)read_response_frame_from(r), std::runtime_error);
}

TEST(NetFraming, ThrowsOnEOFInPayload) {
    std::vector<uint8_t> payload(20, 0xAB);
    auto bytes = build_frame_bytes(seftp::proto::kVersion, static_cast<uint16_t>(seftp::proto::ResCode::RegisterOk), payload);

    FakeReader r;
    r.data = bytes;
    r.hard_eof_at = 7 + 10;

    EXPECT_THROW((void)read_response_frame_from(r), std::runtime_error);
}

TEST(NetFraming, PayloadSizeZeroOk) {
    std::vector<uint8_t> payload;
    auto bytes = build_frame_bytes(seftp::proto::kVersion, static_cast<uint16_t>(seftp::proto::ResCode::TransferDone), payload);

    FakeReader r;
    r.data = bytes;
    r.chunks = { 1,2,4 };

    auto f = read_response_frame_from(r);

    EXPECT_EQ(f.version, seftp::proto::kVersion);
    EXPECT_EQ(f.code, seftp::proto::ResCode::TransferDone);
    EXPECT_TRUE(f.payload.empty());
}

TEST(NetFraming, RejectsOversizedPayload) {
    std::vector<uint8_t> b;
    b.push_back(seftp::proto::kVersion);
    push_u16_le(b, static_cast<uint16_t>(seftp::proto::ResCode::RegisterOk));
    push_u32_le(b, seftp::net::detail::kMaxPayload + 1);

    FakeReader r;
    r.data = b;

    EXPECT_THROW((void)read_response_frame_from(r), std::runtime_error);
}
