#include <gtest/gtest.h>
#include "../../client/src/protocol/protocol.hpp"
TEST(ProtocolReqBase, BuildRequestLayout) {
	//Arrenge
	seftp::proto::ClientId client= {
	0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD
	};
	std::vector<uint8_t> payload = {
	0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, // "hello "
	0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21  // "world!"
	};
	const auto msg = seftp::proto::build_request(
		client,
		seftp::proto::ReqCode::Register,
		payload,
		seftp::proto::kVersion
	);
	ASSERT_EQ(msg.size(), seftp::proto::kReqHeaderLen + payload.size());
    // offsets
    const size_t off_client = 0;
    const size_t off_version = seftp::proto::kClientIdLen;          // 16
    const size_t off_code = off_version + 1;                        // 17
    const size_t off_psize = off_code + 2;                          // 19
    const size_t off_payload = seftp::proto::kReqHeaderLen;         // 23

    // client_id
    ASSERT_GE(msg.size(), seftp::proto::kReqHeaderLen);
    for (size_t i = 0; i < seftp::proto::kClientIdLen; ++i) {
        EXPECT_EQ(msg[off_client + i], client[i]);
    }

    // version
    EXPECT_EQ(msg[off_version], seftp::proto::kVersion);

    // code
    const uint16_t code = seftp::proto::read_u16_le(msg.data() + off_code);
    EXPECT_EQ(code, static_cast<uint16_t>(seftp::proto::ReqCode::Register));

    // payload size
    const uint32_t psize = seftp::proto::read_u32_le(msg.data() + off_psize);
    EXPECT_EQ(psize, static_cast<uint32_t>(payload.size()));

    // payload bytes
    ASSERT_EQ(msg.size() - off_payload, payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(msg[off_payload + i], payload[i]);
    }
}