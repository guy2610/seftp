#include <gtest/gtest.h>
#include "..\client\src\protocol\protocol.hpp"
//helpers
static uint8_t read_u8(const std::vector<uint8_t>& b, size_t off) {
	return b.at(off);
}
static uint16_t read_u16_le_vec(const std::vector<uint8_t>& b, size_t off) {
	return static_cast<uint16_t>(b.at(off)) |
		(static_cast<uint16_t>(b.at(off + 1)) << 8);
}
static uint32_t read_u32_le_vec(const std::vector<uint8_t>& b, size_t off) {
	return static_cast<uint32_t>(b.at(off)) |
		(static_cast<uint32_t>(b.at(off + 1)) << 8) |
		(static_cast<uint32_t>(b.at(off + 2)) << 16) |
		(static_cast<uint32_t>(b.at(off + 3)) << 24);
}
static void expect_req_header(const std::vector<uint8_t>& frame,
	const seftp::proto::ClientId& expected_cid,
	seftp::proto::ReqCode expected_code,
	uint32_t expected_payload_size,
	uint8_t expected_version = seftp::proto::kVersion) {
	ASSERT_GE(frame.size(), seftp::proto::kReqHeaderLen);

	// client_id: [0..15]
	for (size_t i = 0; i < seftp::proto::kClientIdLen; ++i) {
		EXPECT_EQ(frame[i], expected_cid[i]) << "client_id byte " << i;
	}

	// version: [16]
	EXPECT_EQ(read_u8(frame, 16), expected_version);

	// code: [17..18] little-endian
	EXPECT_EQ(read_u16_le_vec(frame, 17), static_cast<uint16_t>(expected_code));

	// payload_size: [19..22] little-endian
	EXPECT_EQ(read_u32_le_vec(frame, 19), expected_payload_size);
}

//Test
TEST(ProtocolBuild, Req825) {

	//build_825_register
	std::string username = "Alice";
	seftp::proto::ClientId expected_zero = seftp::proto::zero_client_id();

	auto frame_825 = seftp::proto::build_825_register(username);
	expect_req_header(frame_825, seftp::proto::zero_client_id(), seftp::proto::ReqCode::Register, static_cast<uint32_t>(username.size() + 1));
	std::vector<uint8_t>v_username(username.c_str(), username.c_str() + username.size() + 1);

	ASSERT_GE(frame_825.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_825(frame_825.begin() + seftp::proto::kReqHeaderLen, frame_825.end());
	EXPECT_EQ(payload_825, v_username);
	EXPECT_EQ(payload_825.back(), '\0');
	EXPECT_EQ(std::vector<uint8_t>(frame_825.begin(), frame_825.begin() + 16),
		std::vector<uint8_t>(expected_zero.begin(), expected_zero.end()));

}
TEST(ProtocolBuild, Req827) {
	//build_827_relogin
	std::string username = "Alice";
	std::vector<uint8_t>v_username(username.c_str(), username.c_str() + username.size() + 1);
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	auto frame_827 = seftp::proto::build_827_relogin(client, username);
	expect_req_header(frame_827, client, seftp::proto::ReqCode::ReLogin, static_cast<uint32_t>(username.size() + 1));

	ASSERT_GE(frame_827.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_827(frame_827.begin() + seftp::proto::kReqHeaderLen, frame_827.end());
	EXPECT_EQ(payload_827, v_username);
}
TEST(ProtocolBuild, Req900) {
	//build_900_crc_ok
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string file_name = "hi.png";
	std::vector<uint8_t> v_file_name(file_name.c_str(), file_name.c_str() + file_name.size() + 1);
	auto frame_900 = seftp::proto::build_900_crc_ok(client, file_name);
	expect_req_header(frame_900, client, seftp::proto::ReqCode::CrcOk, static_cast<uint32_t>(file_name.size() + 1));

	ASSERT_GE(frame_900.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_900(frame_900.begin() + seftp::proto::kReqHeaderLen, frame_900.end());
	EXPECT_EQ(payload_900, v_file_name);
	EXPECT_EQ(payload_900.back(), '\0');
}
TEST(ProtocolBuild, Req901) {
	//build_901_crc_retry
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string file_name = "hi.png";
	std::vector<uint8_t> v_file_name(file_name.c_str(), file_name.c_str() + file_name.size() + 1);
	auto frame_901 = seftp::proto::build_901_crc_retry(client, file_name);
	expect_req_header(frame_901, client, seftp::proto::ReqCode::CrcRetry, static_cast<uint32_t>(file_name.size() + 1));

	ASSERT_GE(frame_901.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_901(frame_901.begin() + seftp::proto::kReqHeaderLen, frame_901.end());
	EXPECT_EQ(payload_901, v_file_name);
}
TEST(ProtocolBuild, Req902) {
	//build_902_crc_fail
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string file_name = "hi.png";
	std::vector<uint8_t> v_file_name(file_name.c_str(), file_name.c_str() + file_name.size() + 1);
	auto frame_902 = seftp::proto::build_902_crc_fail(client, file_name);
	expect_req_header(frame_902, client, seftp::proto::ReqCode::CrcFail, static_cast<uint32_t>(file_name.size() + 1));

	ASSERT_GE(frame_902.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_902(frame_902.begin() + seftp::proto::kReqHeaderLen, frame_902.end());
	EXPECT_EQ(payload_902, v_file_name);
}
TEST(ProtocolBuild, Req826) {
	//build_826_public_key
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string username = "Alice";
	std::vector<uint8_t>v_username(username.c_str(), username.c_str() + username.size() + 1);
	std::string public_key_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!";
	std::vector<uint8_t> v_public_key_b64(public_key_b64.begin(), public_key_b64.end());
	auto frame_826 = seftp::proto::build_826_public_key(client, username, public_key_b64);
	expect_req_header(frame_826, client, seftp::proto::ReqCode::PublicKey, static_cast<uint32_t>(username.size() + 1 + public_key_b64.size()));

	ASSERT_GE(frame_826.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t> payload_826(frame_826.begin() + seftp::proto::kReqHeaderLen, frame_826.end());
	std::vector<uint8_t>payload_826_username(payload_826.begin(), payload_826.begin() + v_username.size());
	std::vector<uint8_t>payload_826_public_key_b64(payload_826.begin() + v_username.size(), payload_826.end());

	EXPECT_EQ(payload_826_username, v_username);
	EXPECT_EQ(payload_826_public_key_b64, v_public_key_b64);
	ASSERT_EQ(payload_826_username.back(), '\0');
	EXPECT_EQ(payload_826_public_key_b64.size(), public_key_b64.size());
}
TEST(ProtocolBuild, Req828_iv) {
	//build_828_packet0_iv
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string file_name = "hi.png";
	std::vector<uint8_t> v_file_name(file_name.c_str(), file_name.c_str() + file_name.size() + 1);
	uint32_t total_cipher_size = 100000;
	uint32_t orig_plain_size = 100000;
	uint16_t total_packets = 10;
	std::array<uint8_t, 16> iv = { 0x4d, 0x92, 0xB1, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::vector<uint8_t> v_iv(iv.begin(), iv.end());

	auto frame_828_0 = seftp::proto::build_828_packet0_iv(client, total_cipher_size, orig_plain_size, total_packets, file_name, iv);
	const uint32_t payload_size_828_0 =4 + 4 + 2 + 2 + static_cast<uint32_t>(file_name.size() + 1) + 16;
	expect_req_header(frame_828_0, client, seftp::proto::ReqCode::FileChunk, static_cast<uint32_t>(payload_size_828_0));

	ASSERT_GE(frame_828_0.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t>payload_828_0(frame_828_0.begin() + seftp::proto::kReqHeaderLen, frame_828_0.end());
	std::vector<uint8_t> total_cipher_size_le, orig_plain_size_le, total_packets_le, packet_0_le;
	seftp::proto::append_u32_le(total_cipher_size_le, total_cipher_size);
	seftp::proto::append_u32_le(orig_plain_size_le, orig_plain_size);
	seftp::proto::append_u16_le(total_packets_le, total_packets);
	packet_0_le = { 0,0 };

	const size_t total_cipher_size_offset = 0;
	const size_t orig_plain_size_offset = total_cipher_size_offset + 4;
	const size_t packet_0_offset = orig_plain_size_offset + 4;
	const size_t total_packets_offset = packet_0_offset + 2;
	const size_t file_name_offset = total_packets_offset + 2;
	const size_t iv_offset = file_name_offset + v_file_name.size();

	std::vector<uint8_t>payload_828_0_total_cipher_size(payload_828_0.begin() + total_cipher_size_offset, payload_828_0.begin() + orig_plain_size_offset);
	std::vector<uint8_t>payload_828_0_orig_plain_size(payload_828_0.begin() + orig_plain_size_offset, payload_828_0.begin() + packet_0_offset);
	std::vector<uint8_t>payload_828_0_packet_0(payload_828_0.begin() + packet_0_offset, payload_828_0.begin() + total_packets_offset);
	std::vector<uint8_t>payload_828_0_total_packets(payload_828_0.begin() + total_packets_offset, payload_828_0.begin() + file_name_offset);
	std::vector<uint8_t>payload_828_0_file_name(payload_828_0.begin() + file_name_offset, payload_828_0.begin() + iv_offset);
	std::vector<uint8_t>payload_828_0_iv(payload_828_0.begin() + iv_offset, payload_828_0.end());

	EXPECT_EQ(payload_828_0_total_cipher_size, total_cipher_size_le);
	EXPECT_EQ(payload_828_0_orig_plain_size, orig_plain_size_le);
	EXPECT_EQ(payload_828_0_packet_0, packet_0_le);
	EXPECT_EQ(payload_828_0_total_packets, total_packets_le);
	EXPECT_EQ(payload_828_0_file_name, v_file_name);
	EXPECT_EQ(payload_828_0_iv.size(), 16u);
	EXPECT_EQ(payload_828_0_iv, v_iv);
}

TEST(ProtocolBuild, Req828_chunk) {

	//build_828_packet_chunk
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::string file_name = "hi.png";
	std::vector<uint8_t> v_file_name(file_name.c_str(), file_name.c_str() + file_name.size() + 1);
	uint32_t total_cipher_size = 100000;
	uint32_t orig_plain_size = 100000;
	uint16_t total_packets = 10;
	std::array<uint8_t, 16> iv = { 0x4d, 0x92, 0xB1, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
	0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::vector<uint8_t> v_iv(iv.begin(), iv.end());
	uint16_t packet_no = 49;
	std::vector<uint8_t> chunk(v_iv.begin(), v_iv.end());

	auto frame_828 = seftp::proto::build_828_packet_chunk(client, total_cipher_size, orig_plain_size, packet_no, total_packets, file_name, chunk);
	const uint32_t payload_size_828 =4 + 4 + 2 + 2 + static_cast<uint32_t>(file_name.size() + 1) + static_cast<uint32_t>(chunk.size());
	expect_req_header(frame_828,client,seftp::proto::ReqCode::FileChunk,static_cast<uint32_t>(payload_size_828));

	ASSERT_GE(frame_828.size(), seftp::proto::kReqHeaderLen);

	std::vector<uint8_t>payload_828(frame_828.begin() + seftp::proto::kReqHeaderLen, frame_828.end());
	std::vector<uint8_t> total_cipher_size_le, orig_plain_size_le, total_packets_le, packet_no_le;
	seftp::proto::append_u32_le(total_cipher_size_le, total_cipher_size);
	seftp::proto::append_u32_le(orig_plain_size_le, orig_plain_size);
	seftp::proto::append_u16_le(total_packets_le, total_packets);
	seftp::proto::append_u16_le(packet_no_le, packet_no);

	const size_t total_cipher_size_offset = 0;
	const size_t orig_plain_size_offset = total_cipher_size_offset + 4;
	const size_t packet_no_offset = orig_plain_size_offset + 4;
	const size_t total_packets_offset = packet_no_offset + 2;
	const size_t file_name_offset = total_packets_offset + 2;
	const size_t chunk_offset = file_name_offset + v_file_name.size();

	std::vector<uint8_t>payload_828_total_cipher_size(payload_828.begin() + total_cipher_size_offset, payload_828.begin() + orig_plain_size_offset);
	std::vector<uint8_t>payload_828_orig_plain_size(payload_828.begin() + orig_plain_size_offset, payload_828.begin() + packet_no_offset);
	std::vector<uint8_t>payload_828_packet_no(payload_828.begin() + packet_no_offset, payload_828.begin() + total_packets_offset);
	std::vector<uint8_t>payload_828_total_packets(payload_828.begin() + total_packets_offset, payload_828.begin() + file_name_offset);
	std::vector<uint8_t>payload_828_file_name(payload_828.begin() + file_name_offset, payload_828.begin() + chunk_offset);
	std::vector<uint8_t>payload_828_chunk(payload_828.begin() + chunk_offset, payload_828.end());

	EXPECT_EQ(payload_828_total_cipher_size, total_cipher_size_le);
	EXPECT_EQ(payload_828_orig_plain_size, orig_plain_size_le);
	EXPECT_EQ(payload_828_packet_no, packet_no_le);
	EXPECT_EQ(payload_828_total_packets, total_packets_le);
	EXPECT_EQ(payload_828_file_name, v_file_name);
	EXPECT_EQ(payload_828_chunk, chunk);
	EXPECT_THROW(
		seftp::proto::build_828_packet_chunk(client, total_cipher_size, orig_plain_size,
			0, total_packets, file_name, chunk),
			std::invalid_argument
		);
}