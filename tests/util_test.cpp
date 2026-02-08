#include <gtest/gtest.h>
#include "../client/src/util/util.hpp"
#include "../client/src/protocol/protocol.hpp"

using namespace seftp::util;
//Test
TEST(Utilfunc, ClientIdHexRoundtrip) {
	seftp::proto::ClientId client= { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
		0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	auto client_id_hex = seftp::util::client_id_to_hex(client);
	ASSERT_EQ(client_id_hex.size(), 32);
	auto parse_client_id = seftp::util::parse_client_id_hex32(client_id_hex);
	EXPECT_EQ(client, parse_client_id);
}
TEST(Utilfunc, ClientIdHexUndersizeInput) {
	std::string undersize = "4f92bc11";
	EXPECT_THROW(seftp::util::parse_client_id_hex32(undersize), std::invalid_argument);
}
TEST(Utilfunc, ClientIdHexOversizeInput) {
	std::string oversize = "4f92bc118a3d475e9902f51bc36678adad";
	EXPECT_THROW(seftp::util::parse_client_id_hex32(oversize), std::invalid_argument);
}
TEST(Utilfunc, ClientIdNotHex) {
	std::string not_hex = "sf92bc118a3d475e990!f51bc36678ad";
	ASSERT_EQ(not_hex.size(), 32);
	EXPECT_THROW(seftp::util::parse_client_id_hex32(not_hex), std::invalid_argument);
}
TEST(Utilfunc, ClientIdVec) {
	seftp::proto::ClientId client = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
		0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	std::vector<uint8_t> client_vec = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
		0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
	auto client_id_vec = seftp::util::client_id_to_vec(client);
	ASSERT_EQ(client_id_vec.size(), client_vec.size());
	for (size_t i = 0; i < client_vec.size(); i++)
	{
		EXPECT_EQ(client_vec[i], client_id_vec[i]);
	}
}
TEST(Utilfunc, ClientIdHexIsLowercase) {
	seftp::proto::ClientId client = {
		0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
		0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55
	};
	auto hex = seftp::util::client_id_to_hex(client);
	ASSERT_EQ(hex.size(), 32);
	for (char c : hex) {
		EXPECT_TRUE((c >= '0' && c <= '9') ||(c >= 'a' && c <= 'f'));
	}
}
