#include <gtest/gtest.h>
#include "../../client/src/protocol/protocol.hpp"
TEST(ProtocolLEHelpers, LE_Helpers) {
	//Arrenge
	//append_u8
	std::vector<uint8_t>b;
	uint8_t v_8 = 0x2A;
	//Act
	seftp::proto::append_u8(b, v_8);
	//Assert
	ASSERT_EQ(b.size(), 1);
	EXPECT_EQ(b[0], v_8);
	b.clear();
	//append_u16_le
	uint16_t v_16= 0xCAFA;
	seftp::proto::append_u16_le(b, v_16);
	ASSERT_EQ(b.size(), 2);
	EXPECT_EQ(b[0], 0xFA);
	EXPECT_EQ(b[1], 0xCA);
	b.clear();
	//append_u32_le
	uint32_t v_32 = 0xB5FA0CD1;
	seftp::proto::append_u32_le(b, v_32);
	ASSERT_EQ(b.size(), 4);
	EXPECT_EQ(b[0], 0xD1);
	EXPECT_EQ(b[1], 0x0C);
	EXPECT_EQ(b[2], 0xFA);
	EXPECT_EQ(b[3], 0xB5);
	b.clear();
	//read_u16_le
	uint8_t buffer_1[] = { 0xFA,0xCA };
	uint16_t result_1 = seftp::proto::read_u16_le(buffer_1);
	EXPECT_EQ(result_1, 0xCAFA);
	//read_u32_le
	uint8_t buffer_2 [] = {0xD1,0x0C,0xFA,0xB5};
	uint32_t result_2 = seftp::proto::read_u32_le(buffer_2);
	EXPECT_EQ(result_2, 0xB5FA0CD1);
	//extra sanity
	const uint8_t z16[] = { 0x00, 0x00 };
	const uint8_t z32[] = { 0x00, 0x00, 0x00, 0x00 };
	EXPECT_EQ(seftp::proto::read_u16_le(z16), 0u);
	EXPECT_EQ(seftp::proto::read_u32_le(z32), 0u);
}