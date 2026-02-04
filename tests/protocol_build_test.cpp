/*#include <gtest/gtest.h>
#include "..\client\src\protocol\protocol.hpp"

TEST(ProtocolBuild, Build825Register) {
	//Arrenge
	std::string username = "Alice";
	//Act
	auto frame = seftp::proto::build_825_register(username);
	//Assert
	ASSERT_GT(frame.size(), 3);
	uint8_t version = frame[0];
	EXPECT_EQ(version, seftp::proto::kVersion);

	uint16_t code = frame[1] | (frame[2] << 8);
	EXPECT_EQ(code, static_cast<uint16_t>(seftp::proto::ReqCode::Register));

	std::string payload(frame.begin() + seftp::proto::kReqHeaderLen, frame.end());

	EXPECT_EQ(payload, username+'\0');

}*/