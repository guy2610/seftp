#include <gtest/gtest.h>
#include "../client/src/protocol/protocol.hpp"
TEST(ProtocolResParse, ResParse1600) {
    //Arrenge
    //parse_1600
    struct seftp::proto::ByteView payload {};
    EXPECT_THROW(seftp::proto::parse_1600(payload), std::runtime_error);
    const uint8_t rawData[] = {
    0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD
    };

    payload.data = rawData;
    payload.size = sizeof(rawData) / sizeof(rawData[0]);

    seftp::proto::ClientId client = {
    0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD
    };
    EXPECT_NO_THROW(seftp::proto::parse_1600(payload));

    const auto msg = seftp::proto::parse_1600(payload);
    ASSERT_EQ(msg.client_id.size(), seftp::proto::kClientIdLen);
    EXPECT_EQ(msg.client_id, client);
}
TEST(ProtocolResParse, ResParse1602) {
    //parse_1602
    const uint8_t rawData[] = {
    0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD
    };
    seftp::proto::ClientId client = {
    0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD
    };
    seftp::proto::ByteView too_short_1602{ rawData, 16 };
    EXPECT_THROW(seftp::proto::parse_1602(too_short_1602), std::runtime_error);

    const uint8_t rawData256_1602[256] = { 0x4F };
    const uint8_t rawData16_1602[16] = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
    uint8_t rawDataCombined_1602[272];
    memcpy(rawDataCombined_1602, rawData256_1602, 256);
    memcpy(rawDataCombined_1602 + 256, rawData16_1602, 16);
    seftp::proto::ByteView bv_1602{};
    bv_1602.data = rawDataCombined_1602;
    bv_1602.size = sizeof(rawDataCombined_1602) / sizeof(rawDataCombined_1602[0]);

    EXPECT_NO_THROW(seftp::proto::parse_1602(bv_1602));
    const auto msg_1602 = seftp::proto::parse_1602(bv_1602);
    ASSERT_EQ(msg_1602.client_id.size(), seftp::proto::kClientIdLen);
    EXPECT_EQ(msg_1602.client_id, client);

    seftp::proto::Res1602 r_1602;
    r_1602.client_id = client;
    std::vector<uint8_t> key(rawDataCombined_1602, rawDataCombined_1602 + 256);

    EXPECT_EQ(msg_1602.encrypted_key.size(), 256u);
    EXPECT_EQ(msg_1602.encrypted_key[0], 0x4F);
    EXPECT_EQ(msg_1602.encrypted_key, key);
}
TEST(ProtocolResParse, ResParse1603){
    //parse_1603
    seftp::proto::ByteView bv_1603{};
    EXPECT_THROW(seftp::proto::parse_1603(bv_1603), std::runtime_error);

    const uint8_t data_client[16] = { 0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
    0x99, 0x02, 0xF5, 0x1B, 0xC3, 0x66, 0x78, 0xAD };
    const uint8_t data_content[4] = { 0x4F, 0x92, 0xBC, 0x11 };
    const uint8_t data_filename[2] = { 0x4F, 0x92 };
    const uint8_t data_server_crc[4] = { 0x4F, 0x92, 0xBC, 0x11 };
    uint8_t payload_1603[16 + 4 + 2 + 4];
    memcpy(payload_1603, data_client, seftp::proto::kClientIdLen);
    memcpy(payload_1603+ seftp::proto::kClientIdLen, data_content, 4);
    memcpy(payload_1603 + 20, data_filename, 2);
    memcpy(payload_1603 + 22, data_server_crc, 4);
    bv_1603.data = payload_1603;
    bv_1603.size = sizeof(payload_1603) / sizeof(payload_1603[0]);

    EXPECT_NO_THROW(seftp::proto::parse_1603(bv_1603));
    const auto msg_1603 = seftp::proto::parse_1603(bv_1603);
    ASSERT_EQ(msg_1603.client_id.size(), seftp::proto::kClientIdLen);
    seftp::proto::ClientId expected_cid{};
    memcpy(expected_cid.data(), data_client, 16);
    EXPECT_EQ(msg_1603.client_id, expected_cid);

    seftp::proto::Res1603 r_1603;
    uint32_t expected_content = seftp::proto::read_u32_le(data_content);
    uint32_t expected_crc = seftp::proto::read_u32_le(data_server_crc);
    memcpy(&r_1603.client_id, data_client, sizeof(data_client));
    r_1603.filename = std::string(data_filename, data_filename + 2);
    EXPECT_EQ(msg_1603.content_size, expected_content);
    EXPECT_EQ(msg_1603.server_crc, expected_crc);
    std::string expected_filename(reinterpret_cast<const char*>(data_filename), 2);
    EXPECT_EQ(msg_1603.filename, expected_filename);
}