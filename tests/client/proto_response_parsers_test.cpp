#include <gtest/gtest.h>
#include "../../client/src/protocol/protocol.hpp"
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
    seftp::proto::ClientId client{
        0x4F, 0x92, 0xBC, 0x11, 0x8A, 0x3D, 0x47, 0x5E,
        0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66
    };

    const uint8_t too_short_raw[16] = {0};
    seftp::proto::ByteView too_short{too_short_raw, sizeof(too_short_raw)};
    EXPECT_THROW(seftp::proto::parse_1602(too_short), std::runtime_error);

    std::vector<uint8_t> encrypted_key(256, 0x4F);
    std::vector<uint8_t> signature(256, 0xAA);

    std::vector<uint8_t> payload;
    payload.insert(payload.end(), client.begin(), client.end());

    uint16_t key_len = static_cast<uint16_t>(encrypted_key.size());
    payload.push_back(static_cast<uint8_t>(key_len & 0xFF));
    payload.push_back(static_cast<uint8_t>((key_len >> 8) & 0xFF));
    payload.insert(payload.end(), encrypted_key.begin(), encrypted_key.end());

    uint16_t sig_len = static_cast<uint16_t>(signature.size());
    payload.push_back(static_cast<uint8_t>(sig_len & 0xFF));
    payload.push_back(static_cast<uint8_t>((sig_len >> 8) & 0xFF));
    payload.insert(payload.end(), signature.begin(), signature.end());

    seftp::proto::ByteView bv{payload.data(), payload.size()};

    EXPECT_NO_THROW(seftp::proto::parse_1602(bv));
    const auto msg = seftp::proto::parse_1602(bv);

    EXPECT_EQ(msg.client_id, client);
    EXPECT_EQ(msg.encrypted_key, encrypted_key);
    EXPECT_EQ(msg.signature, signature);
}
TEST(ProtocolResParse, ResParse1602RejectsEmptyEncryptedKey) {
    seftp::proto::ClientId client{};
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), client.begin(), client.end());

    payload.push_back(0x00);
    payload.push_back(0x00);

    seftp::proto::ByteView bv{payload.data(), payload.size()};
    EXPECT_THROW(seftp::proto::parse_1602(bv), std::runtime_error);
}

TEST(ProtocolResParse, ResParse1602RejectsEmptySignature) {
    seftp::proto::ClientId client{};
    std::vector<uint8_t> encrypted_key(256, 0x4F);

    std::vector<uint8_t> payload;
    payload.insert(payload.end(), client.begin(), client.end());

    uint16_t key_len = static_cast<uint16_t>(encrypted_key.size());
    payload.push_back(static_cast<uint8_t>(key_len & 0xFF));
    payload.push_back(static_cast<uint8_t>((key_len >> 8) & 0xFF));
    payload.insert(payload.end(), encrypted_key.begin(), encrypted_key.end());

    payload.push_back(0x00);
    payload.push_back(0x00);

    seftp::proto::ByteView bv{payload.data(), payload.size()};
    EXPECT_THROW(seftp::proto::parse_1602(bv), std::runtime_error);
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