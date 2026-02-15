#include <gtest/gtest.h>
#include <array>
#include <vector>
#include "../../client/src/crypto/crypto.hpp"

static std::string make_data(size_t n) {
    std::string s;
    s.resize(n);
    for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>(i % 256);
    return s;
}
static std::string read_file_bin(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
TEST(CryptoTests, RandIv) {
	ASSERT_EQ(seftp::crypto::make_iv().size(), 16u);
}
TEST(CryptoTests, Base64EncodeDecode) {
    std::string raw;
    raw.push_back('\0');
    raw += "abc";
    raw.push_back('\0');
    raw += "xyz";

    const auto b64 = seftp::crypto::encode_base64(raw);
    const auto dec = seftp::crypto::decode_base64(b64);

    EXPECT_EQ(dec.size(), raw.size());
    EXPECT_EQ(dec, raw);
}
TEST(CryptoTests, CRC32_KnownVector_123456789) {
    const auto v = seftp::crypto::crc32("123456789");
    EXPECT_EQ(v, 0xCBF43926u);
}
TEST(CryptoTests, CRC32_Empty) {
    const auto v = seftp::crypto::crc32("");
    EXPECT_EQ(v, 0u);
}
TEST(CryptoTests, AES_DeterministicWithFixedIV) {
    const std::string key32(32, 'k');
    const std::array<uint8_t, 16> iv = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    const std::string example = "hello world";

    const auto c1 = seftp::crypto::aes256_cbc_encrypt(example, key32, iv);
    const auto c2 = seftp::crypto::aes256_cbc_encrypt(example, key32, iv);

    ASSERT_FALSE(c1.empty());
    ASSERT_FALSE(c2.empty());

    EXPECT_EQ(c1, c2);
}
TEST(CryptoTests, AES_RejectsWrongKeySize) {
    const std::string bad_key = "short";
    const std::array<uint8_t, 16> iv = { 0 };

    const auto c = seftp::crypto::aes256_cbc_encrypt("x", bad_key, iv);
    EXPECT_TRUE(c.empty());
}
TEST(CryptoTests, RSA_DecryptRejectsNon256Ciphertext) {
    std::vector<uint8_t> ct(10, 0);
    EXPECT_THROW((void)seftp::crypto::rsa_oaep_sha1_decrypt_from_file("priv.key", ct), std::runtime_error);
}
TEST(CryptoTests, AES_RoundTripVariousSizes) {
    const std::string key32(32, 'K');
    const std::array<uint8_t, 16> iv = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

    for (size_t n : {0u, 1u, 15u, 16u, 17u, 1024u}) {
        const auto pt = make_data(n);
        const auto ct = seftp::crypto::aes256_cbc_encrypt(pt, key32, iv);
        ASSERT_FALSE(ct.empty());
        const auto dec = seftp::crypto::aes256_cbc_decrypt(ct, key32, iv);
        EXPECT_EQ(dec, pt);
    }
}
TEST(CryptoTests, AES_WrongIVFailsToMatch) {
    const std::string key32(32, 'K');
    const std::array<uint8_t, 16> iv1 = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    const std::array<uint8_t, 16> iv2 = { 1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

    const auto pt = "hello";
    const auto ct = seftp::crypto::aes256_cbc_encrypt(pt, key32, iv1);
    const auto dec = seftp::crypto::aes256_cbc_decrypt(ct, key32, iv2);

    EXPECT_NE(dec, pt);
}
TEST(CryptoTests, AES_WrongKeySizeReturnsEmpty) {
    const std::array<uint8_t, 16> iv = { 0 };
    EXPECT_TRUE(seftp::crypto::aes256_cbc_decrypt("abc", "short", iv).empty());
}
TEST(CryptoTests, RSA_GenerateKeypair_ReturnsValidPublicKeyDerAndB64) {
    auto pk = seftp::crypto::generate_rsa2048_keypair_der("");
    ASSERT_FALSE(pk.publicKeyDer.empty());
    ASSERT_FALSE(pk.publicKeyB64.empty());

    // base64 must decode back to DER bytes
    const auto decoded = seftp::crypto::decode_base64(pk.publicKeyB64);
    EXPECT_EQ(decoded, pk.publicKeyDer);

    // DER should be loadable as RSA public key
    CryptoPP::RSA::PublicKey pub;
    CryptoPP::ByteQueue q;
    q.Put(reinterpret_cast<const CryptoPP::byte*>(pk.publicKeyDer.data()), pk.publicKeyDer.size());
    pub.Load(q);
    EXPECT_TRUE(pub.Validate(CryptoPP::AutoSeededRandomPool{}, 3));
}

TEST(CryptoTests, RSA_LoadingSamePrivateKey_ReturnsSamePublicDer) {
    const std::string fname = "test_priv.key";
    
    //Produce test_priv.key
    auto pk1 = seftp::crypto::generate_rsa2048_keypair_der("", fname);
    ASSERT_FALSE(pk1.publicKeyDer.empty());

    const auto priv_bytes = read_file_bin(fname);
    ASSERT_FALSE(priv_bytes.empty());
    
    //Read buffer from test_priv.key
    auto pk2 = seftp::crypto::generate_rsa2048_keypair_der(priv_bytes, fname);

    EXPECT_EQ(pk2.publicKeyDer, pk1.publicKeyDer);
    EXPECT_EQ(pk2.publicKeyB64, pk1.publicKeyB64);
    std::remove(fname.c_str());
}
