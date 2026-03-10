#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include "../../client/src/persistence/client_persistence.hpp"

using namespace seftp::persistence;

namespace {
    void cleanup_default_files() {
        std::remove("me.info");
        std::remove("aes.key");
        std::remove("priv.key");
    }
}

TEST(PersistenceTests, SaveLoadIdentity_RoundTrip) {
    cleanup_default_files();

    StoredIdentity in;
    in.username = "user1";
    in.client_id = "abcdef0123456789abcdef0123456789";

    std::string error;
    ASSERT_TRUE(save_identity(in, error));
    EXPECT_TRUE(error.empty());

    StoredIdentity out;
    ASSERT_TRUE(load_identity(out, error));
    EXPECT_EQ(out.username, in.username);
    EXPECT_EQ(out.client_id, in.client_id);
    EXPECT_TRUE(out.public_key_b64.empty());

    cleanup_default_files();
}

TEST(PersistenceTests, SavePublicKey_AfterIdentity_LoadIdentityReturnsPublicKey) {
    cleanup_default_files();

    StoredIdentity in;
    in.username = "user1";
    in.client_id = "abcdef0123456789abcdef0123456789";

    std::string error;
    ASSERT_TRUE(save_identity(in, error));
    ASSERT_TRUE(save_public_key("PUBKEY123", error));

    StoredIdentity out;
    ASSERT_TRUE(load_identity(out, error));
    EXPECT_EQ(out.username, in.username);
    EXPECT_EQ(out.client_id, in.client_id);
    EXPECT_EQ(out.public_key_b64, "PUBKEY123");

    cleanup_default_files();
}

TEST(PersistenceTests, LoadIdentity_FileMissing_ReturnsFalseAndError) {
    cleanup_default_files();

    StoredIdentity out;
    std::string error;
    EXPECT_FALSE(load_identity(out, error));
    EXPECT_FALSE(error.empty());

    cleanup_default_files();
}

TEST(PersistenceTests, SaveLoadAesKey_RoundTrip) {
    cleanup_default_files();

    std::string error;
    ASSERT_TRUE(save_aes_key("AESKEY123", error));
    EXPECT_TRUE(error.empty());

    std::string out;
    ASSERT_TRUE(load_aes_key(out, error));
    EXPECT_EQ(out, "AESKEY123");

    cleanup_default_files();
}

TEST(PersistenceTests, LoadAesKey_FileMissing_ReturnsFalseAndError) {
    cleanup_default_files();

    std::string out;
    std::string error;
    EXPECT_FALSE(load_aes_key(out, error));
    EXPECT_FALSE(error.empty());

    cleanup_default_files();
}

TEST(PersistenceTests, LoadPrivateKey_FileExists_ReturnsContent) {
    cleanup_default_files();

    const std::string expected = "line1\nline2\n";
    {
        std::ofstream f("priv.key", std::ios::binary);
        ASSERT_TRUE(f.is_open());
        f.write(expected.data(), static_cast<std::streamsize>(expected.size()));
    }

    std::string out;
    std::string error;
    ASSERT_TRUE(load_private_key(out, error));
    EXPECT_EQ(out, expected);

    cleanup_default_files();
}

TEST(PersistenceTests, LoadPrivateKey_FileMissing_ReturnsFalseAndError) {
    cleanup_default_files();

    std::string out;
    std::string error;
    EXPECT_FALSE(load_private_key(out, error));
    EXPECT_FALSE(error.empty());

    cleanup_default_files();
}