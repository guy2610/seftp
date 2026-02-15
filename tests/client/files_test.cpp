#include <gtest/gtest.h>
#include <fstream>
#include "../../client/src/util/files.hpp"

using namespace seftp::util::files;
TEST(FileFunc, WriteMeIdentity) {
    const std::string testFile = "test_write_me.info";
    std::remove(testFile.c_str());

    const std::string user1 = "user1";
    const std::string id1 = "A1B2C3D4";
    const std::string user2 = "user2";
    const std::string id2 = "DEADBEEF";
    // first write
    ASSERT_TRUE(seftp::util::files::write_me_identity(user1, id1, testFile));
    {
        std::ifstream in(testFile);
        ASSERT_TRUE(in.is_open());

        std::string line1, line2, extra;
        ASSERT_TRUE(std::getline(in, line1));
        ASSERT_TRUE(std::getline(in, line2));

        EXPECT_EQ(line1, user1);
        EXPECT_EQ(line2, id1);
    }
    // overwrite with new values
    ASSERT_TRUE(seftp::util::files::write_me_identity(user2, id2, testFile));
    {
        std::ifstream in(testFile);
        ASSERT_TRUE(in.is_open());

        std::string line1, line2, extra;
        ASSERT_TRUE(std::getline(in, line1));
        ASSERT_TRUE(std::getline(in, line2));

        EXPECT_EQ(line1, user2);
        EXPECT_EQ(line2, id2);
    }
    std::remove(testFile.c_str());
}
TEST(FileFunc, WriteAesKey) {
    const std::string testFile = "test_aes.key";
    std::remove(testFile.c_str());

    const std::string key1 = "A1B2C3D4";
    const std::string key2 = "DEADBEEF";
    // first write
    ASSERT_TRUE(seftp::util::files::write_aes_key(key1, testFile));
    {
        std::ifstream in(testFile);
        ASSERT_TRUE(in.is_open());

        std::string line1, extra;
        ASSERT_TRUE(std::getline(in, line1));
        EXPECT_EQ(line1, key1);
        // should be exactly one line
        EXPECT_FALSE(std::getline(in, extra));
    }
    // overwrite
    ASSERT_TRUE(seftp::util::files::write_aes_key(key2, testFile));
    {
        std::ifstream in(testFile);
        ASSERT_TRUE(in.is_open());
        std::string line1, extra;
        ASSERT_TRUE(std::getline(in, line1));
        EXPECT_EQ(line1, key2);
        // still exactly one line
        EXPECT_FALSE(std::getline(in, extra));
    }
    std::remove(testFile.c_str());
}
TEST(FileFunc, ReadAesKey) {
    const std::string testFile = "test_read_aes.key";
    std::remove(testFile.c_str());
    // file not found
    {
        std::string out;
        EXPECT_FALSE(seftp::util::files::read_aes_key(out, testFile));
    }
    //empty file
    {
        std::ofstream f(testFile);
        ASSERT_TRUE(f.is_open());
        f.close();

        std::string out = "sentinel";
        ASSERT_TRUE(seftp::util::files::read_aes_key(out, testFile));
        EXPECT_EQ(out, ""); 
        std::remove(testFile.c_str());
    }
    // normal round-trip
    {
        const std::string key = "A1B2C3D4";
        ASSERT_TRUE(seftp::util::files::write_aes_key(key, testFile));

        std::string out;
        ASSERT_TRUE(seftp::util::files::read_aes_key(out, testFile));
        EXPECT_EQ(out, key);
        std::remove(testFile.c_str());
    }
    // overwrite behavior through read
    {
        const std::string key1 = "AAAA";
        const std::string key2 = "BBBB";

        ASSERT_TRUE(seftp::util::files::write_aes_key(key1, testFile));
        ASSERT_TRUE(seftp::util::files::write_aes_key(key2, testFile));

        std::string out;
        ASSERT_TRUE(seftp::util::files::read_aes_key(out, testFile));
        EXPECT_EQ(out, key2);
        std::remove(testFile.c_str());
    }
}
TEST(FileFunc, ReadPrivateKey) {
    const std::string testFile = "test_read_priv.key";
    std::remove(testFile.c_str());
    // file not found
    {
        std::string out;
        EXPECT_FALSE(seftp::util::files::read_private_key(out, testFile));
    }
    // read exact bytes (including newlines)
    {
        const std::string expected = "line1\nline2\nline3\n";
        {
            std::ofstream f(testFile, std::ios::binary | std::ios::trunc);
            ASSERT_TRUE(f.is_open());
            f.write(expected.data(), static_cast<std::streamsize>(expected.size()));
        }
        std::string out;
        ASSERT_TRUE(seftp::util::files::read_private_key(out, testFile));
        EXPECT_EQ(out, expected);
        std::remove(testFile.c_str());
    }
    // binary content (includes null byte)
    {
        std::string expected;
        expected.push_back('A');
        expected.push_back('\0');
        expected.push_back('B');
        expected.push_back('\n');
        {
            std::ofstream f(testFile, std::ios::binary | std::ios::trunc);
            ASSERT_TRUE(f.is_open());
            f.write(expected.data(), static_cast<std::streamsize>(expected.size()));
        }
        std::string out;
        ASSERT_TRUE(seftp::util::files::read_private_key(out, testFile));
        EXPECT_EQ(out.size(), expected.size());
        EXPECT_EQ(out, expected);
        std::remove(testFile.c_str());
    }
}
TEST(FileFunc, ReadMeInfo) {
    std::string testFile = "test_read_me.info";
    std::string id = "A1B2C3D4";
    std::string user = "user";
    bool success=false;
    std::string out_user, out_id;

    //file not found
    std::remove(testFile.c_str());
    out_user.clear();
    out_id.clear();
    ASSERT_FALSE(seftp::util::files::read_me_info(out_user, out_id, nullptr, testFile));
    EXPECT_TRUE(out_user.empty());
    EXPECT_TRUE(out_id.empty());

    //empty file
    std::ofstream inFile(testFile);
    ASSERT_TRUE(inFile.is_open());
    inFile.close();
    out_user.clear();
    out_id.clear();
    ASSERT_FALSE(seftp::util::files::read_me_info(out_user, out_id, nullptr, testFile));
    std::remove(testFile.c_str());
    EXPECT_TRUE(out_user.empty());
    EXPECT_TRUE(out_id.empty());
    
    //only username
    inFile.open(testFile);
    ASSERT_TRUE(inFile.is_open());
    inFile << user << '\n';
    inFile.close();
    out_user.clear();
    out_id.clear();

    ASSERT_FALSE(seftp::util::files::read_me_info(out_user, out_id, nullptr, testFile));
    EXPECT_TRUE(out_user.empty());
    EXPECT_TRUE(out_id.empty());
    std::remove(testFile.c_str());
    //username+id, public_key provided
    std::string data = "sentinel";
    inFile.open(testFile);
    ASSERT_TRUE(inFile.is_open());
    inFile << user << '\n';
    inFile << id << '\n';
    inFile.close();

    success = seftp::util::files::read_me_info(out_user, out_id, &data, testFile);
    ASSERT_TRUE(success);
    EXPECT_EQ(out_user, user);
    EXPECT_EQ(out_id, id);
    EXPECT_EQ(data, "");
    std::remove(testFile.c_str());

    //username+id+pubkey
    data = "sentinel2";
    std::string actual_data = "abcd";
    inFile.open(testFile);
    ASSERT_TRUE(inFile.is_open());
    inFile << user << '\n';
    inFile << id << '\n';
    inFile << actual_data << '\n';
    inFile.close();

    success = seftp::util::files::read_me_info(out_user, out_id, &data, testFile);
    ASSERT_TRUE(success);
    EXPECT_EQ(out_user, user);
    EXPECT_EQ(out_id, id);
    EXPECT_EQ(data, actual_data);
    std::remove(testFile.c_str());

    //username+id(+pubkey)
    inFile.open(testFile);
    ASSERT_TRUE(inFile.is_open());
    inFile << user << '\n';
    inFile << id << '\n';
    inFile << actual_data << '\n';
    inFile.close();
    out_id = "";
    out_user = "";

    success = seftp::util::files::read_me_info(out_user, out_id, nullptr, testFile);
    ASSERT_TRUE(success);
    EXPECT_EQ(out_user, user);
    EXPECT_EQ(out_id, id);
    std::remove(testFile.c_str());

}
TEST(FileFunc, WriteMePublicKey) {
    const std::string testFile = "test_me_pub.info";
    const std::string user = "user";
    const std::string cid = "A1B2C3D4";
    const std::string pub = "PUBLICKEYDATA";
    std::remove(testFile.c_str());
    //file does not exist
    EXPECT_FALSE(seftp::util::files::write_me_public_key(pub, testFile));
    //prepare identity file
    ASSERT_TRUE(seftp::util::files::write_me_identity(user, cid, testFile));
    //write public key
    ASSERT_TRUE(seftp::util::files::write_me_public_key(pub, testFile));
    {
        std::ifstream in(testFile);
        ASSERT_TRUE(in.is_open());

        std::string line1, line2, line3, extra;
        ASSERT_TRUE(std::getline(in, line1));
        ASSERT_TRUE(std::getline(in, line2));
        ASSERT_TRUE(std::getline(in, line3));

        EXPECT_EQ(line1, user);
        EXPECT_EQ(line2, cid);
        EXPECT_EQ(line3, pub);
        //exactly 3 lines
        EXPECT_FALSE(std::getline(in, extra));
    }
    std::remove(testFile.c_str());
}



