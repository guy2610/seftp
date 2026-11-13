#include "seftp_server/registration_validation.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {
    namespace application = seftp::server::application;
    namespace protocol = seftp::server::protocol;

    protocol::RequestFrame make_registration(std::string_view username) {
        protocol::RequestFrame frame;
        frame.version = 3;
        frame.code = protocol::RequestCode::Register;
        frame.payload.assign(username.begin(), username.end());
        frame.payload.push_back(0);
        return frame;
    }

    TEST(RegistrationValidationTest, AcceptsAsciiUsername) {
        const auto result = application::validate_registration_request(make_registration("alice_42"));
        EXPECT_EQ(result.status, application::RegistrationInputStatus::Valid);
        EXPECT_EQ(result.username, "alice_42");
    }

    TEST(RegistrationValidationTest, AcceptsUnicodeLettersAndNumericCharacters) {
        // Python's str.isalnum() accepts these Unicode character classes.
        const auto username = std::string{u8"משתמש9¼"};
        const auto result = application::validate_registration_request(make_registration(username));
        EXPECT_EQ(result.status, application::RegistrationInputStatus::Valid);
        EXPECT_EQ(result.username, username);
    }

    TEST(RegistrationValidationTest, CountsUnicodeCodePointsNotUtf8Bytes) {
        std::string username;
        for (std::size_t i = 0; i < 64; ++i) {
            username += u8"א";
        }
        EXPECT_GT(username.size(), 64u);
        EXPECT_EQ(application::validate_registration_request(make_registration(username)).status,
                  application::RegistrationInputStatus::Valid);

        username += u8"א";
        EXPECT_EQ(application::validate_registration_request(make_registration(username)).status,
                  application::RegistrationInputStatus::InvalidUsername);
    }

    TEST(RegistrationValidationTest, RejectsEmptyUsername) {
        EXPECT_EQ(application::validate_registration_request(make_registration("")).status,
                  application::RegistrationInputStatus::InvalidUsername);
    }

    TEST(RegistrationValidationTest, RejectsInvalidUsernameCharacters) {
        for (const auto username : {"-alice", "alice bob", "../evil", "alice/bob", "a\n"}) {
            EXPECT_EQ(application::validate_registration_request(make_registration(username)).status,
                      application::RegistrationInputStatus::InvalidUsername) << username;
        }
        EXPECT_EQ(application::validate_registration_request(make_registration(u8"a\u0301")).status,
                  application::RegistrationInputStatus::InvalidUsername);
    }

    TEST(RegistrationValidationTest, RequiresZeroClientId) {
        auto frame = make_registration("alice");
        frame.client_id[0] = 1;
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, RequiresExactlyOneTrailingNul) {
        auto frame = make_registration("alice");
        frame.payload.pop_back();
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);

        frame = make_registration("alice");
        frame.payload.push_back(0);
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);

        frame = make_registration("alice");
        frame.payload.insert(frame.payload.begin() + 2, 0);
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, RejectsMalformedUtf8) {
        auto frame = make_registration("alice");
        frame.payload = {0xC3, 0x28, 0x00}; // Invalid UTF-8 two-byte sequence.
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, RejectsNonRegistrationRequest) {
        auto frame = make_registration("alice");
        frame.code = protocol::RequestCode::Upload;
        EXPECT_EQ(application::validate_registration_request(frame).status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, RejectsEmptyPayload) {
        auto frame = make_registration("alice");
        frame.payload.clear();

        const auto result =
            application::validate_registration_request(frame);

        EXPECT_EQ(result.status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, MalformedUtf8TakesPriorityOverInvalidCharacter) {
        auto frame = make_registration("alice!");

        // Append invalid UTF-8 before the trailing NUL.
        frame.payload.pop_back();
        frame.payload.push_back(0xC3);
        frame.payload.push_back(0x28);
        frame.payload.push_back(0x00);

        const auto result =
            application::validate_registration_request(frame);

        EXPECT_EQ(result.status,
                  application::RegistrationInputStatus::Malformed);
    }

    TEST(RegistrationValidationTest, MalformedUtf8TakesPriorityOverExcessiveLength) {
        auto frame = make_registration(std::string(65, 'a'));

        // Username is already too long, but UTF-8 must still be checked.
        frame.payload.pop_back();
        frame.payload.push_back(0xC3);
        frame.payload.push_back(0x28);
        frame.payload.push_back(0x00);

        const auto result =
            application::validate_registration_request(frame);

        EXPECT_EQ(result.status,
                  application::RegistrationInputStatus::Malformed);
    }

} // namespace
