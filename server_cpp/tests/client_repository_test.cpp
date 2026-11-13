#include "seftp_server/client_repository.hpp"

#include <sqlite3.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {
namespace persistence = seftp::server::persistence;

class TemporaryDatabase {
public:
    TemporaryDatabase() {
        static std::atomic<unsigned long long> counter{0};
        const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto unique = counter.fetch_add(1);

        directory_ = std::filesystem::temp_directory_path() /
                     ("seftp_9d_repo_" + std::to_string(ticks) + "_" + std::to_string(unique));

        if (!std::filesystem::create_directory(directory_)) {
            throw std::runtime_error("Cannot create temporary SQLite test directory");
        }
    }

    ~TemporaryDatabase() {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    std::string path() const { return (directory_ / "seftp_test.db").string(); }

private:
    std::filesystem::path directory_;
};

using SqlitePtr = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
using StatementPtr = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

SqlitePtr open_readwrite_database(const std::string& path) {
    sqlite3* raw = nullptr;
    const int rc = sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    SqlitePtr db(raw, sqlite3_close);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open SQLite test database");
    }
    return db;
}

std::string to_hex(const std::array<std::uint8_t, 16>& bytes) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result += hex[byte >> 4];
        result += hex[byte & 0x0f];
    }
    return result;
}

TEST(ClientRepositoryTest, CreatesClientWithUuidV4) {
    TemporaryDatabase temporary;
    persistence::ClientRepository repo(temporary.path());

    const auto result = repo.register_client("alice");

    ASSERT_EQ(result.status, persistence::RegistrationStatus::Created);
    EXPECT_TRUE(std::any_of(result.client_id.begin(), result.client_id.end(),
                            [](std::uint8_t byte) { return byte != 0; }));
    EXPECT_EQ(result.client_id[6] & 0xf0, 0x40); // UUID version 4
    EXPECT_EQ(result.client_id[8] & 0xc0, 0x80); // RFC 4122 variant
}

TEST(ClientRepositoryTest, RejectsDuplicateUsername) {
    TemporaryDatabase temporary;
    persistence::ClientRepository repo(temporary.path());

    ASSERT_EQ(repo.register_client(u8"משתמש").status, persistence::RegistrationStatus::Created);

    const auto duplicate = repo.register_client(u8"משתמש");

    EXPECT_EQ(duplicate.status, persistence::RegistrationStatus::AlreadyExists);
}

TEST(ClientRepositoryTest, PersistsClientUsingPythonCompatibleSchema) {
    TemporaryDatabase temporary;
    std::array<std::uint8_t, 16> created_id{};

    {
        persistence::ClientRepository repo(temporary.path());
        const auto result = repo.register_client("alice");
        ASSERT_EQ(result.status, persistence::RegistrationStatus::Created);
        created_id = result.client_id;
    }

    {
        persistence::ClientRepository reopened(temporary.path());
        EXPECT_EQ(reopened.register_client("alice").status,
                  persistence::RegistrationStatus::AlreadyExists);
    }

    auto db = open_readwrite_database(temporary.path());
    sqlite3_stmt* raw_statement = nullptr;

    ASSERT_EQ(sqlite3_prepare_v2(db.get(),
              "SELECT client_id_hex, created_at, last_seen "
              "FROM Clients WHERE username = ?1", -1, &raw_statement, nullptr), SQLITE_OK);
    StatementPtr statement(raw_statement, sqlite3_finalize);
    ASSERT_EQ(sqlite3_bind_text(statement.get(), 1, "alice", -1, SQLITE_STATIC), SQLITE_OK);

    ASSERT_EQ(sqlite3_step(statement.get()), SQLITE_ROW);
    const auto* hex = sqlite3_column_text(statement.get(), 0);
    const auto* created = sqlite3_column_text(statement.get(), 1);
    const auto* last_seen = sqlite3_column_text(statement.get(), 2);

    ASSERT_NE(hex, nullptr);
    ASSERT_NE(created, nullptr);
    ASSERT_NE(last_seen, nullptr);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(hex)), to_hex(created_id));
    EXPECT_FALSE(std::string(reinterpret_cast<const char*>(created)).empty());
    EXPECT_FALSE(std::string(reinterpret_cast<const char*>(last_seen)).empty());
    EXPECT_EQ(sqlite3_step(statement.get()), SQLITE_DONE);
}

TEST(ClientRepositoryTest, InsertFailureDoesNotReportCreatedOrDuplicate) {
    TemporaryDatabase temporary;
    persistence::ClientRepository repo(temporary.path());

    // Inject a write failure that is NOT a duplicate-username constraint.
    auto db = open_readwrite_database(temporary.path());
    constexpr const char* trigger =
        "CREATE TRIGGER reject_registration BEFORE INSERT ON Clients "
        "BEGIN SELECT RAISE(FAIL, 'injected write failure'); END;";
    ASSERT_EQ(sqlite3_exec(db.get(), trigger, nullptr, nullptr, nullptr), SQLITE_OK);

    const auto result = repo.register_client("alice");

    EXPECT_EQ(result.status, persistence::RegistrationStatus::StorageError);
}

} // namespace
