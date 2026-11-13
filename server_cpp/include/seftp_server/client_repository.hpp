#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>

// Forward declaration avoids exposing sqlite3.h to consumers.
struct sqlite3;

namespace seftp::server::persistence {

enum class RegistrationStatus {
    Created,
    AlreadyExists,
    StorageError,
};

struct RegistrationResult {
    RegistrationStatus status{RegistrationStatus::StorageError};
    std::array<std::uint8_t, 16> client_id{};
};

class ClientRepository {
public:
    explicit ClientRepository(const std::string& db_path);
    ~ClientRepository();

    ClientRepository(const ClientRepository&) = delete;
    ClientRepository& operator=(const ClientRepository&) = delete;
    ClientRepository(ClientRepository&&) = delete;
    ClientRepository& operator=(ClientRepository&&) = delete;

    RegistrationResult register_client(const std::string& username);

private:
    struct SqliteCloser {
        void operator()(sqlite3* db) const noexcept;
    };

    // Stage 9D.2: one SQLite connection, used by one DB worker later.
    std::unique_ptr<sqlite3, SqliteCloser> db_;
};

} // namespace seftp::server::persistence
