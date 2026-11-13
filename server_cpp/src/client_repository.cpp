#include "seftp_server/client_repository.hpp"

#include <sqlite3.h>
#include <sstream>
#include <chrono>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <stdexcept>

namespace {

    struct StatementCloser {
        void operator()(sqlite3_stmt* stmt) const noexcept {
            if (stmt != nullptr) {
                (void)sqlite3_finalize(stmt);
            }
        }
    };

    std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);

        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &now_c);
#else
        localtime_r(&now_c, &tm_buf);
#endif

        std::stringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void exec_or_throw(sqlite3* db, const char* sql) {
        const int rc = sqlite3_exec(db,sql,nullptr,nullptr,nullptr);

        if (rc != SQLITE_OK) {
            const std::string message = sqlite3_errmsg(db);
            throw std::runtime_error(message);
        }
    }
}


namespace seftp::server::persistence {

void ClientRepository::SqliteCloser::operator()(sqlite3* db) const noexcept {
    if (db != nullptr) {
        (void)sqlite3_close(db);
    }
}

ClientRepository::ClientRepository(const std::string& db_path) {
    sqlite3* raw_db = nullptr;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    int rc = sqlite3_open_v2(db_path.c_str(),&raw_db, flags, nullptr);
    db_.reset(raw_db);
    if (rc != SQLITE_OK) {
        std::string err_msg = db_ ? sqlite3_errmsg(db_.get()) : "Out of memory";
        throw std::runtime_error("Failed to open database: " + err_msg);
    }

    exec_or_throw(db_.get(), "PRAGMA foreign_keys = ON;");


    {
        sqlite3_stmt* raw_stmt = nullptr;

        const int prepare_rc = sqlite3_prepare_v2(
            db_.get(),
            "PRAGMA journal_mode = WAL;",
            -1,
            &raw_stmt,
            nullptr
        );

        std::unique_ptr<sqlite3_stmt, StatementCloser> stmt(raw_stmt);

        if (prepare_rc != SQLITE_OK) {
            throw std::runtime_error(
                std::string("Failed to prepare WAL: ") +
                sqlite3_errmsg(db_.get())
            );
        }

        const int step_rc = sqlite3_step(stmt.get());

        if (step_rc != SQLITE_ROW) {
            throw std::runtime_error(
                std::string("Failed to configure WAL: ") +
                sqlite3_errmsg(db_.get())
            );
        }

        const auto* mode_text = sqlite3_column_text(stmt.get(), 0);

        if (mode_text == nullptr) {
            throw std::runtime_error("SQLite returned no journal mode");
        }

        const std::string mode(
            reinterpret_cast<const char*>(mode_text)
        );

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            throw std::runtime_error(
                std::string("Failed to finish WAL configuration: ") +
                sqlite3_errmsg(db_.get())
            );
        }

        if (mode != "wal") {
            if (mode != "delete" &&
                mode != "truncate" &&
                mode != "persist") {
                throw std::runtime_error(
                    "Unsupported SQLite journal mode: " + mode
                );
                }

            std::cerr
                << "Warning: SQLite WAL unavailable. "
                << "Using journal mode: " << mode << '\n';
        }
    }


    exec_or_throw(db_.get(), "PRAGMA synchronous = NORMAL;");

    const char* createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS Clients (
            id INTEGER PRIMARY KEY,
            client_id_hex TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            public_key_der BLOB,
            aes_key_b64 TEXT,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
    )";

    exec_or_throw(db_.get(),createTableSQL);
}

ClientRepository::~ClientRepository() = default;

RegistrationResult ClientRepository::register_client(const std::string& username) {
    const char* insertSQL = R"(
        INSERT INTO clients (client_id_hex, username, public_key_der, aes_key_b64, created_at, last_seen)
        VALUES (?, ?, NULL, NULL, ?, ?)
        ON CONFLICT(username) DO NOTHING;
    )";
    std::unique_ptr<sqlite3_stmt, StatementCloser> stmt;
    sqlite3_stmt* raw_stmt = nullptr;
    boost::uuids::random_generator gen;
    boost::uuids::uuid id = gen();
    int rc;

    rc = sqlite3_prepare_v2(db_.get(), insertSQL, -1, &raw_stmt, nullptr);
    stmt.reset(raw_stmt);

    if (rc == SQLITE_OK) {
        std::string clientId = boost::uuids::to_string(id);
        clientId.erase(std::remove(clientId.begin(), clientId.end(), '-'), clientId.end());
        std::string now = get_timestamp();

        rc = sqlite3_bind_text(stmt.get(), 1, clientId.c_str(), -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            return {RegistrationStatus::StorageError,{}};
        }

        rc = sqlite3_bind_text(stmt.get(), 2, username.c_str(), -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            return {RegistrationStatus::StorageError,{}};
        }

        rc = sqlite3_bind_text(stmt.get(), 3, now.c_str(), -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            return {RegistrationStatus::StorageError,{}};
        }

        rc = sqlite3_bind_text(stmt.get(), 4, now.c_str(), -1, SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            return {RegistrationStatus::StorageError,{}};
        }

        rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            return {RegistrationStatus::StorageError,{}};
        }

        if (sqlite3_changes(db_.get())==0) {
            return {RegistrationStatus::AlreadyExists,{}};
        }

        RegistrationResult res;
        res.status = RegistrationStatus::Created;
        std::copy(id.begin(), id.end(), res.client_id.begin());
        return res;
    }

    return {RegistrationStatus::StorageError, {}};
}

} // namespace seftp::server::persistence
