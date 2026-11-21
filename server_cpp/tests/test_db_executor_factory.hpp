#pragma once

#include "seftp_server/db_executor.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

namespace seftp::server::test_support {

    inline std::shared_ptr<persistence::DbExecutor> make_test_db_executor() {
        namespace fs = std::filesystem;

        static std::atomic<std::uint64_t> counter{0};
        const auto base = fs::temp_directory_path();

        fs::path directory;
        bool created = false;

        for (int attempt = 0; attempt < 32; ++attempt) {
            const auto id = counter.fetch_add(1, std::memory_order_relaxed);
            const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();

            directory = base / ("seftp-test-" + std::to_string(ticks) + "-" + std::to_string(id));

            std::error_code ec;
            created = fs::create_directory(directory, ec);

            if (ec) {
                throw fs::filesystem_error("Cannot create test directory", directory, ec);
            }
            if (created) {
                break;
            }
        }

        if (!created) {
            throw std::runtime_error("Cannot allocate unique test directory");
        }

        try {
            return std::shared_ptr<persistence::DbExecutor>(
                new persistence::DbExecutor((directory / "test.db").string()),
                [directory](persistence::DbExecutor* executor) {
                    delete executor;

                    std::error_code ec;
                    fs::remove_all(directory, ec);
                });
        } catch (...) {
            std::error_code ec;
            fs::remove_all(directory, ec);
            throw;
        }
    }

} // namespace seftp::server::test_support
