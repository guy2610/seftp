#pragma once

#include <iostream>
#include <mutex>
#include <string>

namespace seftp::server {
    inline std::mutex& log_mutex() {
        static std::mutex mutex;
        return mutex;
    }
    inline void log_line(const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex());
        std::cout << message << '\n';
    }

    inline void log_error(const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex());
        std::cerr << message << '\n';
    }

}  // namespace seftp::server