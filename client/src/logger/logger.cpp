#include "logger.hpp"
#include <sstream>   
#include <iomanip>
#include <chrono>
#include <ctime>

namespace seftp::logger {

    static logLevel g_level = logLevel::Info;

    Logger& Logger::getInstance() {
        static Logger instance;
        return instance;
    }

    void Logger::setLevel(logLevel level) {
        g_level = level;
    }

    bool Logger::isDebugEnabled() {
        return g_level == logLevel::Debug;
    }

    void Logger::info(const std::string& msg) { log(logLevel::Info, msg); }
    void Logger::debug(const std::string& msg) { log(logLevel::Debug, msg); }
    void Logger::warn(const std::string& msg) { log(logLevel::Warn, msg); }
    void Logger::error(const std::string& msg) { log(logLevel::Error, msg); }

    std::string Logger::getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        std::tm buf{};
        #ifdef _WIN32
        localtime_s(&buf, &in_time_t);
        #else
        localtime_r(&in_time_t, &buf);
        #endif

        std::ostringstream ss;
        ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void Logger::log(logLevel level, const std::string& message) {
        if (static_cast<int>(level) > static_cast<int>(g_level)) return;

        const char* levelstr = "";
        switch (level) {
        case logLevel::Error: levelstr = "[ERROR]"; break;
        case logLevel::Warn:  levelstr = "[WARN]";  break;
        case logLevel::Info:  levelstr = "[INFO]";  break;
        case logLevel::Debug: levelstr = "[DEBUG]"; break;
        }

        std::ostream& out = (level == logLevel::Error || level == logLevel::Warn) ? std::cerr : std::cout;
        out << getCurrentTime() << " " << levelstr << " " << message << std::endl;
    }

}