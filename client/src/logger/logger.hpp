#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <iomanip>
#include <chrono> 
namespace seftp::logger {
    enum class logLevel { Error, Warn, Info, Debug };

    class Logger {
    public:
        static Logger& getInstance();

        void setLevel(logLevel level);
        void info(const std::string& msg);
        void debug(const std::string& msg);
        void warn(const std::string& msg);
        void error(const std::string& msg);
        bool isDebugEnabled();

    private:
        Logger() = default;
        std::string getCurrentTime();
        void log(logLevel level, const std::string& message);
    };
}
