#include <gtest/gtest.h>
#include <sstream>
#include <iostream>
#include "../client/src/logger/logger.hpp"

namespace {
	class StreamCapture {
	private:
		std::ostream& os_;
		std::stringstream buf_;
		std::streambuf* old_;

	public:
		explicit StreamCapture(std::ostream& s) :os_(s), old_(s.rdbuf(buf_.rdbuf())) {}

		~StreamCapture() {
			os_.rdbuf(old_);
		}
		std::string str() const {
			return buf_.str();
		}
		void clear() {
			buf_.str("");
			buf_.clear();
		}
	};
}
static bool contains(const std::string& s,const std::string& sub) {
	return s.find(sub) != std::string::npos;	
}
TEST(LoggerTests, InfoGoesToCoutNotCerr) {
	auto& lg = seftp::logger::Logger::getInstance();
	lg.setLevel(seftp::logger::logLevel::Debug);

	StreamCapture capOut(std::cout);
	StreamCapture capErr(std::cerr);

	lg.info("hello");

	EXPECT_TRUE(contains(capOut.str(), "[INFO]"));
	EXPECT_TRUE(contains(capOut.str(), "hello"));
	EXPECT_TRUE(capErr.str().empty());
}
TEST(LoggerTests, WarnGoesToCerr) {
	auto& lg = seftp::logger::Logger::getInstance();
	lg.setLevel(seftp::logger::logLevel::Debug);

	StreamCapture capOut(std::cout);
	StreamCapture capErr(std::cerr);

	lg.warn("warning");

	EXPECT_TRUE(contains(capErr.str(), "[WARN]"));
	EXPECT_TRUE(contains(capErr.str(), "warning"));
	EXPECT_TRUE(capOut.str().empty());
}
TEST(LoggerTests, FiltersByLevel_InfoDoesNotPrintDebug) {
	auto& lg = seftp::logger::Logger::getInstance();
	lg.setLevel(seftp::logger::logLevel::Info);

	StreamCapture capOut(std::cout);
	StreamCapture capErr(std::cerr);

	lg.debug("debug");
	lg.info("info");

	EXPECT_FALSE(contains(capOut.str(), "debug"));
	EXPECT_TRUE(contains(capOut.str(), "[INFO]"));
	EXPECT_TRUE(contains(capOut.str(), "info"));
	EXPECT_TRUE(capErr.str().empty());


}
TEST(LoggerTests, ErrorAlwaysPrintedWhenLevelInfo) {
	auto& lg = seftp::logger::Logger::getInstance();
	lg.setLevel(seftp::logger::logLevel::Info);

	StreamCapture capOut(std::cout);
	StreamCapture capErr(std::cerr);
	
	lg.error("boom");
	EXPECT_TRUE(contains(capErr.str(), "[ERROR]"));
	EXPECT_TRUE(contains(capErr.str(), "boom"));
	EXPECT_TRUE(capOut.str().empty());

}
TEST(LoggerTests, HasTimestampPrefix){
	auto& lg = seftp::logger::Logger::getInstance();
	lg.setLevel(seftp::logger::logLevel::Info);

	StreamCapture capOut(std::cout);
	lg.info("x");

	const auto out = capOut.str();
	ASSERT_GE(out.size(), 20u);
	// "YYYY-MM-DD HH:MM:SS"
	EXPECT_TRUE(std::isdigit(out[0]) && std::isdigit(out[1]) && std::isdigit(out[2]) && std::isdigit(out[3]));
	EXPECT_EQ('-', out[4]);
	EXPECT_TRUE(std::isdigit(out[5]) && std::isdigit(out[6]));
	EXPECT_EQ('-', out[7]);
	EXPECT_TRUE(std::isdigit(out[8]) && std::isdigit(out[9]));
	EXPECT_EQ(out[10], ' ');
	EXPECT_EQ(out[13], ':');
	EXPECT_EQ(out[16], ':');
}