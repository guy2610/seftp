#pragma once
#include <cstdint>
#include <vector>
#include <boost/asio.hpp>
#include "../protocol/protocol.hpp"

namespace seftp::net {
	using boost::asio::ip::tcp;
	
	struct ResponseFrame {
		uint8_t version = 0;
		seftp::proto::ResCode code = static_cast<seftp::proto::ResCode>(0);
		std::vector<uint8_t> payload;

	};

	ResponseFrame read_response_frame(tcp::socket& s);
}