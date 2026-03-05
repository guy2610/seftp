#pragma once 
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "../client_types.hpp"

namespace seftp::ui {
	struct UiState {
		bool connected = false;
		std::string last_status;
		std::string last_error;
		std::string aes_b64;
	};

	int run_console_ui(boost::asio::io_context& io, boost::asio::ip::tcp::socket& s, boost::asio::ip::tcp::resolver& resolver, const seftp::ClientConfig& cfg, seftp::ClientContext& cc);
}