#include <iostream>
#include "console_ui.hpp"
#include "../flow/flow.hpp"

using boost::asio::ip::tcp;


namespace seftp::ui {
	static int read_menu_choise() {
		std::string line;
		std::getline(std::cin, line);
		try { return std::stoi(line); }
		catch (...) { return -1; }
	}
	static void print_status(const UiState& st, const seftp::ClientConfig& cfg, const seftp::ClientContext& cc) {
		std::cout << "\n --- Status --- \n";
		std::cout << "server: " << cfg.host << ":" << cfg.port << "\n";
		std::cout << "connected: " << (st.connected ? "yes" : "no") << "\n";
		std::cout << "username: " << cc.username << "\n";
		std::cout << "client_id_loaded: " << (!cc.client_id.empty() ? cc.client_id : "(none)") << "\n";
		if (!st.last_status.empty()) std::cout << "last_status: " << st.last_status << "\n";
		if (!st.last_error.empty()) std::cout << "last_error: " << st.last_error << "\n";
		std::cout << "--------------\n";
	}
	int run_console_ui(boost::asio::io_context& io, boost::asio::ip::tcp::socket& s, boost::asio::ip::tcp::resolver& resolver, const seftp::ClientConfig& cfg, seftp::ClientContext& cc) {
		UiState ui;

		for(;;){
			std::cout << "\n === SEFTP Client === \n";
			if (!ui.last_error.empty()) std::cout << "ERROR: " << ui.last_error << "\n";
			if (!ui.last_status.empty()) std::cout << "INFO: " << ui.last_status << "\n";

			if (!ui.connected) std::cout << "1) Connect\n";
			else std::cout << "1) Reconnect\n";
			std::cout << "2) Status\n";
			if (ui.connected) {
				std::cout << "3) Send single file\n";
				std::cout << "4) Send batch\n";
			}
			std::cout << "0) Exit\n";
			std::cout << "> ";

			int c = read_menu_choise();
			if (c == 0) break;
			if (c == 2) {
				print_status(ui, cfg, cc);
				continue;
			}
			if (c == 1) {
				ui.last_error.clear();
				ui.last_status = ui.connected ? "reconnecting..." : "connecting...";
				
				if (ui.connected) {
					seftp::flow::disconnect_socket(s);
					ui.connected = false;
					ui.aes_b64.clear();
				}

				std::string aes_b64;
				bool ok = seftp::flow::connect_and_handshake(io, s, resolver, cfg, cc, aes_b64);
				if(!ok){
					ui.last_error = cc.last_error_text.empty() ? "connect failed" : cc.last_error_text;
					ui.last_status.clear();
					ui.connected = false;
				}
				else {
					ui.connected = true;
					ui.aes_b64 = std::move(aes_b64);
					ui.last_status = "connected as " + cc.username + " id=" + cc.client_id;
				}
				continue;
			}
			if (ui.connected && c == 3) {
				std::string path;
				std::cout << "What is the file name you want to send?\n";
				std::getline(std::cin, path);
				if (path.empty()) {
					ui.last_error = "no file provided";
					ui.last_status.clear();
					continue;
				}
				bool ok = seftp::flow::send_single_file(s, ui.aes_b64, cc, path);
				if (!ok) {
					ui.last_error = cc.last_error_text.empty() ? ("failed sending file: " + path) : cc.last_error_text;
					ui.last_status.clear();
				}
				else {
					ui.last_status = "file: " + path + " sent to the server.";
				}
				continue;
			}
			if (ui.connected && c == 4) {
				std::string line;
				std::cout << "What are the file names you want to send? (separated by space)\n";
				std::getline(std::cin, line);
				std::stringstream ss(line);
				std::vector<std::string> tokens;
				std::string path;
				while (ss >> path) {
					tokens.push_back(path);
				}
				if (tokens.empty()) {
					ui.last_error = "no files provided";
					ui.last_status.clear();
					continue;
				}
				int success_count = 0;
				int fail_count = 0;
				for (const std::string& name : tokens) {
					bool ok = seftp::flow::send_single_file(s, ui.aes_b64, cc, name);
					if (!ok) {
						++fail_count;
						std::cout << "ERROR: "<< (cc.last_error_text.empty() ? ("failed sending file: " + name) : cc.last_error_text)<< "\n";
					}
					else {
						++success_count;
						std::cout << "INFO: file sent: " << name << "\n";
					}
				}
				if (fail_count > 0) {
					ui.last_error = std::to_string(fail_count) + " file(s) failed";
				}
				else {
					ui.last_error.clear();
				}
				ui.last_status = std::to_string(success_count) + " file(s) sent successfully";
				continue;
			}
			ui.last_error = "invalid choice";
		}
		seftp::flow::disconnect_socket(s);
		ui.connected = false;
		ui.aes_b64.clear();
		return 0;
	}
}