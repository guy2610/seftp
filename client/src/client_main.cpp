// Secure File Transfer Client
// Protocol: custom binary (client_id + version + code + payload size + payload)
// Crypto: RSA-2048 (Crypto++), AES-256-CBC, CRC32
// Dependencies: Boost.Asio, Crypto++

// This client registers/logs in to the server, receives an AES key encrypted
// with RSA-2048, encrypts a chosen file with AES-256-CBC, and sends it in chunks.

#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include <vector>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>          // AutoSeededRandomPool
#include <cryptopp/files.h>          // FileSink, FileSource
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>  // For HashFilter, HexEncoder, StringSink
#include <cryptopp/modes.h>
#include <iomanip>
#include <sstream>
#include <cryptopp/base64.h>   // CryptoPP::Base64Encoder
#include <cryptopp/crc.h> // For CRC32
#include <chrono>
#include <filesystem>
#include <random>
#include <cctype>
#include <algorithm>
#include <optional>
#include "protocol/protocol.hpp"
#include "net/net.hpp"
#include "util/util.hpp"
#include "crypto/crypto.hpp"
#include "logger/logger.hpp"
#include "ui/console_ui.hpp"
#include "flow/flow.hpp"
#include "client_types.hpp"
#include "persistence/client_persistence.hpp"

using namespace std;
using namespace CryptoPP;
using  boost::asio::ip::tcp;
struct ClientEvent {
	string method;
	string time_stamp;
};

struct CliOptions {
	bool debug_set = false;
	bool debug = false;
	std::vector<std::string> files;
	size_t file_index = 0;
};


bool load_tranfer_info(const std::string& path, seftp::ClientConfig& out);
string timestamp();
void request_825(tcp::socket& s, const string& name);
void request_826(tcp::socket& s, const string& name, const string& publicKeyStr, const string& uuid);
void request_827(tcp::socket& s, const string& name, const string & uuid);
void request_828_retry(tcp::socket& s, string encrypt_key, seftp::ClientContext& cc, const std::string& file_name);
void request_829(tcp::socket& s, std::array<uint8_t, seftp::proto::kStage7NonceLen>& client_nonce);
std::optional<uint32_t> request_828_streaming(tcp::socket& s, const string& name, const string& uuid, const string& encrypt_key, const std::string& file_name);
void request_830(tcp::socket& s);
void request_900(tcp::socket& s, const string& name, const string& uuid);
void request_901(tcp::socket& s, const string& name, const string& uuid);
void request_902(tcp::socket& s, const string& name, const string& uuid);
std::vector<uint8_t> parse_uuid(const std::string& uuid_str);
std::string to_hex(const std::string& data);
seftp::DispatchResult answer_manager(tcp::socket& s, seftp::ClientContext& cc, uint32_t original_crc=0, bool* crc_ok=nullptr);
void making_RSAkeys(tcp::socket& s, const seftp::ClientContext& cc, const std::string& key = std::string());
CliOptions parse_cli(int argc, char* argv[]);
void print_client_exit_summary();
static std::string trim_copy(const std::string& s);
static std::string normalize_user_path_input(const std::string& raw);
static std::string protocol_filename_from_path(const std::string& path);
std::array<uint8_t, seftp::proto::kStage7NonceLen> generate_nonce();
bool execute_server_identity_handshake(tcp::socket& s,seftp::ClientContext& cc);

vector<ClientEvent> client_history;
bool debug_mode = false;
constexpr const char* kTranserInfo = "transfer.info";
auto& g_logger = seftp::logger::Logger::getInstance();
CliOptions options;
int main(int argc, char* argv[]) {
	options = parse_cli(argc, argv);
	string ans;
	if (options.debug_set) {
		g_logger.setLevel(options.debug ? seftp::logger::logLevel::Debug
			: seftp::logger::logLevel::Info);
	}
	else {
		cout << "do you wish to see debug console promts? answer 'yes' or something else for no" << endl;
		getline(cin, ans);
		transform(ans.begin(), ans.end(), ans.begin(),
			[](unsigned char c) { return std::tolower(c); });;
		g_logger.setLevel(ans == "yes" ? seftp::logger::logLevel::Debug
			: seftp::logger::logLevel::Info);
	}

	// Read connection and username info from transfer.info
	// Expected: host, port, username
	seftp::ClientConfig client_config{};
	if (!load_tranfer_info(kTranserInfo, client_config)) {
		g_logger.error("there was a problem loading " + std::string(kTranserInfo) + " file");
		exit(1);
	}
	seftp::ClientContext cc{};
	cc.username = client_config.username;
	const int max_Length = 1042;
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	std::string aes_b64;
	string file_name;
	g_logger.debug("before file send operation");
	if (!options.files.empty()) {
		// headless: send provided files
		if (!seftp::flow::connect_and_handshake(io_context, s, resolver, client_config, cc, aes_b64)) {
			g_logger.error(cc.last_error_text);
			return 1;
		}
		for (options.file_index = 0; options.file_index < options.files.size(); ++options.file_index) {
			file_name = options.files[options.file_index];
			if (!seftp::flow::send_single_file(s, aes_b64, cc, file_name)) {
				g_logger.error(cc.last_error_text);
			}
			else {
				g_logger.info("transferred file " + std::to_string(options.file_index + 1) + "/" + std::to_string(options.files.size()));
			}
		}
		seftp::flow::disconnect_socket(s);
		print_client_exit_summary();
		return 0;
	}
	int rc = seftp::ui::run_console_ui(io_context, s, resolver, client_config, cc);
	print_client_exit_summary();
	return rc;

}

namespace seftp::flow{
	bool connect_and_handshake(boost::asio::io_context& io, tcp::socket& s, tcp::resolver& resolver, const seftp::ClientConfig& cfg, seftp::ClientContext& cc, std::string& out_aes_b64) {
		cc.last_error_text.clear();
		out_aes_b64.clear();
		try {
			// Establish TCP connection to the server
			boost::asio::connect(s, resolver.resolve(cfg.host, cfg.port));
		}
		catch (const boost::system::system_error& e) {
			cc.last_error_text = std::string("Failed to connect: ") + e.what();
			g_logger.error(cc.last_error_text);
			return false;
		}
		g_logger.info("\nconnection succeeded");
		if (!execute_server_identity_handshake(s,cc)) return false;

		std::string me_user, me_cid;
		std::string persist_error;
		seftp::persistence::StoredIdentity stored_identity{};
		if (!seftp::persistence::load_identity(stored_identity, persist_error)) {
			// No me.info -> first registration flow (825 + 826 + 1600 + 1602)
			g_logger.info("Identity not loaded, starting first sign on");

			//first sign on
			// 1) Send registration request with username (825)
			request_825(s, cc.username);
			// 2) Wait for 1600 and receive server-issued client_id from server
			auto r = answer_manager(s, cc);
			if (r.step == seftp::NextStep::Fatal) {
				g_logger.error(cc.last_error_text);
				return false;
			}
			// 3) Generate RSA-2048 key pair, send public key (826), receive AES key (1602)
			g_logger.debug("before entering making_RSAkeys ");
			try {
				making_RSAkeys(s, cc);
			}
			catch (const std::exception& e) {
				cc.last_error_text = e.what();
				g_logger.error(cc.last_error_text);
				return false;
			}
			r = answer_manager(s, cc);
			if (r.step == seftp::NextStep::Fatal) {
				g_logger.error(cc.last_error_text);
				return false;
			}
		}
		else {
			// me.info exists -> Single Sign-On flow (827 + 1605)
			g_logger.info("identity loaded, starting relogin flow");
			if (stored_identity.username != cc.username) {
				cc.last_error_text = "me.info username mismatch. transfer.info=" + cc.username + " me.info=" + stored_identity.username;
				g_logger.error("relogin failed: " + cc.last_error_text);
				return false;
			}
			cc.client_id = stored_identity.client_id;
			g_logger.info("this is name in me.info: " + cc.username);
			g_logger.info("this is uuid in me.info: " + cc.client_id);
			// 1) Send SSO / re-login request with existing client_id + username (827)
			request_827(s, cc.username, cc.client_id);
			// 2) Wait for 1605 (or 1606). client_id remains stable; only AES key is refreshed if needed
			auto r = answer_manager(s, cc);
			if (r.step == seftp::NextStep::NeedRegister) {
				// 825 -> 1600
				g_logger.debug("making a new user with request_825");
				request_825(s, cc.username);
				auto r2 = answer_manager(s, cc);
				if (r2.step == seftp::NextStep::Fatal) {
					g_logger.error("relogin failed: " + cc.last_error_text);
					return false;
				}
				// 826 -> 1602
				g_logger.info("the public key not good making a new one with RSA");
				try {
					making_RSAkeys(s, cc);
				}
				catch (const std::exception& e) {
					cc.last_error_text = e.what();
					g_logger.error(cc.last_error_text);
					return false;
				}
				auto r3 = answer_manager(s, cc);
				if (r3.step == seftp::NextStep::Fatal) {
					g_logger.error("relogin failed: " + cc.last_error_text);
					return false;
				}
			}
			else if (r.step == seftp::NextStep::NeedSendPublicKey) {
				g_logger.info("has new client id, need to send 826 to get a key");
				std::string keybin;
				std::string persist_error;
				if (!seftp::persistence::load_private_key(keybin, persist_error)) {
					cc.last_error_text =
						"local private key is missing or unreadable; manual identity reset required";
					g_logger.error(cc.last_error_text);
					return false;
				}

				try {
					making_RSAkeys(s, cc, keybin);
				}
				catch (const std::exception& e) {
					cc.last_error_text = e.what();
					g_logger.error(cc.last_error_text);
					return false;
				}
				auto r2 = answer_manager(s, cc);
				if (r2.step == seftp::NextStep::Fatal) {
					g_logger.error("relogin failed: " + cc.last_error_text);
					return false;
				}
			}
			else if (r.step == seftp::NextStep::Fatal) {
				g_logger.error("relogin failed: " + cc.last_error_text);
				return false;
			}

		}
		std::string key;
		// Load AES key from aes.key (Base64), which was written by answer_1602/1605
		if (!seftp::persistence::load_aes_key(key, persist_error)) {
			cc.last_error_text = persist_error;
			g_logger.error(cc.last_error_text);
			return false;
		}
		g_logger.info("Loaded AES key from file (Base64, len=" + std::to_string(key.size()) + " )");
		out_aes_b64 = std::move(key);
		return true;
	}
	void disconnect_socket(tcp::socket& s)
	{
		boost::system::error_code ec;
		if (s.is_open()) {
			s.shutdown(tcp::socket::shutdown_both, ec);
			s.close(ec);
		}
	}
	bool send_single_file(tcp::socket&s, const std::string& aes_key, ClientContext& cc, const std::string& path){
		cc.last_error_text.clear();
		const std::string normalized_path = normalize_user_path_input(path);
		if (normalized_path.empty()|| !std::filesystem::exists(normalized_path) || !std::filesystem::is_regular_file(normalized_path)) {
			cc.last_error_text = "file does not exist or is not a regular file: " + normalized_path;
			g_logger.error(cc.last_error_text);
			return false;
		}
		if (!s.is_open()) {
			cc.last_error_text = "not connected";
			g_logger.error(cc.last_error_text);
			return false;
		}
		if (aes_key.empty()) {
			cc.last_error_text = "missing AES key";
			g_logger.error(cc.last_error_text);
			return false;
		}
		try {
			request_828_retry(s, aes_key, cc, normalized_path);
		}
		catch(const std::exception& e){
			cc.last_error_text = e.what();
			g_logger.error(cc.last_error_text);
			return false;
		}
		// Read final response (e.g., 1604 � transfer finished)
		auto r = answer_manager(s, cc);
		if (r.step == NextStep::Fatal) {
			g_logger.error("send_single_file failed: " + cc.last_error_text);
			return false;
		}
		return true;
	}
}
/*
 * Generate a fresh Stage 7 client nonce.
 *
 * The nonce is sent in CLIENT_HELLO and later used as part of the
 * signed handshake transcript, preventing replay of old SERVER_HELLO
 * messages across connections.
 */
std::array<uint8_t, seftp::proto::kStage7NonceLen> generate_nonce() {
	std::array<uint8_t, seftp::proto::kStage7NonceLen> nonce{};
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(nonce.data(), nonce.size());
	return nonce;
}
bool validate_server_hello_payload(const seftp::proto::Res1608& hello, seftp::ClientContext& cc) {
	if (hello.security_version != seftp::proto::kSecurityVersion) {
		cc.last_error_text	= "unsupported security version";
		g_logger.error(cc.last_error_text);
		return false;
	}
	if (hello.server_public_key_der.empty()) {
		cc.last_error_text	= "public key is empty";
		g_logger.error(cc.last_error_text);
		return false;
	}
	if (hello.server_public_key_der.size() > 4096) {
		cc.last_error_text = "public key too large";
		g_logger.error(cc.last_error_text);
		return false;
	}
	if (hello.signature.empty()) {
		cc.last_error_text	= "signature is empty";
		g_logger.error(cc.last_error_text);
		return false;
	}
	if (hello.signature.size() !=256) {
		cc.last_error_text	= "signature size mismatch";
		g_logger.error(cc.last_error_text);
		return false;
	}
	return true;
}
bool validate_server_trust(seftp::ClientContext& cc, const std::string& fingerprint) {
	const std::string normalized_fingerprint = trim_copy(fingerprint);

	std::string pinned;
	std::string pin_error;

	if (seftp::persistence::load_server_pin(pinned, pin_error)) {
		pinned = trim_copy(pinned);

		if (pinned != fingerprint) {
			cc.last_error_text = "pinned server fingerprint mismatch";
			g_logger.error(cc.last_error_text);
			return false;
		}

		g_logger.info("pinned server fingerprint matched");
		return true;
	}

	g_logger.debug("no pinned server fingerprint configured; using TOFU");

	std::string stored;
	std::string fingerprint_error;

	if (seftp::persistence::load_server_fingerprint(stored, fingerprint_error)) {
		stored = trim_copy(stored);

		if (stored != fingerprint) {
			cc.last_error_text = "server fingerprint mismatch";
			g_logger.error(cc.last_error_text);
			return false;
		}
	} else {
		if (!seftp::persistence::save_server_fingerprint(fingerprint, fingerprint_error)) {
			cc.last_error_text = fingerprint_error;
			g_logger.error(cc.last_error_text);
			return false;
		}
		g_logger.warn("TOFU: stored new server fingerprint");
	}
	return true;
}
/*
 * Execute server-identity handshake.
 *
 * Flow:
 * - generate a fresh client nonce
 * - send 829 CLIENT_HELLO
 * - expect 1608 SERVER_HELLO
 * - parse the server identity payload
 * - send 830 CLIENT_HANDSHAKE_ACK
 *
 * At this stage, this function only wires the protocol flow.
 * Signature verification, TOFU, and pinned-key validation are added later.
 */
bool execute_server_identity_handshake(tcp::socket& s,seftp::ClientContext& cc) {
	std::array<uint8_t, seftp::proto::kStage7NonceLen> client_nonce = generate_nonce();
	request_829(s, client_nonce);
	try {
		auto frame = seftp::net::read_response_frame(s);
		std::stringstream ss;
		ss << "version: " << (int)frame.version << ", code: " << (uint16_t)frame.code << ", payload size: " << frame.payload.size();
		g_logger.debug(ss.str());
		seftp::proto::ByteView pv{ frame.payload.data(), frame.payload.size() };

		auto res_code = frame.code;
		if (res_code != seftp::proto::ResCode::ServerHello) {
			cc.last_error_text = "expected SERVER_HELLO (1608)";
			g_logger.error(cc.last_error_text);
			return false;
		}
		auto hello = seftp::proto::parse_1608(pv);
		if (!validate_server_hello_payload(hello,cc)) {
			return false;
		}

		auto fingerprint = seftp::crypto::sha256_hex(hello.server_public_key_der);
		g_logger.info("server identity fingerprint: " + fingerprint);

		if (!seftp::crypto::verify_server_hello_signature(hello.security_version, client_nonce, hello.server_nonce, hello.server_public_key_der, hello.signature)) {
			cc.last_error_text = "server identity signature verification failed";
			g_logger.error(cc.last_error_text);
			return false;
		}
		if (!validate_server_trust(cc, fingerprint)) return false;

		cc.security_version = hello.security_version;
		cc.client_nonce = client_nonce;
		cc.server_nonce = hello.server_nonce;
		cc.stage7_handshake_complete = true;
		cc.server_public_key_der = hello.server_public_key_der;
	}
	catch (const std::exception& e) {
		g_logger.error(std::string("server handshake failed: ") + e.what());
		return false;
	}
	g_logger.info("Client Handshake Ack");
	request_830(s);
	return true;
}
void print_client_exit_summary() {
	std::cout << "Thanks, Goodbye!!" << std::endl;
	std::cout << "\n\nclient history: [";
	for (const ClientEvent& event : client_history) {
		std::cout << "'" << event.method << "' " << event.time_stamp << "; ";
	}
	std::cout << "]" << std::endl;
}
static size_t padded_cbc_size(size_t plain_size) {
	const size_t block = CryptoPP::AES::BLOCKSIZE;
	const size_t padding = block - (plain_size % block);
	return plain_size + padding;
}

static size_t choose_upload_chunk_size(size_t cipher_size) {
	const size_t MAX_PACKETS = 65535;
	size_t chunk_min = (cipher_size + MAX_PACKETS - 1) / MAX_PACKETS;
	size_t chunk_size = std::max<size_t>(8192, chunk_min);
	chunk_size = ((chunk_size + 1023) / 1024) * 1024;
	return chunk_size;
}
CliOptions parse_cli(int argc, char* argv[]) {
	CliOptions cli;
	for (int i = 1; i < argc; ++i) {
		std::string a = argv[i];
		if (a == "--info") {
			cli.debug_set = true;
			cli.debug = false;
			continue;
		}
		if (a == "--debug") {
			cli.debug_set = true;
			cli.debug = true;
			continue;
		}
		if (a.rfind("--debug=", 0) == 0) {
			cli.debug_set = true;
			cli.debug = (a.substr(8) == "1" || a.substr(8) == "true");
			continue;
		}
		if (a.rfind("--files=", 0) == 0) {
			std::string list = a.substr(8);
			std::stringstream ss(list);
			std::string item;
			while (std::getline(ss, item, ',')) {
				if (!item.empty()) cli.files.push_back(item);
			}
			continue;
		}
		// backward-compat: treat bare args as files
		if (!a.empty() && a[0] != '-') cli.files.push_back(a);
	}
	return cli;
}
string timestamp() {
	using namespace std::chrono;

	auto now = system_clock::now();
	auto in_time_t = system_clock::to_time_t(now);
	auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

	std::tm buf;
#ifdef _WIN32
	localtime_s(&buf, &in_time_t);
#else
	localtime_r(&in_time_t, &buf);
#endif

	std::ostringstream oss;
	oss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S")
		<< ":" << std::setw(3) << std::setfill('0') << ms.count();

	return oss.str();
}
std::string to_hex(const std::string& data)
{
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');

	for (unsigned char c : data) {
		oss << std::setw(2) << static_cast<int>(c);
	}
	return oss.str();
}
void making_RSAkeys(tcp::socket& s, const seftp::ClientContext& cc, const std::string& key)
{
	// Generate a new RSA-2048 key pair or load an existing private key,
	// send the public key to the server (request 826), and wait for the AES key (1602/1605).
	// If 'key' is empty: generate new keys and save priv.key.
	// If 'key' is non-empty: load RSA private key from the given binary string.
	client_history.push_back({ "making_RSAkeys",timestamp() });
	g_logger.debug("inside making_RSAkeys");
	seftp::crypto::PublicKeyFormat key_pair;
	try {
		key_pair = seftp::crypto::generate_rsa2048_keypair_der(key);
	}
	catch (const std::exception& e) {
		throw std::runtime_error("failed to generate RSA keys: " + std::string(e.what()));
	}
	g_logger.debug("DER len: " + std::to_string(key_pair.publicKeyDer.size()));
	g_logger.debug("publicKeyB64 length: " + std::to_string(key_pair.publicKeyB64.size()));
	std::string persist_error;

	if (key.empty()) {
		if (std::filesystem::exists(seftp::util::files::kPrivKey)) {
			throw std::runtime_error(
				"refusing to overwrite existing priv.key; manual identity reset required"
			);
		}
		if (key_pair.privateKeyDer.empty()) {
			throw std::runtime_error("generated private key DER is empty");
		}
		if (!seftp::persistence::save_private_key(key_pair.privateKeyDer, persist_error)) {
			throw std::runtime_error(persist_error);
		}
	}

	if (!seftp::persistence::save_public_key(key_pair.publicKeyB64, persist_error)) {
		throw std::runtime_error(persist_error);
	}
	g_logger.info("Public key (B64) added to me.info: " + key_pair.publicKeyB64);
	g_logger.debug("sending 826, b64 len: " + std::to_string(key_pair.publicKeyB64.size()));
	request_826(s, cc.username, key_pair.publicKeyB64, cc.client_id);

	g_logger.info("RSA keys generated and saved to files");
}
bool load_tranfer_info(const std::string& path, seftp::ClientConfig& out) {
	// Read transfer.info and parse connection and username information.
	// Expected format (per line):
	//   host-port: 127.0.0.1:1234
	//   username:myname
	// Returns a object client config.
	std::string myText,line1,line2;
	std::ifstream MyReadFile(kTranserInfo);
	if (!MyReadFile.is_open()) return false;
	if (!std::getline(MyReadFile, line1)) return false;
	if (!std::getline(MyReadFile, line2)) return false;

	auto pos = line1.find(':');
	if (pos == std::string::npos) return false;

	out.host = line1.substr(0, pos);
	out.port = line1.substr(pos + 1);
	out.username = line2;
	return !out.host.empty() && !out.port.empty() && !out.username.empty();
}
static std::string trim_copy(const std::string& s) {
	auto begin = std::find_if_not(s.begin(), s.end(),
		[](unsigned char ch) { return std::isspace(ch); });

	auto end = std::find_if_not(s.rbegin(), s.rend(),
		[](unsigned char ch) { return std::isspace(ch); }).base();

	if (begin >= end) {
		return "";
	}

	return std::string(begin, end);
}
static std::string normalize_user_path_input(const std::string& row) {
	std::string s = trim_copy(row);
	if (s.size()>=2) {
		const char first = s.front();
		const char last = s.back();
		if ((first == '\'' && last == '\'') ||
		 (first == '"' && last == '"')) {
			s = s.substr(1, s.size() - 2);
			s = trim_copy(s);
		}
	}
	return s;
}

static std::string protocol_filename_from_path(const std::string& path) {
	return std::filesystem::path(path).filename().string();
}
void request_825(tcp::socket& s, const string& name) {
	// Build and send request 825: initial registration.
	// Payload: username + '\0'.
	// Response expected: 1600 (success) or 1601 (failure).
	try {
		client_history.push_back({ "request_825", timestamp() });
		g_logger.debug("in request_825");
		auto msg = seftp::proto::build_825_register(name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_825: " + std::string(e.what()));
	}
}
void request_826(tcp::socket& s, const string& name, const string& publicKeyStr, const string& uuid) {
	// Build and send request 826: send RSA public key in Base64.
	// Payload: username + '\0' + publicKeyB64.
	// Response expected: 1602 with encrypted AES key.
	try {
		client_history.push_back({ "request_826", timestamp() });
		g_logger.debug("in request_826");
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_826_public_key(cid, name, publicKeyStr);
		g_logger.info("publicKeyB64 length: " + std::to_string(publicKeyStr.size()));
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_826: " + std::string(e.what()));
	}
}
void request_827(tcp::socket& s, const string& name, const string& uuid) {
	// Build and send request 827: re-login (SSO) using existing client_id and username.
	// Payload: username + '\0'.
	// Response expected: 1605 (re-login success) or 1606 (re-register required).
	g_logger.debug("in request_827");
	client_history.push_back({ "request_827", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_827_relogin(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));;
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_827: " + std::string(e.what()));
	}

}
std::optional<uint32_t> request_828_streaming(tcp::socket& s, const string& name, const string& uuid, const string& encrypt_key, const std::string& file_name) {
	g_logger.debug("in request_828_streaming");
	client_history.push_back({ "request_828_streaming", timestamp() });
	try {
		const auto plain_size_u64 = std::filesystem::file_size(file_name);
		if (plain_size_u64 > std::numeric_limits<uint32_t>::max()) {
			throw std::runtime_error("file too large for current 828 protocol");
		}
		const size_t plain_size = static_cast<size_t>(plain_size_u64);
		const size_t cipher_size = padded_cbc_size(plain_size);
		if (cipher_size > std::numeric_limits<uint32_t>::max()) {
			throw std::runtime_error("ciphertext too large for current 828 protocol");
		}
		const size_t CHUNK_SIZE = choose_upload_chunk_size(cipher_size);
		const size_t total_packets = (cipher_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
		if (total_packets == 0 || total_packets > std::numeric_limits<uint16_t>::max()) {
			throw std::runtime_error("too many upload packets");
		}
		std::string protocol_file_name = protocol_filename_from_path(file_name);
		auto cid = seftp::util::parse_client_id_hex32(uuid);

		std::string raw_key = seftp::crypto::decode_base64(encrypt_key);
		if (raw_key.size() != CryptoPP::AES::MAX_KEYLENGTH) {
			throw std::runtime_error("AES key must be exactly 32 bytes");
		}
		auto iv_arr = seftp::crypto::make_iv();

		auto msg0 = seftp::proto::build_828_packet0_iv(cid, static_cast<uint32_t>(cipher_size),
			static_cast<uint32_t>(plain_size),
			static_cast<uint16_t>(total_packets),
			protocol_file_name,
			iv_arr
		);

		boost::asio::write(s, boost::asio::buffer(msg0));

		CryptoPP::SecByteBlock aes_key(
			reinterpret_cast<const CryptoPP::byte*>(raw_key.data()),
			CryptoPP::AES::MAX_KEYLENGTH
		);

		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
		std::memcpy(iv, iv_arr.data(), CryptoPP::AES::BLOCKSIZE);

		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		encryptor.SetKeyWithIV(aes_key, aes_key.size(), iv);

		CryptoPP::CRC32 crc;
		std::ifstream file(file_name, std::ios::binary);
		if (!file.is_open()) {
			throw std::runtime_error("failed to open file: " + file_name);
		}

		size_t packet_num = 1;
		size_t sent_cipher_bytes = 0;
		std::string pending_cipher_packet;

		auto send_packet = [&](const std::string& packet_data) {
			if (packet_data.empty()) {
				throw std::runtime_error("attempted to send empty upload packet");
			}

			if (packet_num > total_packets) {
				throw std::runtime_error("attempted to send too many upload packets");
			}

			std::vector<uint8_t> chunk(packet_data.begin(), packet_data.end());

			auto msgN = seftp::proto::build_828_packet_chunk(
				cid,
				static_cast<uint32_t>(cipher_size),
				static_cast<uint32_t>(plain_size),
				static_cast<uint16_t>(packet_num),
				static_cast<uint16_t>(total_packets),
				protocol_file_name,
				chunk
			);

			boost::asio::write(s, boost::asio::buffer(msgN));

			sent_cipher_bytes += packet_data.size();
			packet_num++;
		};

		auto append_cipher_bytes = [&](const std::string& data) {
			pending_cipher_packet.append(data);

			while (pending_cipher_packet.size() >= CHUNK_SIZE) {
				std::string packet_data = pending_cipher_packet.substr(0, CHUNK_SIZE);
				pending_cipher_packet.erase(0, CHUNK_SIZE);
				send_packet(packet_data);
			}
		};

		std::vector<char> plain_buf(64 * 1024);
		std::string pending_plain;

		while (file) {
			file.read(plain_buf.data(), static_cast<std::streamsize>(plain_buf.size()));
			const std::streamsize got = file.gcount();

			if (got <= 0) {
				break;
			}

			crc.Update(
				reinterpret_cast<const CryptoPP::byte*>(plain_buf.data()),
				static_cast<size_t>(got)
			);

			pending_plain.append(plain_buf.data(), static_cast<size_t>(got));

			const size_t full_block_len =
				(pending_plain.size() / CryptoPP::AES::BLOCKSIZE) * CryptoPP::AES::BLOCKSIZE;

			if (full_block_len > 0) {
				std::string encrypted(full_block_len, '\0');

				encryptor.ProcessData(
					reinterpret_cast<CryptoPP::byte*>(encrypted.data()),
					reinterpret_cast<const CryptoPP::byte*>(pending_plain.data()),
					full_block_len
				);

				append_cipher_bytes(encrypted);
				pending_plain.erase(0, full_block_len);
			}
		}

		const size_t padding_len =
			CryptoPP::AES::BLOCKSIZE - (pending_plain.size() % CryptoPP::AES::BLOCKSIZE);

		pending_plain.append(padding_len, static_cast<char>(padding_len));

		if (pending_plain.size() % CryptoPP::AES::BLOCKSIZE != 0) {
			throw std::runtime_error("internal error: final padded plaintext is not block aligned");
		}

		std::string encrypted_final(pending_plain.size(), '\0');

		encryptor.ProcessData(
			reinterpret_cast<CryptoPP::byte*>(encrypted_final.data()),
			reinterpret_cast<const CryptoPP::byte*>(pending_plain.data()),
			pending_plain.size()
		);

		append_cipher_bytes(encrypted_final);

		if (!pending_cipher_packet.empty()) {
			send_packet(pending_cipher_packet);
			pending_cipher_packet.clear();
		}

		if (sent_cipher_bytes != cipher_size) {
			throw std::runtime_error("streaming upload sent unexpected ciphertext size");
		}

		if (packet_num != total_packets + 1) {
			throw std::runtime_error("streaming upload sent unexpected packet count");
		}

		uint32_t crc_val = 0;
		crc.Final(reinterpret_cast<CryptoPP::byte*>(&crc_val));

		g_logger.info(
			"streaming upload complete cipher_size=" + std::to_string(cipher_size) +
			" plain_size=" + std::to_string(plain_size) +
			" total_packets=" + std::to_string(total_packets)
		);

		return crc_val;
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_828_streaming: " + std::string(e.what()));
		return std::nullopt;
	}
}
void request_828_retry(tcp::socket& s, string encrypt_key, seftp::ClientContext& cc, const std::string& file_name) {
	// Wrapper for request_828 with retry logic based on CRC check (1603).
	// If CRC mismatch:
	//   - up to 3 retries: send 901 and resend file.
	//   - on 4th failure: send 902 (give up).
	// If CRC matches: send 900 (success).
	g_logger.debug("in request_828_retry");
	client_history.push_back({ "request_828_retry", timestamp() });
	int retries = 0;
	const int MAX_RETRIES = 4;
	bool crc_ok_init = false;
	bool* crc_ok = &crc_ok_init;
	const std::string protocol_file_name = protocol_filename_from_path(file_name);
	while (retries < MAX_RETRIES && !*crc_ok) {
		// 1) Send encrypted file (828) and get original CRC of plaintext
		auto original_crc_file = request_828_streaming(s, cc.username, cc.client_id, encrypt_key, file_name);
		if (!original_crc_file.has_value()) {
			cc.last_error_text = "upload send failed before receiving server CRC";
			g_logger.error(cc.last_error_text);
			return;
		}
		// 2) Wait for 1603 from server (CRC verification) and update crc_ok
		auto r = answer_manager(s, cc, *original_crc_file, crc_ok);
		if (r.step == seftp::NextStep::Fatal) {
			g_logger.error("upload aborted after server/protocol error: " + cc.last_error_text);
			return;
		}
		if (!*crc_ok) {
			// CRC mismatch -> retry or give up
			retries++;
			if (retries < MAX_RETRIES) {
				g_logger.info("CRC mismatch, retry " + std::to_string(retries) + "/" + std::to_string(MAX_RETRIES));
				// Notify server: CRC invalid but we will resend (901)
				request_901(s, protocol_file_name,cc.client_id);
			}
			else {
				// 4th failure -> give up (902)
				g_logger.info("CRC mismatch after 4 retries, sending 902");
				request_902(s, protocol_file_name, cc.client_id);
			}
		}
		else {
			// CRC OK -> confirm success (900)
			request_900(s, protocol_file_name, cc.client_id);
		}
	}

}
void request_829(tcp::socket& s, std::array<uint8_t, seftp::proto::kStage7NonceLen>& client_nonce) {
	g_logger.debug("in request_829");
	try {
		auto msg = seftp::proto::build_829_client_hello(client_nonce);
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_829: " + std::string(e.what()));
	}
}
void request_830(tcp::socket& s) {
	g_logger.debug("in request_830");
	try {
		auto msg = seftp::proto::build_830_client_handshake_ack();
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_830: " + std::string(e.what()));
	}
}
void request_900(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 900: notify server that CRC matched for the given file name.
	g_logger.debug("in request_900");
	client_history.push_back({ "request_900", timestamp() });
	g_logger.info("we got a match with the crc value, sending confirmation to the server");
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_900_crc_ok(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_900: " + std::string(e.what()));
	}

}
void request_901(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 901: notify server that CRC mismatched (client will retry sending file).
	g_logger.debug("in request_901");
	client_history.push_back({ "request_901", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_901_crc_retry(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_901: " + std::string(e.what()));
	}

}
void request_902(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 902: notify server that CRC mismatched after max retries (give up).
	g_logger.debug("in request_902");
	client_history.push_back({ "request_902", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_902_crc_fail(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		g_logger.error("Error in request_902: " + std::string(e.what()));
	}

}
std::vector<uint8_t> parse_uuid(const std::string& uuid_str) {
	if (uuid_str.length() != 32)
		throw std::invalid_argument("UUID string must be exactly 32 hex characters (no dashes)");

	std::vector<uint8_t> uuid_bytes;
	uuid_bytes.reserve(16); // 32 hex chars -> 16 bytes

	for (size_t i = 0; i < uuid_str.length(); i += 2) {
		std::string byte_str = uuid_str.substr(i, 2);

		// validate hex
		if (!std::isxdigit(byte_str[0]) || !std::isxdigit(byte_str[1]))
			throw std::invalid_argument("UUID contains invalid hex characters");

		uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
		uuid_bytes.push_back(byte);
	}

	return uuid_bytes;
}

string answer_1600(vector<uint8_t>& payload, string name) {
	// Handle response 1600: registration succeeded.
	// Payload: 16-byte client_id.
	// Writes name and client_id hex into me.info.
	g_logger.debug("in answer_1600");
	client_history.push_back({ "answer_1600" ,timestamp()});
	std::ostringstream oss;
	for (uint8_t byte : payload) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
	}
	string client_id_hex = oss.str();
	//write to me.info
	std::string persist_error;
	seftp::persistence::StoredIdentity identity{};
	identity.username = name;
	identity.client_id = client_id_hex;

	if (!seftp::persistence::save_identity(identity, persist_error)) {
		g_logger.error(persist_error);
		return "";
	}

	g_logger.info("register for the client id: " + client_id_hex + " succeed");
	return client_id_hex;
}

static std::string handle_1600(const seftp::proto::Res1600& r, const std::string& username)
{
	// reuse existing behavior exactly
	auto payload16 = seftp::util::client_id_to_vec(r.client_id);
	return answer_1600(payload16, username);
}
void answer_1601() {
	// Handle response 1601: registration failed (username already exists or other error).
	// Exits the client.
	g_logger.debug("in answer_1601");
	client_history.push_back({ "answer_1601" ,timestamp()});
	g_logger.warn("register failed");
}
std::string answer_1602(const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1602: AES key encrypted with RSA public key for this client.
	// Decrypts AES key using priv.key and stores it as Base64 in aes.key.
	g_logger.debug("in answer_1602");
	client_history.push_back({ "answer_1602" ,timestamp() });
	g_logger.info("client " + client_id + " received encrypted AES key");
	std::string decrypted;
	try {
		decrypted = seftp::crypto::rsa_oaep_sha1_decrypt_from_file(privkey_filename, ciphertext);
		g_logger.debug("Decrypted AES key len=" + std::to_string(decrypted.size()));
	}
	catch (const std::exception& e) {
		throw std::runtime_error(
			"failed to decrypt AES key with local private key; manual identity reset required: " +
			std::string(e.what())
		);
	}

	std::string aes_key_b64 = seftp::crypto::encode_base64(decrypted);
	std::string persist_error;
	if (!seftp::persistence::save_aes_key(aes_key_b64, persist_error)) {
		g_logger.error(persist_error);
	}
	else {
		g_logger.info("AES key saved to aes.key (Base64, len=" + std::to_string(aes_key_b64.size()) + ") <only for demonstrating>: " + aes_key_b64);
	}

	return aes_key_b64;
}
string answer_1605(const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1605: re-login approved.
	// Same format as 1602 (delegates to answer_1602).
	client_history.push_back({ "answer_1605" ,timestamp() });
	g_logger.debug("in answer_1605 the next will be answer_1602 (SAME FUNCTION)");
	g_logger.info("request to re-register approved, gets aes encrypted key");
	return answer_1602(client_id, ciphertext, privkey_filename);
}

static seftp::DispatchResult handle_1606(const std::vector<uint8_t>& payload, seftp::ClientContext& cc) {
	// Handle response 1606: server indicates that re-login failed or public key is invalid.
	// If client_id is all zeros -> client must register again (825 + 826).
	// Otherwise -> generate new RSA keys and send again.
	g_logger.debug("in handle_1606");
	client_history.push_back({ "handle_1606" ,timestamp() });
	seftp::DispatchResult out{};
	if (payload.size() < seftp::proto::kClientIdLen) {
		cc.last_error_text = "1606 payload too short";
		out.step = seftp::NextStep::Fatal;
		return out;
	}
	seftp::proto::ClientId cid{};
	std::memcpy(cid.data(), payload.data(), seftp::proto::kClientIdLen);
	std::string client_id_hex = seftp::util::client_id_to_hex(cid);
	if (client_id_hex == std::string(32, '0')) {
		cc.need_register = true;
		out.step = seftp::NextStep::NeedRegister;
		g_logger.info("request to re-register disapproved, the client id is: " + client_id_hex + ". is not register");
		g_logger.info("need to sign up, making a new client id");
		return out;
	}
	cc.client_id = client_id_hex;
	cc.send_public_key = true;
	out.step = seftp::NextStep::NeedSendPublicKey;
	out.updated_client_id = true;
	return out;
}
static std::string handle_1602_or_1605(seftp::proto::ResCode code, const seftp::proto::Res1602& r, const seftp::ClientContext& cc) {
	std::string client_id_hex = seftp::util::client_id_to_hex(r.client_id);
	if (!cc.stage7_handshake_complete) {
		throw std::runtime_error("AES key response received before completed Stage 7 handshake");
	}

	if (cc.server_public_key_der.empty()) {
		throw std::runtime_error("missing server public key for AES key binding verification");
	}
	if (!seftp::crypto::verify_aes_key_binding_signature(
			cc.security_version,
			cc.client_nonce,
			cc.server_nonce,
			r.client_id,
			code,
			r.encrypted_key,
			cc.server_public_key_der,
			r.signature)) {
		throw std::runtime_error("invalid AES key binding signature");
			}
	g_logger.info("AES key binding signature verified");
	if (code == seftp::proto::ResCode::AesKey)
	{
		try {
			answer_1602(client_id_hex, r.encrypted_key, "priv.key");
		}
		catch (const std::exception& e) {
			throw;
		}
		g_logger.debug("after 1602");
	}
	else { // 1605
		cout << answer_1605(client_id_hex, r.encrypted_key, "priv.key") << endl;
		g_logger.debug("after 1605");
	}

	g_logger.debug("uuid in answer manager after 1602/1605: [" + client_id_hex + "]");
	return client_id_hex;
}
bool answer_1603(tcp::socket& s, vector<uint8_t>payload, uint32_t original_crc) {
	// Handle response 1603: server sends its computed CRC for the received file.
	// Compares server CRC to original_crc and returns true on match.
	// Used by request_828_retry() to decide whether to retry or send 900/902.
	g_logger.debug("after 1603");
	client_history.push_back({ "answer_1603" ,timestamp() });
	size_t offset = 0;
	// Extract 16-byte client_id (not used here, but part of the protocol)
	std::vector<uint8_t> client_id(payload.begin(), payload.begin() + 16);
	offset += 16;
	// Next 4 bytes: content_size (total ciphertext size, mainly informational)
	uint32_t content_size = static_cast<uint32_t>(payload[offset]) |
		(static_cast<uint32_t>(payload[offset + 1])<<8)|
		(static_cast<uint32_t>(payload[offset + 2]) << 16)|
		(static_cast<uint32_t>(payload[offset + 3]) << 24);
	offset += 4;
	// Filename length = total payload size minus 4 bytes of CRC and bytes already consumed
	size_t filename_len = payload.size() - 4 - offset;
	// Extract filename as string
	string filename(payload.begin() + offset, payload.begin() + filename_len + offset);
	offset += filename_len;
	// Last 4 bytes: server CRC
	uint32_t server_crc =
		static_cast<uint32_t>(payload[offset]) |
		(static_cast<uint32_t>(payload[offset+1]) << 8) |
		(static_cast<uint32_t>(payload[offset+2]) << 16) |
		(static_cast<uint32_t>(payload[offset+3]) << 24);


	g_logger.info("Server CRC: " + std::to_string(server_crc) + ", original CRC: " + std::to_string(original_crc));

	if (server_crc == original_crc) {
		g_logger.info("Checksum verified successfully!");
		return true;
	}
	else {
		g_logger.warn("Checksum mismatch!");
		return false;
	}
}
static void handle_1603(const seftp::proto::Res1603& r, uint32_t original_crc, bool* crc_ok)
{
	if (!crc_ok) return;

	g_logger.info("Server CRC: " + std::to_string(r.server_crc) + ", original CRC: " + std::to_string(original_crc));

	if (r.server_crc == original_crc) {
		g_logger.info("Checksum verified successfully!");
		*crc_ok = true;
	}
	else {
		g_logger.warn("Checksum mismatch!");
		*crc_ok = false;
	}
}
void answer_1604() {
	client_history.push_back({ "answer_1604" ,timestamp() });
	g_logger.debug("in answer_1604");
	g_logger.info("finish transfering");
}
void answer_1607(string& text) {
	client_history.push_back({ "answer_1607" ,timestamp() });
	g_logger.debug("in answer_1607");
	g_logger.warn("server error: " + text);
}
seftp::DispatchResult answer_manager(tcp::socket& s, seftp::ClientContext& cc, uint32_t original_crc, bool* crc_ok) {
	// Read a single response frame from the server and dispatch to the correct handler.
	// The function may:
	//   - write me.info (on registration success)
	//   - decrypt and store AES key (1602/1605)
	//   - update crc_ok flag based on 1603
	//   - print status / errors for 1604/1607
	// Returns:
	//   - client_id as a hex string when relevant (1600/1602/1605/1606)
	//   - empty string otherwise.
	g_logger.debug("in answer_manager");
	client_history.push_back({ "answer_manager" ,timestamp() });
	const int max_Length = 1024;
	char request[max_Length];

	auto frame = seftp::net::read_response_frame(s);

	std::stringstream ss;
	ss << "version: " << (int)frame.version << ", code: " << (uint16_t)frame.code << ", payload size: " << frame.payload.size();
	g_logger.debug(ss.str());
	seftp::proto::ByteView pv{ frame.payload.data(), frame.payload.size() };

	auto res_code = frame.code;
	switch (res_code) {
	case  seftp::proto::ResCode::RegisterOk: {
		auto r1600 = seftp::proto::parse_1600(pv);
		cc.client_id = handle_1600(r1600, cc.username);
		return {};
	}
	case seftp::proto::ResCode::RegisterFail: {
		cc.last_error_text = "1601 register failed";
		answer_1601();
		return { seftp::NextStep::Fatal,false };
	}
		case seftp::proto::ResCode::AesKey:
		case seftp::proto::ResCode::ReloginOk: {
		try {
			auto r1602_1605 = seftp::proto::parse_1602(pv);
			cc.client_id = handle_1602_or_1605(frame.code, r1602_1605, cc);
			return {};
		}
		catch (const std::exception& e) {
			cc.last_error_text = e.what();
			g_logger.error(cc.last_error_text);
			return { seftp::NextStep::Fatal, false };
			}
		}
	case seftp::proto::ResCode::ReloginFail: {
		return handle_1606(frame.payload, cc);
	}
	case seftp::proto::ResCode::CrcResult: {
		auto r1603 = seftp::proto::parse_1603(pv);
		handle_1603(r1603, original_crc, crc_ok);
		return {};
	}
	case seftp::proto::ResCode::TransferDone: {
		answer_1604();
		return {};
	}
	case seftp::proto::ResCode::Error: {
		seftp::DispatchResult out{};
		out.step = seftp::NextStep::Fatal;
		if (frame.payload.size() < seftp::proto::kClientIdLen) {
			g_logger.warn("payload for 1607 too short");
			cc.last_error_text = "payload for 1607 too short";
			return out;
		}
		seftp::proto::ClientId cid{};
		std::memcpy(cid.data(), frame.payload.data(), seftp::proto::kClientIdLen);
		std::string client_id_hex = seftp::util::client_id_to_hex(cid);
		std::vector<uint8_t> c_text(frame.payload.begin() + seftp::proto::kClientIdLen, frame.payload.end());
		std::string text(c_text.begin(), c_text.end());
		auto pos = text.find('\0');
		if (pos != std::string::npos) text.resize(pos);
		cc.last_error_text = text.empty() ? "1607 error (empty text)" : text;
		answer_1607(cc.last_error_text);
		g_logger.debug("this is the uuid in answer manager after 1607: [" + client_id_hex + "]");
		return { seftp::NextStep::Fatal };
	}
	default:
		g_logger.warn("the code: " + std::to_string(static_cast<uint16_t>(frame.code)) + " is not a valid code for a response");
		cc.last_error_text = "Unknown response code: " + std::to_string((uint16_t)frame.code);
		return { seftp::NextStep::Fatal,false };

	}
}
