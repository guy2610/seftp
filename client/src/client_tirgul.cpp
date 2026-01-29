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
#include <cryptlib.h>
#include <rsa.h>
#include <osrng.h>          // AutoSeededRandomPool
#include <files.h>          // FileSink, FileSource
#include <hex.h>
#include <sha.h>
#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h>
#include <iomanip>
#include <sstream>
#include <base64.h>   // CryptoPP::Base64Encoder
#include <crc.h> // For CRC32
#include <files.h> // For FileSource
#include <filters.h> // For HashFilter, HexEncoder, StringSink
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <random>
#include "protocol/protocol.hpp"
#include "net/net.hpp"
#include "util/util.hpp"
#include "crypto/crypto.hpp"
#include "util/files.hpp"
#include "logger/logger.hpp"

using namespace std;
using namespace CryptoPP;
using  boost::asio::ip::tcp;
struct ClientContext {
	std::string client_id;
	std::string username;
	std::string aes_key_b64;
	bool logged_in_or_has_aes = false;
	bool need_register = false;
	bool send_public_key = false;
	std::string last_error_text;
};
struct ClientConfig
{
	std::string host;
	std::string port;
	std::string username;

};
struct ClientEvent {
	string method;
	string time_stamp;
};

enum class NextStep { None, NeedRegister, NeedSendPublicKey, Fatal };
struct DispatchResult
{
	NextStep step = NextStep::None;
	bool updated_client_id = false;
};

bool load_tranfer_info(const std::string& path, ClientConfig& out);
string timestamp();
void request_825(tcp::socket& s, const string& name);
void request_826(tcp::socket& s, const string& name, const string& publicKeyStr, const string& uuid);
void request_827(tcp::socket& s, const string& name, const string & uuid);
uint32_t request_828(tcp::socket& s, const string& name, const string& uuid, vector<string>& components);
void request_828_retry(tcp::socket& s, string encrypt_key, ClientContext& cc);
void request_900(tcp::socket& s, const string& name, const string& uuid);
void request_901(tcp::socket& s, const string& name, const string& uuid);
void request_902(tcp::socket& s, const string& name, const string& uuid);
std::vector<std::string> splitStringBySize(const std::string& str, size_t chunkSize);
std::vector<string> encrypt_file(string key);
std::vector<uint8_t> parse_uuid(const std::string& uuid_str);
std::string to_hex(const std::string& data);
DispatchResult answer_manager(tcp::socket& s, ClientContext& cc, uint32_t original_crc=0, bool* crc_ok=nullptr);
void making_RSAkeys(tcp::socket& s, const ClientContext& cc, const std::string& key = std::string());

vector<ClientEvent> client_history;
bool debug_mode = false;
string file_name;
constexpr const char* kTranserInfo = "transfer.info";
auto& logger = seftp::logger::Logger::getInstance();
int main() {
	cout << "do you wish to see debug console promts? answer 'yes' or something else for no" << endl;
	string ans;
	getline(cin, ans);
	transform(ans.begin(), ans.end(), ans.begin(),
		[](unsigned char c) { return std::tolower(c); });;
	/*if (ans == "yes") debug_mode = true;*/
	if (ans == "yes") {
		logger.setLevel(seftp::logger::logLevel::Debug);
	}
	else { logger.setLevel(seftp::logger::logLevel::Info); }


	// Read connection and username info from transfer.info
	// Expected: host, port, username
	ClientConfig client_config{};
	if (!load_tranfer_info(kTranserInfo, client_config)) {
		/*std::cout << "there was a problem loading " << kTranserInfo << " file" << endl;*/
		logger.error("there was a problem loading " + std::string(kTranserInfo)+ " file");
		exit(1);
	}
	ClientContext cc{};
	cc.username = client_config.username;
	const int max_Length = 1042;
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	try {
		// Establish TCP connection to the server
		boost::asio::connect(s, resolver.resolve(client_config.host, client_config.port));
	}
	catch (const boost::system::system_error& e) {
		/*std::cerr << "Failed to connect: " << e.what() << std::endl;*/
		logger.error("Failed to connect: " + std::string(e.what()));
		return 1;
	}
	logger.info("\nconnection succeeded");
	/*cout << "\nconnection succeeded" << endl;*/
	char request[max_Length];
	vector<uint8_t>message;
	string key;
	std::string me_user, me_cid;
	if (!seftp::util::files::read_me_info(me_user, me_cid)) {
		// No me.info -> first registration flow (825 + 826 + 1600 + 1602)
		/*cout << "Failed to open me.info" << std::endl;
		cout << "Doing First sign on" << std::endl;*/
		logger.info("Failed to open me.info");
		logger.info("Doing First sign on");
		//first sign on
		const int max_Length = 1042;
		char request[max_Length];
		//head of request
		// 1) Send registration request with username (825)
		request_825(s, cc.username);
		// 2) Wait for 1600 and receive server-issued client_id from server
		auto r = answer_manager(s, cc);
		if (r.step == NextStep::Fatal) {
			/*std::cerr << "Fatal: " << cc.last_error_text << "\n";*/
			logger.error("Fatal: " + cc.last_error_text);
			return 1;
		}
		/*if (debug_mode)std::cout << "uuid after answer_manager: [" << cc.client_id << "]" << std::endl;*/
		logger.debug("uuid after answer_manager: [" + cc.client_id + "]");
		// 3) Generate RSA-2048 key pair, send public key (826), receive AES key (1602)
		logger.debug("before entering making_RSAkeys ");
		/*if (debug_mode)std::cout << "before entering making_RSAkeys " << std::endl;*/
		making_RSAkeys(s, cc);
		r = answer_manager(s, cc);
		if (r.step == NextStep::Fatal) {
			logger.error("Fatal: " + cc.last_error_text);
			/*std::cerr << "Fatal: " << cc.last_error_text << "\n";*/
			return 1;
		}
		logger.debug("uuid after answer_manager: [" + cc.client_id + "]");
		/*if (debug_mode)std::cout << "uuid after answer_manager: [" << cc.client_id << "]" << std::endl;*/
	}
	else {
		// me.info exists -> Single Sign-On flow (827 + 1605)
		logger.info("file me.info exist, handle SSO");
		/*std::cout << "file me.info exist, handle SSO" << endl;*/
		if (me_user != cc.username) {
			cc.last_error_text = "me.info username mismatch. transfer.info=" + cc.username + " me.info=" + me_user;
			logger.error("Fatal: " + cc.last_error_text);
			/*std::cerr << "Fatal: " << cc.last_error_text << "\n";*/
			return 1;
		}
		cc.client_id = me_cid;
		logger.info("this is name in me.info: " + cc.username);
		logger.info("this is uuid in me.info: " + cc.client_id);
		/*std::cout << "this is name in me.info: " << cc.username << endl;
		std::cout << "this is uuid in me.info: " << cc.client_id << endl;*/
		// 1) Send SSO / re-login request with existing client_id + username (827)
		request_827(s, cc.username, cc.client_id);
		/*if (debug_mode)std::cout << "uuid after answer_manager: [" << cc.client_id << "]" << std::endl;*/
		logger.debug("uuid after answer_manager: [" + cc.client_id + "]");
		// 2) Wait for 1605 (or 1606). client_id remains stable; only AES key is refreshed if needed
		auto r = answer_manager(s, cc);
		/*if (debug_mode)std::cout << "uuid after answer_manager: [" << cc.client_id << "]" << std::endl;*/
		logger.debug("uuid after answer_manager: [" + cc.client_id + "]");
		if (r.step == NextStep::NeedRegister) {
			// 825 -> 1600
			/*if (debug_mode) cout << "making a new user with request_825" << endl;*/
			logger.debug("making a new user with request_825");
			request_825(s, cc.username);
			auto r2 = answer_manager(s, cc);
			if (r2.step == NextStep::Fatal) {
				std::cerr << "Fatal: " << cc.last_error_text << "\n";
				return 1;
			}
			// 826 -> 1602
			/*cout << "the public key not good making a new one with RSA" << endl;*/
			logger.info("the public key not good making a new one with RSA");
			making_RSAkeys(s, cc);
			auto r3 = answer_manager(s, cc);
			if (r3.step == NextStep::Fatal) {
				/*std::cerr << "Fatal: " << cc.last_error_text << "\n";*/
				logger.error("Fatal: " + cc.last_error_text);
				return 1;
			}
		}
		else if (r.step == NextStep::NeedSendPublicKey) {
			logger.info("has new client id, need to send 826 to get a key");
			/*cout << "has new client id, need to send 826 to get a key" << endl;*/
			std::string keybin;
			/*if (seftp::util::files::read_private_key(keybin)) std::cout << "private key has been assigned" << std::endl;*/
			if (seftp::util::files::read_private_key(keybin)) logger.info("private key has been assigned");
			making_RSAkeys(s,cc, keybin);
			auto r2 = answer_manager(s, cc);
			if (r2.step == NextStep::Fatal) {
				logger.error("Fatal: " + cc.last_error_text);
				/*std::cerr << "Fatal: " << cc.last_error_text << "\n";*/
				return 1;
			}
		}
		else if (r.step == NextStep::Fatal) {
			logger.error("fatal during relogin: " + cc.last_error_text);
			/*std::cerr << "fatal during relogin: " << cc.last_error_text << "\n";*/
			return 1;
		}
		
	}
	// Load AES key from aes.key (Base64), which was written by answer_1602/1605
	if (!seftp::util::files::read_aes_key(key))//key in Base64
	{
		logger.error("cant open aes.key");
		/*std::cerr << "cant open aes.key\n";*/
		exit(1);
	}
	logger.info("Loaded AES key from file (Base64, len=" + std::to_string(key.size()) + " )");
	/*std::cout << "Loaded AES key from file (Base64, len=" << key.size() << ")" << std::endl;*/
	logger.debug("this is the uuid " + cc.client_id);
	logger.debug("before file send operation");
	/*if (debug_mode)cout << "this is the uuid " << cc.client_id << endl;
	if (debug_mode)cout << "before file send operation" << endl;*/
	// Main loop: encrypt and send files to the server, one by one
	while (true) {
		// Sends file (828 + retry with 900/901/902 based on CRC)
		request_828_retry(s, key, cc);
		// Read final response (e.g., 1604 – transfer finished)
		auto r = answer_manager(s, cc);
		logger.debug("uuid after answer_manager: [" + cc.client_id + "]");
		/*if (debug_mode)std::cout << "uuid after answer_manager: [" << cc.client_id << "]" << std::endl;*/
		// Ask user if they want to send another file
		logger.info("\nDo you want to send another file to the server? answer 'yes' or something else for no");
		/*cout << "\nDo you want to send another file to the server? answer 'yes' or something else for no" << endl;*/
		getline(cin, ans);
		transform(ans.begin(), ans.end(), ans.begin(),
			[](unsigned char c) { return std::tolower(c); });
		if (ans != "yes") break;
	}
	cout << "Thanks, Goodbye!!" << endl;
	// Print client event history for debugging
	cout << "\n\nclient history: [";
	for (const ClientEvent event : client_history) {
		cout << "'" << event.method << "' "<<event.time_stamp<<"; ";
	}
	cout << "]" << endl;

	return 0;
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
	localtime_r(&buf, &in_time_t);
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
void making_RSAkeys(tcp::socket& s, const ClientContext& cc, const std::string& key)
{
	// Generate a new RSA-2048 key pair or load an existing private key,
	// send the public key to the server (request 826), and wait for the AES key (1602/1605).
	// If 'key' is empty: generate new keys and save priv.key.
	// If 'key' is non-empty: load RSA private key from the given binary string.
	client_history.push_back({ "making_RSAkeys",timestamp() });
	logger.debug("inside making_RSAkeys");
	/*if (debug_mode)cout << "inside making_RSAkeys" << endl;*/
	seftp::crypto::PublicKeyFormat key_pair = seftp::crypto::generate_rsa2048_keypair_der(key);
	logger.debug("DER len: " + std::to_string(key_pair.publicKeyDer.size()));
	logger.debug("publicKeyB64 length: " + std::to_string(key_pair.publicKeyB64.size()));
	/*if (debug_mode)std::cout << "DER len: " << key_pair.publicKeyDer.size() << std::endl;
	if (debug_mode) std::cout << "publicKeyB64 length: " << key_pair.publicKeyB64.size() << std::endl;*/
	// approx 392 chars
	if (!seftp::util::files::write_me_public_key(key_pair.publicKeyB64))
	{
		logger.error("Failed to add to me.info public key");
		/*cerr << "Failed to add to me.info public key" << endl;*/
		exit(1);
	}
	logger.info("Public key (B64) added to me.info: " + key_pair.publicKeyB64);
	logger.debug("sending 826, b64 len: " + std::to_string(key_pair.publicKeyB64.size()));
	/*cout << "Public key (B64) added to me.info: " << key_pair.publicKeyB64 << endl;
	if(debug_mode)cout << "sending 826, b64 len: " << key_pair.publicKeyB64.size() << endl;*/
	request_826(s, cc.username, key_pair.publicKeyB64, cc.client_id);

	/*std::cout << "RSA keys generated and saved to files.\n";*/
	logger.info("RSA keys generated and saved to files");
}
bool load_tranfer_info(const std::string& path, ClientConfig& out) {
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

void request_825(tcp::socket& s, const string& name) {
	// Build and send request 825: initial registration.
	// Payload: username + '\0'.
	// Response expected: 1600 (success) or 1601 (failure).
	try {
		client_history.push_back({ "request_825", timestamp() });
		logger.debug("in request_825");
		/*if (debug_mode)cout << "in request_825" << endl;*/
		auto msg = seftp::proto::build_825_register(name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		logger.error("Error in request_825: " + std::string(e.what()));
		/*std::cerr << "Error in request_825: " << e.what() << std::endl;*/
	}
}
void request_826(tcp::socket& s, const string& name, const string& publicKeyStr, const string& uuid) {
	// Build and send request 826: send RSA public key in Base64.
	// Payload: username + '\0' + publicKeyB64.
	// Response expected: 1602 with encrypted AES key.
	try {
		client_history.push_back({ "request_826", timestamp() });
		/*if (debug_mode) cout << "in request_826" << endl;*/
		logger.debug("in request_826");
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_826_public_key(cid, name, publicKeyStr);
		logger.info("publicKeyB64 length: " + std::to_string(publicKeyStr.size()));
		/*std::cout << "publicKeyB64 length: " << publicKeyStr.size() << std::endl;*/
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		/*std::cerr << "Error in request_826: " << e.what() << std::endl;*/
		logger.error("Error in request_826: " + std::string(e.what()));
	}
}
void request_827(tcp::socket& s, const string& name, const string& uuid) {
	// Build and send request 827: re-login (SSO) using existing client_id and username.
	// Payload: username + '\0'.
	// Response expected: 1605 (re-login success) or 1606 (re-register required).
	/*if (debug_mode) cout << "in request_827" << endl;*/
	logger.debug("in request_827");
	client_history.push_back({ "request_827", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_827_relogin(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));;
	}
	catch (const std::exception& e) {
		/*std::cerr << "Error in request_827: " << e.what() << std::endl;*/
		logger.error("Error in request_827: " + std::string(e.what()));
	}

}
uint32_t request_828(tcp::socket& s, const string& name, const string& uuid, vector<string>& components) {
	// Build and send request 828: encrypted file in chunks.
	// Packet 0 carries ONLY the 16-byte IV.
	// Packets 1..N carry metadata + filename + ciphertext chunk.
	// total_cipher_size refers to ciphertext bytes only (excludes the IV).
	// Returns the original CRC32 of the plaintext for verification.
	/*if (debug_mode)cout << "in request_828" << endl;*/
	logger.debug("in request_828");
	client_history.push_back({ "request_828", timestamp() });
	try {
		
		if (components[4].size() != CryptoPP::AES::BLOCKSIZE)
			throw std::runtime_error("IV size is not 16");
		if (components.empty()) {
			logger.error("components is empty");
			/*cout << "components is empty" << endl;*/
			exit(1);
		}
		logger.info("IV(hex)=" + to_hex(components[4]));
		logger.info("cipher_prefix(hex)=" + to_hex(components[2].substr(0, 32)));
		/*std::cout << "IV(hex)=" << to_hex(components[4]) << "\n";
		std::cout << "cipher_prefix(hex)=" << to_hex(components[2].substr(0, 32)) << "\n";*/
		const size_t CHUNK_SIZE = 1024;
		// Split ciphertext into fixed-size chunks
		vector<string> chunks = splitStringBySize(components[2], CHUNK_SIZE);
		const size_t total_packets = chunks.size();
		
		// Packet 0: send IV only (16 bytes). Packets 1..N: send ciphertext chunks.
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
		std::memcpy(iv, components[4].data(), CryptoPP::AES::BLOCKSIZE);
		//Clean file name
		size_t address_ch_name = components[0].rfind('\\');
		std::string file_name;
		if (address_ch_name!=string::npos)
		{
			file_name = components[0].substr(address_ch_name+1);
		}
		else {
			file_name = components[0];
		}
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		std::array<uint8_t, 16> iv_arr{};
		std::memcpy(iv_arr.data(), components[4].data(), 16);
		auto msg0 = seftp::proto::build_828_packet0_iv(cid, (uint32_t)components[2].size(), (uint32_t)components[1].size(), (uint16_t)total_packets,file_name, iv_arr);
		logger.debug("[CLIENT] sending packet  0/" + std::to_string(total_packets)+ ", chunk size=" + std::to_string(components[4].size()));
		/*/if (debug_mode)std::cout << "[CLIENT] sending packet " << 0
			<< "/" << total_packets
			<< ", chunk size=" << components[4].size() << std::endl;*/
		// Send the full frame
		boost::asio::write(s, boost::asio::buffer(msg0));
		const bool debug = logger.isDebugEnabled();
		std::ostream& prog = std::cerr;
		// Send each chunk as a separate 828 request
		for (size_t packet_num = 1; packet_num <= total_packets; packet_num ++)
		{
			const std::string& chunk_str = chunks[packet_num - 1];
			std::vector<uint8_t> chunk(chunk_str.begin(), chunk_str.end());
			// Progress bar: debug/normal printing
			if (debug) {
				prog << "sending packet number: " << packet_num << " of " << total_packets << std::endl;
			}
			else if (packet_num == total_packets) prog << "\r"<< "sending packet number: " << packet_num << " of " << total_packets<< " [####################] 100%" << std::endl;
			else {
				prog << "\r"<<"sending packet number: " << packet_num << " of " << total_packets << " [";
				size_t filled = (packet_num * 20) / total_packets;
				for (size_t i = 0; i < 20; i++)
					prog << (i < filled ? '#' : '.');

				prog << "] "<<filled*5<<"%" << std::flush;

			}
			auto msgN=seftp::proto::build_828_packet_chunk(cid, (uint32_t)components[2].size(), (uint32_t)components[1].size(), (uint16_t)packet_num,(uint16_t)total_packets,file_name, chunk);
			if (debug) logger.debug("[CLIENT] sending packet " + std::to_string(packet_num) +
				"/" + std::to_string(total_packets) +
				", chunk size=" + std::to_string(chunk.size()));
			// Send the full frame
			boost::asio::write(s, boost::asio::buffer(msgN));
		}
		logger.debug("[CLIENT] full cipher sent size=" + std::to_string(components[2].size()) +
			", total_packets=" + std::to_string(total_packets) +
			", chunk_size=" + std::to_string(CHUNK_SIZE));
		/*if (debug_mode)std::cout << "[CLIENT] full cipher sent size=" << components[2].size()
			<< ", total_packets=" << total_packets
			<< ", chunk_size=" << CHUNK_SIZE
			<< std::endl;*/
		logger.debug("CRC string: [" + components[3] + "]");
		/*if (debug_mode)std::cout << "CRC string: [" << components[3] << "]" << std::endl;*/
		// Convert CRC string to uint32_t (decimal)
		uint32_t original_crc = static_cast<uint32_t>(std::stoul(components[3], nullptr, 10));
		std::stringstream ss;
		ss << "original_crc (dec): " << original_crc
			<< " (hex): 0x" << std::hex << original_crc;
		logger.debug(ss.str());
		/*if (debug_mode)std::cout << "original_crc (dec): " << original_crc
			<< " (hex): 0x" << std::hex << original_crc << std::dec << std::endl;*/

		return original_crc;// original CRC for this file
	}
	catch (const std::exception& e) {
		logger.error("Error in request_828: " + std::string(e.what()));
		/*std::cerr << "Error in request_828: " << e.what() << std::endl;*/
		return 0;
	}
}
void request_828_retry(tcp::socket& s, string encrypt_key, ClientContext& cc) {
	// Wrapper for request_828 with retry logic based on CRC check (1603).
	// If CRC mismatch:
	//   - up to 3 retries: send 901 and resend file.
	//   - on 4th failure: send 902 (give up).
	// If CRC matches: send 900 (success).
	/*if (debug_mode)cout << "in request_828_retry" << endl;*/
	logger.debug("in request_828_retry");
	client_history.push_back({ "request_828_retry", timestamp() });
	int retries = 0;
	const int MAX_RETRIES = 4;
	bool crc_ok_init = false;
	bool* crc_ok = &crc_ok_init;
	// Encrypt file and compute its CRC32
	// components = [ file_name, plaintext, ciphertext, crc_string, random iv ]
	vector<string> components = encrypt_file(encrypt_key);
	while (retries < MAX_RETRIES && !*crc_ok) {
		logger.debug("this is the uuid " + cc.client_id);
		/*if (debug_mode)cout << "this is the uuid " << cc.client_id << endl;*/
		// 1) Send encrypted file (828) and get original CRC of plaintext
		uint32_t original_crc_file = request_828(s, cc.username, cc.client_id, components);
		// 2) Wait for 1603 from server (CRC verification) and update crc_ok
		auto r = answer_manager(s, cc, original_crc_file, crc_ok);
		logger.debug("this is the uuid " + cc.client_id);
		/*if (debug_mode)cout << "this is the uuid " << cc.client_id << endl;*/
		if (!*crc_ok) {
			// CRC mismatch -> retry or give up
			retries++;
			if (retries < MAX_RETRIES) {
				logger.info("CRC mismatch, retry " + std::to_string(retries) + "/" + std::to_string(MAX_RETRIES));
				/*std::cout << "CRC mismatch, retry " << retries << "/" << MAX_RETRIES << std::endl;*/
				// Notify server: CRC invalid but we will resend (901)
				request_901(s, file_name,cc.client_id);
				logger.debug("this is the uuid " + cc.client_id);
				/*if (debug_mode)cout << "this is the uuid " << cc.client_id << endl;*/
			}
			else {
				// 4th failure -> give up (902)
				logger.info("CRC mismatch after 4 retries, sending 902");
				/*std::cout << "CRC mismatch after 4 retries, sending 902" << std::endl;*/
				request_902(s, file_name, cc.client_id);
			}
		}
		else {
			// CRC OK -> confirm success (900)
			request_900(s, file_name, cc.client_id);
		}	
	}
	
}
void request_900(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 900: notify server that CRC matched for the given file name.
	logger.debug("in request_900");
	/*if (debug_mode)cout << "in request_900" << endl;*/
	client_history.push_back({ "request_900", timestamp() });
	logger.info("we got a match with the crc value, sending confirmation to the server");
	/*cout << "we got a match with the crc value, sending confirmation to the server" << endl;*/
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_900_crc_ok(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		logger.error("Error in request_900: " + std::string(e.what()));
		/*std::cerr << "Error in request_900: " << e.what() << std::endl;*/
	}

}
void request_901(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 901: notify server that CRC mismatched (client will retry sending file).
	/*if (debug_mode)cout << "in request_901" << endl;*/
	logger.debug("in request_901");
	client_history.push_back({ "request_901", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_901_crc_retry(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		/*std::cerr << "Error in request_901: " << e.what() << std::endl;*/
		logger.error("Error in request_901: " + std::string(e.what()));
	}

}
void request_902(tcp::socket& s, const string& name, const string& uuid) {
	// Send request 902: notify server that CRC mismatched after max retries (give up).
	/*if (debug_mode)cout << "in request_902" << endl;*/
	logger.debug("in request_902");
	client_history.push_back({ "request_902", timestamp() });
	try {
		auto cid = seftp::util::parse_client_id_hex32(uuid);
		auto msg = seftp::proto::build_902_crc_fail(cid, name);
		// send
		boost::asio::write(s, boost::asio::buffer(msg));
	}
	catch (const std::exception& e) {
		/*std::cerr << "Error in request_902: " << e.what() << std::endl;*/
		logger.error("Error in request_902: " + std::string(e.what()));
	}

}
std::vector<uint8_t> parse_uuid(const std::string& uuid_str) {
	/*if (debug_mode)cout << "this is the uuid_str " << uuid_str << endl;*/
	logger.debug("this is the uuid_str " + uuid_str);
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

std::vector<string> encrypt_file(string key) {
	// Ask the user for a filename, read the file in binary, compute CRC32,
	// encrypt content using AES-256-CBC with a random per-file IV and a 32-byte AES key
	// (provided as a Base64 string).
	//
	// Returns:
	//   res[0] = file name
	//   res[1] = plaintext content
	//   res[2] = ciphertext (binary, includes PKCS#7 padding, WITHOUT the IV)
	//   res[3] = CRC32 of plaintext as a decimal string
	//   res[4] = IV (16 bytes, binary) for this file
	client_history.push_back({ "encrypt_file", timestamp() });
	/*if (debug_mode)cout << "in encrypt_file " << endl;*/
	logger.debug("in encrypt_file");
	std::ifstream file;
	while (true) {
		// Ask user for file name to send
		std::cout << "\nWhat is the name of the file you want to send:" << std::endl;
		std::getline(cin, file_name);
		// Try to open the file in binary mode
		logger.info("reading file ");
		/*cout << "reading file " << endl;*/
		file.open(file_name, std::ios::binary);
		if (file.is_open()) break;
		// If failed, report and ask again
		logger.error("Error opening file: " + file_name);
		/*std::cerr << "Error opening file: " << file_name << std::endl;*/
		file.clear();

	}
	// Read entire file into plaintext string
	std::string plain_text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();
	// Compute CRC32 over plaintext (for integrity verification with server later)
	uint32_t crc_val = seftp::crypto::crc32(plain_text);
	std::stringstream ss;
	ss << "CRC (dec): " << crc_val << " (hex): 0x" << std::hex << crc_val;
	logger.info(ss.str());
	/*cout << "CRC (dec): " << crc_val << " (hex): 0x" << std::hex << crc_val << std::dec << endl;*/
	logger.debug("Plaintext size: " + std::to_string(plain_text.size()));
	/*if (debug_mode)cout << "Plaintext size: " << plain_text.size() << endl;*/
	// Decode AES key from Base64 string
	std::string raw_key = seftp::crypto::decode_base64(key);
	auto iv_arr = seftp::crypto::make_iv();
	std::string cipher_text = seftp::crypto::aes256_cbc_encrypt(plain_text,raw_key,iv_arr);
	std::string iv_str(reinterpret_cast<const char*>(iv_arr.data()), iv_arr.size());

	// Package results for later use:
	std::vector<std::string> res;
	res.push_back(file_name);      // index 0: file name
	res.push_back(plain_text);     // index 1: original plaintext
	res.push_back(cipher_text);    // index 2:  encrypted binary data
	res.push_back(std::to_string(crc_val));//CRC32 of plaintext, as a decimal string
	res.push_back(iv_str); // IV (16 bytes) generated per file, sent separately in 828 packet_number=0
	logger.debug("==== CLIENT DEBUG ====");
	logger.debug("Original file name: ");
	logger.debug("Original file size: " + std::to_string(plain_text.size()));
	ss.clear();
	ss.str("");
	ss << "Original CRC (dec): " << crc_val << " (hex): 0x" << std::hex << crc_val;
	logger.debug(ss.str());
	logger.debug("======================");
	/*if (debug_mode) {
		cout << "==== CLIENT DEBUG ====" << endl;
		cout << "Original file name: " << file_name << endl;
		cout << "Original file size: " << plain_text.size() << endl;
		cout << "Original CRC (dec): " << crc_val
			<< " (hex): 0x" << std::hex << crc_val << std::dec << endl;
		cout << "======================" << endl;
	}*/
	return res;
}
std::vector<std::string> splitStringBySize(const std::string& str, size_t chunkSize) {
	std::vector<std::string> chunks;
	for (size_t i = 0; i < str.length(); i += chunkSize) {
		chunks.push_back(str.substr(i, chunkSize));
	}
	return chunks;
}
string answer_1600(vector<uint8_t>& payload, string name) {
	// Handle response 1600: registration succeeded.
	// Payload: 16-byte client_id.
	// Writes name and client_id hex into me.info.
	/*if (debug_mode) cout << "in answer_1600" << endl;*/
	logger.debug("in answer_1600");
	client_history.push_back({ "answer_1600" ,timestamp()});
	std::ostringstream oss;
	for (uint8_t byte : payload) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
	}
	string client_id_hex = oss.str();
	//write to me.info
	if (!seftp::util::files::write_me_identity(name,client_id_hex))
	{
		/*cerr << "Failed to open me.info for writing" << endl;*/
		logger.error("Failed to open me.info for writing");
		return "";
	}

	logger.info("register for the client id: " + client_id_hex + " succeed");
	/*cout << "register for the client id: " << client_id_hex << " succeed" << endl;*/
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
	logger.debug("in answer_1601");
	/*if (debug_mode)cout << "in answer_1601" << endl;*/
	client_history.push_back({ "answer_1601" ,timestamp()});
	logger.info("register failed");
	/*cout << "register failed" << endl;*/
}
std::string answer_1602(const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1602: AES key encrypted with RSA public key for this client.
	// Decrypts AES key using priv.key and stores it as Base64 in aes.key.
	logger.debug("in answer_1602");
	/*if (debug_mode)cout << "in answer_1602" << endl;*/
	client_history.push_back({ "answer_1602" ,timestamp() });
	logger.info("client " + client_id + " received encrypted AES key");
	/*std::cout << "client " << client_id << " received encrypted AES key" << std::endl;*/
	std::string decrypted;
	try {
		decrypted = seftp::crypto::rsa_oaep_sha1_decrypt_from_file(privkey_filename, ciphertext);
		/*if (debug_mode) {
			std::cout << "Decrypted AES key len=" << decrypted.size() << std::endl;
		}*/
		logger.debug("Decrypted AES key len=" + std::to_string(decrypted.size()));
	}
	catch (const std::exception& e) {
		logger.error("Decryption error: " + std::string(e.what()));
		/*std::cerr << "Decryption error: " << e.what() << std::endl;*/
		decrypted.clear();
	}

	std::string aes_key_b64 = seftp::crypto::encode_base64(decrypted);
	if (!seftp::util::files::write_aes_key(aes_key_b64))
	{
		/*std::cerr << "Failed to open aes.key for writing" << std::endl;*/
		logger.error("Failed to open aes.key for writing");
	}
	else {
		/*std::cout << "AES key saved to aes.key (Base64, len=" << aes_key_b64.size() << ") <only for demonstrating>: " << aes_key_b64 << std::endl;*/
		logger.info("AES key saved to aes.key (Base64, len=" + std::to_string(aes_key_b64.size()) + ") <only for demonstrating>: " + aes_key_b64);
	}

	return aes_key_b64;
}
string answer_1605(const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1605: re-login approved.
	// Same format as 1602 (delegates to answer_1602).
	client_history.push_back({ "answer_1605" ,timestamp() });
	logger.debug("in answer_1605 the next will be answer_1602 (SAME FUNCTION)");
	/*if (debug_mode)cout << "in answer_1605 the next will be answer_1602 (SAME FUNCTION)" << endl;*/
	logger.info("request to re-register approved, gets aes encrypted key");
	/*cout << "request to re-register approved, gets aes encrypted key" << endl;*/
	return answer_1602(client_id, ciphertext, privkey_filename);
}

static DispatchResult handle_1606(const std::vector<uint8_t>& payload, ClientContext& cc) {
	// Handle response 1606: server indicates that re-login failed or public key is invalid.
	// If client_id is all zeros -> client must register again (825 + 826).
	// Otherwise -> generate new RSA keys and send again.
	/*if (debug_mode)cout << "in handle_1606" << endl;*/
	logger.debug("in handle_1606");
	client_history.push_back({ "handle_1606" ,timestamp() });
	DispatchResult out{};
	if (payload.size() < seftp::proto::kClientIdLen) {
		cc.last_error_text = "1606 payload too short";
		out.step = NextStep::Fatal;
		return out;
	}
	seftp::proto::ClientId cid{};
	std::memcpy(cid.data(), payload.data(), seftp::proto::kClientIdLen);
	std::string client_id_hex = seftp::util::client_id_to_hex(cid);
	if (client_id_hex == std::string(32, '0')) {
		cc.need_register = true;
		out.step = NextStep::NeedRegister;
		logger.info("request to re-register disapproved, the client id is: " + client_id_hex + ". is not register");
		/*cout << "request to re-register disapproved, the client id is: " << client_id_hex << ". is not register" << endl;*/
		/*cout << "need to sign up, making a new client id" << endl;*/
		logger.info("need to sign up, making a new client id");
		return out;
	}
	cc.client_id = client_id_hex;
	cc.send_public_key = true;
	out.step = NextStep::NeedSendPublicKey;
	out.updated_client_id = true;
	return out;
}
static std::string handle_1602_or_1605(seftp::proto::ResCode code, const seftp::proto::Res1602& r) {
	std::string client_id_hex = seftp::util::client_id_to_hex(r.client_id);
	if (code == seftp::proto::ResCode::AesKey)
	{
		answer_1602(client_id_hex, r.encrypted_key, "priv.key");
		logger.debug("after 1602");
		/*if (debug_mode) cout << "after 1602" << endl;*/
	}
	else { // 1605
		cout << answer_1605(client_id_hex, r.encrypted_key, "priv.key") << endl;
		/*if (debug_mode) cout << "after 1605" << endl;*/
		logger.debug("after 1605");
	}

	/*if (debug_mode) {
		std::cout << "uuid in answer manager after 1602/1605: [" << client_id_hex << "]" << std::endl;
	}*/
	logger.debug("uuid in answer manager after 1602/1605: [" + client_id_hex + "]");
	return client_id_hex;
}
bool answer_1603(tcp::socket& s, vector<uint8_t>payload, uint32_t original_crc) {
	// Handle response 1603: server sends its computed CRC for the received file.
	// Compares server CRC to original_crc and returns true on match.
	// Used by request_828_retry() to decide whether to retry or send 900/902.
	/*if (debug_mode)cout << "in answer_1603" << endl;*/
	logger.debug("after 1603");
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


	/*std::cout << "Server CRC: " << server_crc << ", original CRC: " << original_crc << std::endl;*/
	logger.info("Server CRC: " + std::to_string(server_crc) + ", original CRC: " + std::to_string(original_crc));

	if (server_crc == original_crc) {
		logger.info("Checksum verified successfully!");
		/*std::cout << "Checksum verified successfully!" << std::endl;*/
		return true;
	}
	else {
		logger.warn("Checksum mismatch!");
		/*std::cerr << "Checksum mismatch!" << std::endl;*/
		return false;
	}
}
static void handle_1603(const seftp::proto::Res1603& r, uint32_t original_crc, bool* crc_ok)
{
	if (!crc_ok) return;

	/*std::cout << "Server CRC: " << r.server_crc << ", original CRC: " << original_crc << std::endl;*/
	logger.info("Server CRC: " + std::to_string(r.server_crc) + ", original CRC: " + std::to_string(original_crc));

	if (r.server_crc == original_crc) {
		/*std::cout << "Checksum verified successfully!" << std::endl;*/
		logger.info("Checksum verified successfully!");
		*crc_ok = true;
	}
	else {
		/*std::cerr << "Checksum mismatch!" << std::endl;*/
		logger.warn("Checksum mismatch!");
		*crc_ok = false;
	}
}
void answer_1604() {
	client_history.push_back({ "answer_1604" ,timestamp() });
	/*if (debug_mode)std::cout << "in answer_1604" << std::endl;*/
	logger.debug("in answer_1604");
	logger.info("finish transfering");
	/*std::cout << "finish transfering" << std::endl;*/
}
void answer_1607(string& text) {
	client_history.push_back({ "answer_1607" ,timestamp() });
	/*if (debug_mode)std::cout << "in answer_1607" << std::endl;*/
	logger.debug("in answer_1607");
	logger.warn("general error {" + text + "}, please close the client and run again");
	/*cout << "general error {" << text << "}, please close the client and run again" << endl;*/
}
DispatchResult answer_manager(tcp::socket& s, ClientContext& cc, uint32_t original_crc, bool* crc_ok) {
	// Read a single response frame from the server and dispatch to the correct handler.
	// The function may:
	//   - write me.info (on registration success)
	//   - decrypt and store AES key (1602/1605)
	//   - update crc_ok flag based on 1603
	//   - print status / errors for 1604/1607
	// Returns:
	//   - client_id as a hex string when relevant (1600/1602/1605/1606)
	//   - empty string otherwise.
	/*if (debug_mode)cout << "in answer_manager" << endl;*/
	logger.debug("in answer_manager");
	client_history.push_back({ "answer_manager" ,timestamp() });
	const int max_Length = 1024;
	char request[max_Length];

	auto frame = seftp::net::read_response_frame(s);

	/*if (debug_mode) {
		std::cout << "version: " << (int)frame.version
			<< ", code: " << (uint16_t)frame.code
			<< ", payload size: " << frame.payload.size()
			<< std::endl;
	}*/
	std::stringstream ss;
	ss << "version: " << (int)frame.version << ", code: " << (uint16_t)frame.code << ", payload size: " << frame.payload.size();
	logger.debug(ss.str());
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
		return { NextStep::Fatal,false };
	}
	case seftp::proto::ResCode::AesKey:
	case seftp::proto::ResCode::ReloginOk: {
		auto r1602_1605 = seftp::proto::parse_1602(pv);
		cc.client_id = handle_1602_or_1605(frame.code, r1602_1605);
		return {};
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
		DispatchResult out{};
		out.step = NextStep::Fatal;
		if (frame.payload.size() < seftp::proto::kClientIdLen) {
			logger.warn("payload for 1607 too short");
			/*cout << "payload for 1607 too short" << endl;*/
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
		logger.debug("this is the uuid in answer manager after 1607: [" + client_id_hex + "]");
		/*if (debug_mode)std::cout << "this is the uuid in answer manager after 1607: [" << client_id_hex << "]" << std::endl;*/
		return { NextStep::Fatal };
	}
	default:
		logger.warn("the code: " + std::to_string(static_cast<uint16_t>(frame.code)) + " is not a valid code for a response");
		/*cout << "the code: " << static_cast<uint16_t>(frame.code) << " is not a valid code for a response" << endl;*/
		cc.last_error_text = "Unknown response code: " + std::to_string((uint16_t)frame.code);
		return { NextStep::Fatal,false };

	}
}
