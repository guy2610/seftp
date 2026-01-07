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
using namespace std;
using namespace CryptoPP;
using  boost::asio::ip::tcp;

vector<string> transfer_file_info(string namefile);
string timestamp();
void request_825(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message);
void request_826(tcp::socket& s, const string& name, string publicKeyStr, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid);
void request_827(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid);
uint32_t request_828(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid, string encrypt_key, vector<string>& components);
void request_828_retry(tcp::socket& s, vector<string> transfers, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid, string encrypt_key);
void request_900(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid);
void request_901(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid);
void request_902(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid);
void append_little_endian_32(std::vector<uint8_t>& buffer, uint32_t value);
void append_little_endian_8(std::vector<uint8_t>& buffer, uint8_t value);
void append_little_endian_16(std::vector<uint8_t>& buffer, uint16_t value);
std::vector<std::string> splitStringBySize(const std::string& str, size_t chunkSize);
std::vector<string> encrypt_file(string key);
std::vector<uint8_t> parse_uuid(const std::string& uuid_str);
std::array<uint8_t, 16> make_iv();
std::string to_hex(const std::string& data);
string answer_manager(tcp::socket& s, vector<string> transfers, uint32_t original_crc=0, bool* crc_ok=nullptr);
void making_RSAkeys(tcp::socket& s, char request[], const int max_Length, vector<uint8_t>& message, vector<string> transfers,  string& uuid, string key = "");
struct ClientEvent{
	string method;
	string time_stamp;
};
vector<ClientEvent> client_history;
bool debug_mode = false;
string file_name;
int main() {
	cout << "do you wish to see debug console promts? answer 'yes' or something else for no" << endl;
	string ans;
	getline(cin, ans);
	transform(ans.begin(), ans.end(), ans.begin(),
		[](unsigned char c) { return std::tolower(c); });;
	if (ans == "yes") debug_mode = true;

	// Read connection and username info from transfer.info
	// Expected: host, port, username
	vector<string> transfers = transfer_file_info("transfer.info");
	string address = transfers[0];
	string port = transfers[1];
	const int max_Length = 1042;
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	try {
		// Establish TCP connection to the server
		boost::asio::connect(s, resolver.resolve(address, port));
	}
	catch (const boost::system::system_error& e) {
		std::cerr << "Failed to connect: " << e.what() << std::endl;
		return 1;
	}
	cout << "\nconnection succeeded" << endl;
	char request[max_Length];
	ifstream MyReadFile("me.info");
	vector<uint8_t>message;
	string uuid, key, name;
	auto update_uuid_if_present = [&](const string& maybe) {
		if (!maybe.empty()) uuid = maybe;};
	if (!MyReadFile.is_open()) {
		// No me.info -> first registration flow (825 + 826 + 1600 + 1602)
		cout << "Failed to open me.info" << std::endl;
		cout << "Doing First sign on" << std::endl;
		//first sign on
		const int max_Length = 1042;
		char request[max_Length];
		//head of request
		MyReadFile.close();
		// 1) Send registration request with username (825)
		request_825(s, transfers[2].c_str(), request, max_Length, message);
		// 2) Wait for 1600 and receive server-issued client_id from server
		update_uuid_if_present(answer_manager(s, transfers));
		if (debug_mode)std::cout << "uuid after answer_manager: [" << uuid << "]" << std::endl;
		// 3) Generate RSA-2048 key pair, send public key (826), receive AES key (1602)
		if (debug_mode)cout << "before entering making_RSAkeys " << endl;
		making_RSAkeys(s, request, max_Length, message, transfers, uuid);
		update_uuid_if_present(answer_manager(s, transfers));
		if (debug_mode)std::cout << "uuid after answer_manager: [" << uuid << "]" << std::endl;
	
	}
	else {
		// me.info exists -> Single Sign-On flow (827 + 1605)
		cout << "file me.info exist, handle SSO" << endl;
		string text;
		getline(MyReadFile, name);// first line: username
		cout << "this is name in me.info: "<<name << endl;
		getline(MyReadFile, uuid);// second line: client_id hex
		cout << "this is uuid in me.info: " << uuid<< endl;
		MyReadFile.close();
		// 1) Send SSO / re-login request with existing client_id + username (827)
		request_827(s, transfers[2].c_str(), request, max_Length, message, uuid);
		if (debug_mode)std::cout << "uuid after answer_manager: [" << uuid << "]" << std::endl;
		// 2) Wait for 1605 (or 1606). client_id remains stable; only AES key is refreshed if needed
		update_uuid_if_present(answer_manager(s, transfers));
		if (debug_mode)std::cout << "uuid after answer_manager: [" << uuid << "]" << std::endl;
		
	}
	// Load AES key from aes.key (Base64), which was written by answer_1602/1605
	{
		std::ifstream f("aes.key");
		if (!f) {
			std::cerr << "cant open aes.key\n";
			exit(1);
		}
		std::getline(f, key);  //key in Base64
		std::cout << "Loaded AES key from file (Base64, len=" << key.size() << ")" << std::endl;
	}
	if (debug_mode)cout << "this is the uuid "<<uuid << endl;
	if (debug_mode)cout << "before file send operation" << endl;
	// Main loop: encrypt and send files to the server, one by one
	while (true) {
		// Sends file (828 + retry with 900/901/902 based on CRC)
		request_828_retry(s, transfers, request, max_Length, message, uuid, key);
		// Read final response (e.g., 1604 – transfer finished)
		string tmp = answer_manager(s, transfers);
		if (debug_mode)std::cout << "uuid after answer_manager: [" << uuid << "]" << std::endl;
		// Ask user if they want to send another file
		cout << "\nDo you want to send another file to the server? answer 'yes' or something else for no" << endl;
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
void making_RSAkeys(tcp::socket& s, char request[], const int max_Length,vector<uint8_t>& message, vector<string> transfers, string& uuid, string key)
{
	// Generate a new RSA-2048 key pair or load an existing private key,
	// send the public key to the server (request 826), and wait for the AES key (1602/1605).
	// If 'key' is empty: generate new keys and save priv.key.
	// If 'key' is non-empty: load RSA private key from the given binary string.
	client_history.push_back({"making_RSAkeys",timestamp() });
	if (debug_mode)cout << "inside making_RSAkeys" << endl;
	CryptoPP::RSA::PrivateKey privateKey;
	CryptoPP::RSA::PublicKey publicKey;

	if (key.empty()) {
		//create new keys
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::InvertibleRSAFunction params;
		params.GenerateRandomWithKeySize(rng, 2048);
		privateKey = CryptoPP::RSA::PrivateKey(params);
		publicKey = CryptoPP::RSA::PublicKey(params);
	}
	else {
		try {
		CryptoPP::StringSource ss(key, true);  
		privateKey.Load(ss);                   //load binary private key
		publicKey = RSA::PublicKey(privateKey);
		}catch (const CryptoPP::Exception& e) {
		std::cerr << "Failed to load priv.key (DER): " << e.what() << std::endl;
		exit(1);
		}
	}
	// send public key to the server
	std::string publicKeyDer;
	publicKey.Save(CryptoPP::StringSink(publicKeyDer).Ref());
	if(debug_mode)std::cout << "DER len: " << publicKeyDer.size() << std::endl;

	std::string publicKeyB64;
	CryptoPP::StringSource(publicKeyDer, true,
		new CryptoPP::Base64Encoder(new CryptoPP::StringSink(publicKeyB64), false)
	);
	if (debug_mode) std::cout << "publicKeyB64 length: " << publicKeyB64.size() << std::endl;
	// approx 392 chars
	std::fill(request, request + max_Length, '\0');
	ofstream myFile;
	myFile.open("me.info", std::ios_base::app);
	if (!myFile.is_open()) {
		cerr << "Failed to add to me.info public key" << endl;
		exit(1);
	}
	myFile << publicKeyB64 << "\n";
	myFile.close();
	cout << "Public key (B64) added to me.info: "<<publicKeyB64 << endl;
	if(debug_mode)cout << "sending 826, b64 len: " << publicKeyB64.size() << endl;
	request_826(s, transfers[2].c_str(),publicKeyB64, request, max_Length, message, uuid);

	// keep private key
	if (key.empty()) {
		privateKey.Save(CryptoPP::FileSink("priv.key").Ref());
	}

	std::cout << "RSA keys generated and saved to files.\n";
	{
		std::string maybe = answer_manager(s, transfers);
		if (!maybe.empty()) uuid = maybe;
	}
}
vector<string> transfer_file_info(string namefile) {
	// Read transfer.info and parse connection and username information.
	// Expected format (per line):
	//   host:127.0.0.1
	//   port:1234
	//   username:myname
	// Returns a vector with tokens in the same order.
	client_history.push_back({ "transfer_file_info",timestamp() });
	vector<string> res;
	string myText;
	ifstream MyReadFile(namefile);
	while (getline(MyReadFile, myText)) {
		size_t i = myText.find(":");
		if (i != string::npos) {
			res.push_back(myText.substr(0, i));
			res.push_back(myText.substr(i + 1, myText.length()));
		}
		else {
			res.push_back(myText);
		}
	}
	return res;
}
void request_825(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message) {
	// Build and send request 825: initial registration.
	// Payload: username + '\0'.
	// Response expected: 1600 (success) or 1601 (failure).
	try {
		client_history.push_back({ "request_825", timestamp() });
		if (debug_mode)cout << "in request_825" << endl;
		message.clear();
		message.insert(message.end(), 16, 0);
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 825);
		// Payload Size = length(username) + \0
		append_little_endian_32(message, name.size() + 1);
		// Payload = username + \0
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		// send
		boost::asio::write(s, boost::asio::buffer(message));
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_825: " << e.what() << std::endl;
	}
}
void request_826(tcp::socket& s, const string& name, string publicKeyStr, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid) {
	// Build and send request 826: send RSA public key in Base64.
	// Payload: username + '\0' + publicKeyB64.
	// Response expected: 1602 with encrypted AES key.
	try {
		client_history.push_back({ "request_826", timestamp() });
		if (debug_mode) cout << "in request_826" << endl;
		message.clear();
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 826);
		// Payload Size = length(username) + \0
		append_little_endian_32(message, name.size() + 1 + publicKeyStr.size() );
		// Payload = username + \0
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		message.insert(message.end(), publicKeyStr.begin(), publicKeyStr.end());
		std::cout << "publicKeyB64 length: " << publicKeyStr.size() << std::endl;
		// send
		boost::asio::write(s, boost::asio::buffer(message));
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_826: " << e.what() << std::endl;
	}
}
void request_827(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid) {
	// Build and send request 827: re-login (SSO) using existing client_id and username.
	// Payload: username + '\0'.
	// Response expected: 1605 (re-login success) or 1606 (re-register required).
	if (debug_mode) cout << "inside request_827"  << endl;
	client_history.push_back({ "request_827", timestamp() });
	try {
		message.clear();
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 827);
		// Payload Size = length(username) + \0
		append_little_endian_32(message, name.size() + 1);
		// Payload = username + \0
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		// send
		boost::asio::write(s, boost::asio::buffer(message));;
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_827: " << e.what() << std::endl;
	}

}
uint32_t request_828(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid, string encrypt_key, vector<string>& components) {
	// Build and send request 828: encrypted file in chunks.
	// Packet 0 carries ONLY the 16-byte IV.
	// Packets 1..N carry metadata + filename + ciphertext chunk.
	// total_cipher_size refers to ciphertext bytes only (excludes the IV).
	// Returns the original CRC32 of the plaintext for verification.
	if (debug_mode)cout << "in request_828" << endl;
	client_history.push_back({ "request_828", timestamp() });
	try {
		
		if (components[4].size() != CryptoPP::AES::BLOCKSIZE)
			throw std::runtime_error("IV size is not 16");
		if (components.empty()) {
			cout << "components is empty" << endl;
			exit(1);
		}
		std::cout << "IV(hex)=" << to_hex(components[4]) << "\n";
		std::cout << "cipher_prefix(hex)=" << to_hex(components[2].substr(0, 32)) << "\n";
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
		
		message.clear();
		// Convert UUID string (32 hex chars) to 16 bytes
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		// Version
		append_little_endian_8(message, 3);
		// Code = 828 (file transfer)
		append_little_endian_16(message, 828);
		// Compute payload size:
		//   4 bytes: total ciphertext size
		//   4 bytes: original plaintext size
		//   2 bytes: packet number
		//   2 bytes: total_packets
		//   len(file_name) + 1: filename + '\0'
		//   chunk.size(): ciphertext chunk
		append_little_endian_32(message, 4 + 4 + 2 + 2 + file_name.size() + 1 + CryptoPP::AES::BLOCKSIZE);
		// Total ciphertext size (for information)
		append_little_endian_32(message, components[2].size());
		// Original plaintext size
		append_little_endian_32(message, components[1].size());
		// Packet number (0 = IV init packet, then 1..total_packets)
		append_little_endian_16(message, 0);
		// Total number of packets
		append_little_endian_16(message, total_packets);
		// Filename + '\0'
		message.insert(message.end(), file_name.begin(), file_name.end());
		message.push_back('\0');
		// Ciphertext chunk
		message.insert(message.end(), iv, iv + CryptoPP::AES::BLOCKSIZE);
		if (debug_mode)std::cout << "[CLIENT] sending packet " << 0
			<< "/" << total_packets
			<< ", chunk size=" << components[4].size() << std::endl;
		// Send the full frame
		boost::asio::write(s, boost::asio::buffer(message));
		// Send each chunk as a separate 828 request
		for (size_t packet_num = 1; packet_num <= total_packets; packet_num ++)
		{
			const std::string& chunk = chunks[packet_num - 1];
			// Progress bar: debug/normal printing
			if (debug_mode) {
				std::cout << "sending packet number: " << packet_num << " of " << total_packets << std::endl;	
			}
			else if (packet_num == total_packets)std::cout << "\r"<<"sending packet number: " << packet_num << " of " << total_packets << " [####################] 100%" << std::endl;
			else {
				std::cout << "\r"<<"sending packet number: " << packet_num << " of " << total_packets << " [";
				size_t filled = (packet_num * 20) / total_packets;
				for (size_t i = 0; i < 20; i++)
					std::cout << (i < filled ? '#' : '.');

				std::cout << "] "<<filled*5<<"%" << std::flush;

			}

			message.clear();
			// Convert UUID string (32 hex chars) to 16 bytes
			std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
			if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
			message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
			// Version
			append_little_endian_8(message, 3);
			// Code = 828 (file transfer)
			append_little_endian_16(message, 828);
			// Compute payload size:
			//   4 bytes: total ciphertext size
			//   4 bytes: original plaintext size
			//   2 bytes: packet number
			//   2 bytes: total_packets
			//   len(file_name) + 1: filename + '\0'
			//   chunk.size(): ciphertext chunk
			append_little_endian_32(message, 4 + 4 + 2 + 2 + file_name.size() + 1 + chunks[packet_num - 1].size());
			// Total ciphertext size (for information)
			append_little_endian_32(message, components[2].size());
			// Original plaintext size
			append_little_endian_32(message, components[1].size());
			// Packet number (1-based)
			append_little_endian_16(message, packet_num);
			// Total number of packets
			append_little_endian_16(message, total_packets);
			// Filename + '\0'
			message.insert(message.end(), file_name.begin(), file_name.end());
			message.push_back('\0');
			// Ciphertext chunk
			message.insert(message.end(), chunks[packet_num - 1].begin(), chunks[packet_num - 1].end());
			if (debug_mode)std::cout << "[CLIENT] sending packet " << packet_num
				<< "/" << total_packets
				<< ", chunk size=" << chunks[packet_num - 1].size() << std::endl;
			// Send the full frame
			boost::asio::write(s, boost::asio::buffer(message));

		}
		if (debug_mode)std::cout << "[CLIENT] full cipher sent size=" << components[2].size()
			<< ", total_packets=" << total_packets
			<< ", chunk_size=" << CHUNK_SIZE
			<< std::endl;
		if (debug_mode)std::cout << "CRC string: [" << components[3] << "]" << std::endl;
		// Convert CRC string to uint32_t (decimal)
		uint32_t original_crc = static_cast<uint32_t>(std::stoul(components[3], nullptr, 10));
		if (debug_mode)std::cout << "original_crc (dec): " << original_crc
			<< " (hex): 0x" << std::hex << original_crc << std::dec << std::endl;

		return original_crc;// original CRC for this file
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_828: " << e.what() << std::endl;
		return 0;
	}
}
void request_828_retry(tcp::socket& s, vector<string> transfers, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid, string encrypt_key) {
	// Wrapper for request_828 with retry logic based on CRC check (1603).
	// If CRC mismatch:
	//   - up to 3 retries: send 901 and resend file.
	//   - on 4th failure: send 902 (give up).
	// If CRC matches: send 900 (success).
	if (debug_mode)cout << "in request_828_retry" << endl;
	client_history.push_back({ "request_828_retry", timestamp() });
	int retries = 0;
	const int MAX_RETRIES = 4;
	bool crc_ok_init = false;
	bool* crc_ok = &crc_ok_init;
	// Encrypt file and compute its CRC32
	// components = [ file_name, plaintext, ciphertext, crc_string, random iv ]
	vector<string> components = encrypt_file(encrypt_key);
	while (retries < MAX_RETRIES && !*crc_ok) {
		if (debug_mode)cout << "this is the uuid " << uuid << endl;
		// 1) Send encrypted file (828) and get original CRC of plaintext
		uint32_t original_crc_file = request_828(s, transfers[2].c_str(), request, max_Length, message, uuid, encrypt_key, components);
		// 2) Wait for 1603 from server (CRC verification) and update crc_ok
		string tmp;
		tmp = answer_manager(s, transfers, original_crc_file,crc_ok);
		if (debug_mode)cout << "this is the uuid " << uuid << endl;
		if (!*crc_ok) {
			// CRC mismatch -> retry or give up
			retries++;
			if (retries < MAX_RETRIES) {
				std::cout << "CRC mismatch, retry " << retries << "/" << MAX_RETRIES << std::endl;
				// Notify server: CRC invalid but we will resend (901)
				request_901(s, file_name, request,max_Length,message,uuid);
				if (debug_mode)cout << "this is the uuid " << uuid << endl;
			}
			else {
				// 4th failure -> give up (902)
				std::cout << "CRC mismatch after 4 retries, sending 902" << std::endl;
				request_902(s, file_name, request, max_Length, message, uuid);
			}
		}
		else {
			// CRC OK -> confirm success (900)
			request_900(s, file_name, request, max_Length, message, uuid);
		}	
	}
	
}
void request_900(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid) {
	// Send request 900: notify server that CRC matched for the given file name.
	if (debug_mode)cout << "in request_900"<<endl;
	client_history.push_back({ "request_900", timestamp() });
	cout << "we got a match with the crc value, sending confirmation to the server" << endl;
	try {
		message.clear();
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 900);
		// Payload Size = length(fileName) + \0 
		append_little_endian_32(message, name.size() + 1);
		// Payload = fileName + \0
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		// send
		boost::asio::write(s, boost::asio::buffer(message));
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_900: " << e.what() << std::endl;
	}

}
void request_901(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid) {
	// Send request 901: notify server that CRC mismatched (client will retry sending file).
	if (debug_mode)cout << "in request_901" << endl;
	client_history.push_back({ "request_901", timestamp() });
	try {
		message.clear();
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); //hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 901);
		// 4. Payload Size 
		append_little_endian_32(message, name.size() + 1);
		// 5. Payload – fileName + null terminator
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		// send
		boost::asio::write(s, boost::asio::buffer(message));
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_901: " << e.what() << std::endl;
	}

}
void request_902(tcp::socket& s, const string& name, char request[], const int max_Length, vector<uint8_t>& message, const string& uuid) {
	// Send request 902: notify server that CRC mismatched after max retries (give up).
	if (debug_mode)cout << "in request_902" << endl;
	client_history.push_back({ "request_902", timestamp() });
	try {
		message.clear();
		std::vector<uint8_t> uuid_bytes = parse_uuid(uuid); // hex string to 16 bytes
		if (uuid_bytes.size() != 16) throw std::runtime_error("Invalid UUID");
		message.insert(message.end(), uuid_bytes.begin(), uuid_bytes.end());
		append_little_endian_8(message, 3);
		append_little_endian_16(message, 902);
		// Payload Size = length(fileName) + \0
		append_little_endian_32(message, name.size() + 1);
		// Payload = fileName + \0
		message.insert(message.end(), name.begin(), name.end());
		message.push_back('\0');
		// send
		boost::asio::write(s, boost::asio::buffer(message));
	}
	catch (const std::exception& e) {
		std::cerr << "Error in request_902: " << e.what() << std::endl;
	}

}
void append_little_endian_16(std::vector<uint8_t>& buffer, uint16_t value) {
	buffer.push_back(static_cast<uint8_t>(value & 0xFF));        // byte 0 (LSB)
	buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF)); // byte 1 (MSB)
	}
void append_little_endian_8(std::vector<uint8_t>& buffer, uint8_t value) {
	buffer.push_back(value);
}
void append_little_endian_32(std::vector<uint8_t>& buffer, uint32_t value) {
	buffer.push_back(static_cast<uint8_t>(value & 0xFF));
	buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
	buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
	buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}
std::vector<uint8_t> parse_uuid(const std::string& uuid_str) {
	if (debug_mode)cout << "this is the uuid_str " << uuid_str << endl;
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
std::string encode_base64(const std::string& raw_key) {
	std::string encoded;
	CryptoPP::StringSource(reinterpret_cast<const unsigned char*>(raw_key.data()), raw_key.size(), true,
		new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
	return encoded;
}
std::string decode_base64(const std::string& key_b64) {
	std::string decoded;
	CryptoPP::StringSource(key_b64, true,
		new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
	return decoded;
}
std::array<uint8_t, 16> make_iv()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<unsigned int> dist(0, 255);

	std::array<uint8_t, 16> iv{};
	std::generate(iv.begin(), iv.end(),
		[&]() { return static_cast<uint8_t>(dist(gen)); });

	return iv;
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
	if (debug_mode)cout << "in encrypt_file " << endl;
	std::ifstream file;
	while (true) {
		// Ask user for file name to send
		std::cout << "\nWhat is the name of the file you want to send:" << std::endl;
		std::getline(cin, file_name);
		// Try to open the file in binary mode
		cout << "reading file " << endl;
		file.open(file_name, std::ios::binary);
		if (file.is_open()) break;
		// If failed, report and ask again
		std::cerr << "Error opening file: " << file_name << std::endl;
		file.clear();

	}
	// Read entire file into plaintext string
	std::string plain_text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();
	// Compute CRC32 over plaintext (for integrity verification with server later)
	uint32_t crc_val = 0;
	CryptoPP::CRC32 hash;
	hash.Update(reinterpret_cast<const CryptoPP::byte*>(plain_text.data()), plain_text.size());
	hash.Final(reinterpret_cast<CryptoPP::byte*>(&crc_val));
	if (debug_mode)cout << "Plaintext size: " << plain_text.size() << endl;
	cout << "CRC (dec): " << crc_val<< " (hex): 0x" << std::hex << crc_val << std::dec << endl;
	// Decode AES key from Base64 string
	std::string raw_key = decode_base64(key);

	if (raw_key.size() != CryptoPP::AES::MAX_KEYLENGTH) {
		std::cerr << "AES key must be exactly 32 bytes (got " << raw_key.size() << ")\n";
		return {};
	}

	// Use raw 32-byte key as AES-256 key material
	CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(raw_key.data()),
		CryptoPP::AES::MAX_KEYLENGTH);

	/***
	// Stage 1:
	// IV is generated randomly per file and sent to the server alongside the upload
	// (see request_828: packet_number=0 carries the IV).*/
	auto iv_arr = make_iv(); // std::array<uint8_t, 16>
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	std::memcpy(iv, iv_arr.data(), CryptoPP::AES::BLOCKSIZE);
	std::string iv_str(reinterpret_cast<const char*>(iv), CryptoPP::AES::BLOCKSIZE);

	// Encrypt plaintext using AES-256-CBC (binary, no Base64)
	std::string cipher_text;
	try {
		cout << "encrypting the file " << endl;
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		encryptor.SetKeyWithIV(aes_key, aes_key.size(), iv);

		CryptoPP::StringSource(plain_text, true,
			new CryptoPP::StreamTransformationFilter(encryptor,
				new CryptoPP::StringSink(cipher_text)
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Encryption error: " << e.what() << std::endl;
		return {};
	}
	// Package results for later use:
	std::vector<std::string> res;
	res.push_back(file_name);      // index 0: file name
	res.push_back(plain_text);     // index 1: original plaintext
	res.push_back(cipher_text);    // index 2:  encrypted binary data
	res.push_back(std::to_string(crc_val));//CRC32 of plaintext, as a decimal string
	res.push_back(iv_str); // IV (16 bytes) generated per file, sent separately in 828 packet_number=0
	if (debug_mode) {
		cout << "==== CLIENT DEBUG ====" << endl;
		cout << "Original file name: " << file_name << endl;
		cout << "Original file size: " << plain_text.size() << endl;
		cout << "Original CRC (dec): " << crc_val
			<< " (hex): 0x" << std::hex << crc_val << std::dec << endl;
		cout << "======================" << endl;
	}
	return res;
}
std::vector<std::string> splitStringBySize(const std::string& str, size_t chunkSize) {
	std::vector<std::string> chunks;
	for (size_t i = 0; i < str.length(); i += chunkSize) {
		chunks.push_back(str.substr(i, chunkSize));
	}
	return chunks;
}
string answer_1600(tcp::socket& s, vector<uint8_t>& payload, string name) {
	// Handle response 1600: registration succeeded.
	// Payload: 16-byte client_id.
	// Writes name and client_id hex into me.info.
	if (debug_mode) cout << "in answer_1600" << endl;
	client_history.push_back({ "answer_1600" ,timestamp()});
	std::ostringstream oss;
	for (uint8_t byte : payload) {
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
	}
	string client_id_hex = oss.str();

	//write to me.info
	ofstream myFile("me.info");
	if (!myFile.is_open()) {
		cerr << "Failed to open me.info for writing" << endl;
		return "";
	}
	myFile << name << "\n";
	myFile << client_id_hex << "\n";
	myFile.close();
	cout << "register for the client id: " << client_id_hex << " succeed" << endl;
	return client_id_hex;
}
void answer_1601(tcp::socket& s) {
	// Handle response 1601: registration failed (username already exists or other error).
	// Exits the client.
	if (debug_mode)cout << "in answer_1601" << endl;
	client_history.push_back({ "answer_1601" ,timestamp()});
	cout << "register failed" << endl;
	exit(1);
}
std::string answer_1602(tcp::socket& s, const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1602: AES key encrypted with RSA public key for this client.
	// Decrypts AES key using priv.key and stores it as Base64 in aes.key.
	if (debug_mode)cout << "in answer_1602" << endl;
	client_history.push_back({ "answer_1602" ,timestamp() });
	std::cout << "client " << client_id << " received encrypted AES key" << std::endl;
	std::string decrypted;
	try {
		// load private from file
		CryptoPP::RSA::PrivateKey privateKey;
		CryptoPP::FileSource file(privkey_filename.c_str(), true);
		privateKey.Load(file);
		//prepare decryptor OAEP-SHA
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
		//RNG must be lvalue, not temporary
		CryptoPP::AutoSeededRandomPool rng;
		//cast to byte
		const CryptoPP::byte* ct_ptr =
			reinterpret_cast<const CryptoPP::byte*>(ciphertext.data());
		size_t ct_len = ciphertext.size();

		// decrypting through pipeline
		CryptoPP::ArraySource as(
			ct_ptr, ct_len, true,
			new CryptoPP::PK_DecryptorFilter(
				rng, decryptor,
				new CryptoPP::StringSink(decrypted)
			)
		);
		if(debug_mode)std::cout << "Decrypted AES key: '\n'" << decrypted << std::endl;
		if (decrypted.size() != CryptoPP::AES::MAX_KEYLENGTH) {
			if (debug_mode)std::cerr << "ERROR: AES key invalid size: " << decrypted.size()
				<< " (expected " << CryptoPP::AES::MAX_KEYLENGTH << ")" << std::endl;
		}

	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Decryption error: " << e.what() << std::endl;
	}
	std::string aes_key_b64 = encode_base64(decrypted);
	std::ofstream aesFile("aes.key", std::ios::trunc);
	if (!aesFile) {
		std::cerr << "Failed to open aes.key for writing" << std::endl;
	}
	else {
		aesFile << aes_key_b64 << std::endl;
		aesFile.close();
		std::cout << "AES key saved to aes.key (Base64, len=" << aes_key_b64.size() << ") <only for demonstrating>: "<< aes_key_b64 << std::endl;
	}
	return aes_key_b64;
}
string answer_1605(tcp::socket& s, const std::string& client_id, const std::vector<uint8_t>& ciphertext, const std::string& privkey_filename) {
	// Handle response 1605: re-login approved.
	// Same format as 1602 (delegates to answer_1602).
	client_history.push_back({ "answer_1605" ,timestamp() });
	if (debug_mode)cout << "in answer_1605 the next will be answer_1602 (SAME FUNCTION)" << endl;
	cout << "request to re-register approved, gets aes encrypted key" << endl;
	return answer_1602(s, client_id, ciphertext, privkey_filename);
}
string answer_1606(tcp::socket& s, vector<string>transfers, char request[], const int max_Length, vector<uint8_t>message, vector<uint8_t> payload) {
	// Handle response 1606: server indicates that re-login failed or public key is invalid.
	// If client_id is all zeros -> client must register again (825 + 826).
	// Otherwise -> generate new RSA keys and send again.
	if (debug_mode)cout << "in answer_1606" << endl;
	client_history.push_back({ "answer_1606" ,timestamp() });
	const size_t ID_LEN = 16;
	if (payload.size() < ID_LEN) cerr << "1602 payload too short: " << payload.size() << endl;
	std::vector<uint8_t> cid(payload.begin(), payload.begin() + ID_LEN);
	auto to_hex = [](const std::vector<uint8_t>& v) {
		std::ostringstream oss;
		for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
		return oss.str();
		};
	std::string client_id_hex = to_hex(cid);
	cout << "this is the client_id_hex " << client_id_hex << endl;
	if (client_id_hex == std::string(32, '0')) {
		cout << "request to re-register disapproved, the client id is: " << client_id_hex << ". is not register" << endl;
		cout << "need to sign up, making a new client id" << endl;
		if(debug_mode) cout << "making a new user with request_825" << endl;
		request_825(s, transfers[2].c_str(), request, max_Length, message);
		{
			std::string maybe = answer_manager(s, transfers);
			if (!maybe.empty()) client_id_hex = maybe;
		}
		std::string key;
		{
			std::ifstream f("priv.key", std::ios::binary);
			if (!f) {
				std::cout << "cant open priv.key\nneed to make new keys\n";
				making_RSAkeys(s, request, max_Length, message, transfers, client_id_hex);
			}
			else {
				key.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
				making_RSAkeys(s, request, max_Length, message, transfers, client_id_hex, key);
			}
		}

	}
	else {
		cout << "the public key not good making a new one with RSA" << endl;
		making_RSAkeys(s, request, max_Length, message, transfers, client_id_hex);
	}
	return client_id_hex;
}
bool answer_1603(tcp::socket& s, vector<uint8_t>payload, uint32_t original_crc) {
	// Handle response 1603: server sends its computed CRC for the received file.
	// Compares server CRC to original_crc and returns true on match.
	// Used by request_828_retry() to decide whether to retry or send 900/902.
	if (debug_mode)cout << "in answer_1603" << endl;
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


	std::cout << "Server CRC: " << server_crc << ", original CRC: " << original_crc << std::endl;

	if (server_crc == original_crc) {
		std::cout << "Checksum verified successfully!" << std::endl;
		return true;
	}
	else {
		std::cerr << "Checksum mismatch!" << std::endl;
		return false;
	}
}
void answer_1604(tcp::socket& s) {
	client_history.push_back({ "answer_1604" ,timestamp() });
	if (debug_mode)std::cout << "in answer_1604" << std::endl;
	std::cout << "finish transfering" << std::endl;
}
void answer_1607(tcp::socket& s, string& text) {
	client_history.push_back({ "answer_1607" ,timestamp() });
	if (debug_mode)std::cout << "in answer_1607" << std::endl;
	cout << "general error {"<<text<<"}, please close the client and run again" << endl;
	exit(1);
}
string answer_manager(tcp::socket& s, vector<string> transfers, uint32_t original_crc, bool* crc_ok) {
	// Read a single response frame from the server and dispatch to the correct handler.
	// The function may:
	//   - write me.info (on registration success)
	//   - decrypt and store AES key (1602/1605)
	//   - update crc_ok flag based on 1603
	//   - print status / errors for 1604/1607
	// Returns:
	//   - client_id as a hex string when relevant (1600/1602/1605/1606)
	//   - empty string otherwise.
	if (debug_mode)cout << "in answer_manager" << endl;
	client_history.push_back({ "answer_manager" ,timestamp() });
	const int max_Length = 1024;
	char request[max_Length];

	// read header (7 bytes)
	boost::asio::read(s, boost::asio::buffer(request, 7));

	uint8_t version = request[0];
	uint16_t code = static_cast<uint8_t>(request[1]) |
		(static_cast<uint8_t>(request[2]) << 8);

	uint32_t payload_size =
		static_cast<uint8_t>(request[3]) |
		(static_cast<uint8_t>(request[4]) << 8) |
		(static_cast<uint8_t>(request[5]) << 16) |
		(static_cast<uint8_t>(request[6]) << 24);

	// check payload dont exceed length of 7
	if (debug_mode && payload_size > max_Length - 7) {
		cerr << "Payload too big! size=" << payload_size << endl;
		exit(1);
	}

	// read payload with correct size
	boost::asio::read(s, boost::asio::buffer(request + 7, payload_size));

	// payload to vector of uint8_t
	vector<uint8_t> payload(request + 7, request + 7 + payload_size);

	if (debug_mode) {
		cout << "version: " << (int)version << ", code: " << code
			<< ", payload size: " << payload_size << endl;

		cout << "this is the code: " << code << endl;
	}
	string uuid;
	if (code == 1600)
	{
		uuid = answer_1600(s, payload, transfers[2].c_str());
		return uuid;
	}
	else if (code == 1601){
		answer_1601(s);
		exit(1);
	}
	else if (code == 1602||code==1605){
		const size_t RSA_CT_LEN = 256;  
		const size_t ID_LEN = 16;
		if (payload.size() < RSA_CT_LEN + ID_LEN) {
			 if (code==1602)cerr << "1602 payload too short: " << payload.size() << endl;
			 else cerr << "1605 payload too short: " << payload.size() << endl;//code == 1605
			return uuid;
		}
		std::vector<uint8_t> ct(payload.begin(), payload.begin() + RSA_CT_LEN);
		std::vector<uint8_t> cid(payload.begin() + RSA_CT_LEN, payload.begin() + RSA_CT_LEN + ID_LEN);
		auto to_hex = [](const std::vector<uint8_t>& v) {
			std::ostringstream oss;
			for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
			return oss.str();
			};
		std::string client_id_hex = to_hex(cid);
		
		if (code == 1602)answer_1602(s, client_id_hex,ct,"priv.key");
		if (debug_mode)cout << "after 1602" << endl;
		if (code == 1605)cout << answer_1605(s, client_id_hex, ct, "priv.key") << endl;//code == 1605
		if (debug_mode)cout << "didnt do 1605" << endl;
		if (debug_mode)std::cout << "this is the uuid in answer manager after 1602: [" << client_id_hex << "]" << std::endl;
		return client_id_hex;
		
	}	
	else if (code == 1606) {
		
		vector<uint8_t>message;
		uuid = answer_1606(s, transfers, request, max_Length, message, payload);
		return uuid;
	}
	else if (code == 1603){
		*crc_ok = answer_1603(s, payload, original_crc);
		return uuid;
	}
	else if (code == 1604){
		answer_1604(s);
		return uuid;
	}	
	else if (code == 1607){
		const size_t ID_LEN = 16;
		if (payload.size() < ID_LEN) {
			cout << "payload for 1607 too short" << endl;
			return uuid;
		}
		std::vector<uint8_t> cid(payload.begin(),payload.begin()+ID_LEN);
		std::vector<uint8_t> c_text(payload.begin() + ID_LEN, payload.end());
		auto to_hex = [](const std::vector<uint8_t>& v) {
			std::ostringstream oss;
			for (auto b : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
			return oss.str();
			};
		std::string client_id_hex = to_hex(cid);
		std::string text(c_text.begin(), c_text.end());
		auto pos = text.find('\0');
		if (pos != std::string::npos) text.resize(pos);
		answer_1607(s, text);
		if (debug_mode)std::cout << "this is the uuid in answer manager after 1607: [" << client_id_hex << "]" << std::endl;
		return uuid;
		
	}
	else {
		cout << "the code: "<<  code << " is not a valid code for a response" << endl;
		exit(1);
	}



}