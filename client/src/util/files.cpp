#include "files.hpp"
#include <fstream>
namespace seftp::util::files {
	bool write_me_identity(const std::string& username, const std::string& client_id_hex) {
		std::ofstream myFile(kMeInfo);
		if (!myFile.is_open()) return false;

		myFile << username << "\n";
		myFile << client_id_hex << "\n";
		myFile.close();
		return true;
	}

	bool write_me_public_key(const std::string& public_key_b64) {
		std::string username, cid;
		if (!read_me_info(username, cid, nullptr)) return false;

		std::ofstream out(kMeInfo, std::ios::trunc);
		if (!out) return false;
		out << username << "\n";
		out << cid << "\n";
		out << public_key_b64 << "\n";
		return true;
	}
	bool write_aes_key(const std::string& aes_key_b64) {
		std::ofstream aesFile(kAesKey, std::ios::trunc);
		if (!aesFile) return false;

		aesFile << aes_key_b64 << std::endl;
		aesFile.close();
		return true;
	}
	bool read_aes_key(std::string& aes_key_b64) {
		std::ifstream f(kAesKey);
		if (!f) return false;

		std::getline(f, aes_key_b64);  
		return true;
	}
	bool read_private_key(std::string& key_bin) {
		std::ifstream f(kPrivKey, std::ios::binary);
		if (!f) return false;

		key_bin.assign(std::istreambuf_iterator<char>(f), {});
		return true;
	}
	bool read_me_info(std::string& username, std::string& client_id_hex, std::string* public_key_b64) {
		std::ifstream MyReadFile(kMeInfo);
		if (!MyReadFile.is_open()) return false;

		if(!std::getline(MyReadFile, username)) return false;// first line: username
		if (!std::getline(MyReadFile, client_id_hex)) return false;// second line: client_id hex
		if (public_key_b64) {
			std::string line;
			if (std::getline(MyReadFile, line)) *public_key_b64 = line;
			else public_key_b64->clear();
		}
		MyReadFile.close();
		return true;
	}	
}