#include "files.hpp"
#include <fstream>
namespace seftp::util::files {
	static bool atomic_write(const std::string& file_name, const std::string& content, bool owner_only = false, bool binary = false);

	bool write_me_identity(const std::string& username, const std::string& client_id_hex, const std::string& file_name) {
		std::string content = username + "\n" + client_id_hex + "\n";
		return atomic_write(file_name,content);
	}

	bool write_me_public_key(const std::string& public_key_b64, const std::string& file_name) {
		std::string username, cid;
		if (!read_me_info(username, cid, nullptr,file_name)) return false;

		std::string content = username + "\n" + cid + "\n" + public_key_b64 + "\n";
		return atomic_write(file_name, content);
	}
	bool write_private_key(const std::string& private_key_der, const std::string& file_name) {
		if (std::filesystem::exists(file_name)) {
			return false;
		}
		return atomic_write(file_name, private_key_der, true, true);
	}
	bool write_aes_key(const std::string& aes_key_b64, const std::string& file_name) {
		std::string content = aes_key_b64 + "\n";
		return atomic_write(file_name, content, true);
	}
	static bool set_owner_only_permissions(const std::string& file_name) {
		namespace fs = std::filesystem;
		std::error_code ec;

		fs::permissions(file_name, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);

		return !ec;
	}
	static bool atomic_write(const std::string& file_name, const std::string& content,bool owner_only, bool binary) {
		const std::string tmp = file_name + ".tmp";
		auto mode = std::ios::trunc;
		if (binary) {
			mode |= std::ios::binary;
		}
		{
			std::ofstream out(tmp, mode);
			if (!out) return false;
			out.write(content.data(), static_cast<std::streamsize>(content.size()));
			out.close();
			if (!out) {
				std::filesystem::remove(tmp);
				return false;
			}
		}
		if (owner_only && !set_owner_only_permissions(tmp)) {
			std::filesystem::remove(tmp);
			return false;
		}
		std::error_code ec;
		std::filesystem::remove(file_name, ec);
		std::filesystem::rename(tmp, file_name, ec);
		if (ec) {
			std::filesystem::remove(tmp);
			return false;
		}
		return true;
	}
	bool read_aes_key(std::string& aes_key_b64, const std::string& file_name) {
		std::ifstream f(file_name);
		if (!f) return false;

		std::getline(f, aes_key_b64);  
		return true;
	}
	bool read_private_key(std::string& key_bin, const std::string& file_name) {
		std::ifstream f(file_name, std::ios::binary);
		if (!f) return false;

		key_bin.assign(std::istreambuf_iterator<char>(f), {});
		return true;
	}
	bool read_me_info(std::string& username, std::string& client_id_hex, std::string* public_key_b64, const std::string& file_name) {
		std::ifstream MyReadFile(file_name);
		if (!MyReadFile.is_open()) return false;

		std::string username_tmp, client_id_hex_tmp;
		if(!std::getline(MyReadFile, username_tmp)) return false;// first line: username
		if (!std::getline(MyReadFile, client_id_hex_tmp)) return false;// second line: client_id hex
		username = username_tmp;
		client_id_hex = client_id_hex_tmp;
		if (public_key_b64) {
			std::string line;
			if (std::getline(MyReadFile, line)) *public_key_b64 = line;
			else public_key_b64->clear();
		}
		MyReadFile.close();
		return true;
	}
	bool read_fingerprint(std::string& fingerprint, const std::string& file_name) {
		std::ifstream f(file_name);
		if (!f) return false;
		std::getline(f, fingerprint);
		return true;
	}
	bool write_fingerprint(const std::string& fingerprint, const std::string& file_name) {
		std::string content = fingerprint + "\n";
		return atomic_write(file_name, content, true);
	}
	bool read_server_pin(std::string& fingerprint, const std::string& file_name) {
		std::ifstream f(file_name);
		if (!f) return false;
		std::getline(f, fingerprint);
		return true;
	}
}	