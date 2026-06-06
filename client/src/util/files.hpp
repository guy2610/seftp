#pragma once
#include <string>
#include <filesystem>

namespace seftp::util::files {
	inline constexpr const char* kMeInfo = "me.info";
	inline constexpr const char* kAesKey = "aes.key";
	inline constexpr const char* kPrivKey = "priv.key";
	inline constexpr const char* kFingerprint = "server.fingerprint";
	inline constexpr const char* kServerPin = "server.pin";
	
	//me.info file
	bool read_me_info(std::string& username, std::string& client_id_hex, std::string* public_key_b64 = nullptr, const std::string& file_name = kMeInfo);
	bool write_me_identity(const std::string& username, const std::string& client_id_hex, const std::string& file_name = kMeInfo);
	bool write_me_public_key(const std::string& public_key_b64, const std::string& file_name = kMeInfo);

	//aes.key file
	bool read_aes_key(std::string& aes_key_b64, const std::string& file_name=kAesKey);
	bool write_aes_key(const std::string& aes_key_b64, const std::string& file_name= kAesKey);

	//priv.key file
	bool read_private_key(std::string& key_bin, const std::string& file_name = kPrivKey);
	bool write_private_key(const std::string& private_key_der, const std::string& file_name = kPrivKey);

	//server fingerprint
	bool read_fingerprint(std::string& fingerprint, const std::string& file_name = kFingerprint);
	bool write_fingerprint(const std::string& fingerprint, const std::string& file_name = kFingerprint);

	bool read_server_pin(std::string& fingerprint, const std::string& file_name = kServerPin);

}