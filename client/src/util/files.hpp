#pragma once
#include <string>

namespace seftp::util::files {
	inline constexpr const char* kMeInfo = "me.info";
	inline constexpr const char* kAesKey = "aes.key";
	inline constexpr const char* kPrivKey = "priv.key";
	
	//me.info file
	bool read_me_info(std::string& username, std::string& client_id_hex, std::string* public_key_b64 = nullptr);
	bool write_me_identity(const std::string& username, const std::string& client_id_hex);
	bool write_me_public_key(const std::string& public_key_b64);

	//aes.key file
	bool read_aes_key(std::string& aes_key_b64);
	bool write_aes_key(const std::string& aes_key_b64);

	//priv.key file
	bool read_private_key(std::string& key_bin);

}