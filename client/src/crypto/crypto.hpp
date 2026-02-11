#pragma once
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>   // CryptoPP::Base64Encoder
#include <random>
#include <array>
#include <cryptopp/files.h>          // FileSink, FileSource
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>          // AutoSeededRandomPool
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/crc.h>
#include <cryptopp/modes.h>

namespace seftp::crypto {
	struct PublicKeyFormat
	{
		std::string publicKeyDer;
		std::string publicKeyB64;
	};
	std::string encode_base64(const std::string& raw_key);
	std::string decode_base64(const std::string& key_b64);
	std::array<uint8_t, 16> make_iv();
	PublicKeyFormat generate_rsa2048_keypair_der(std::string key, std::string priv_key_file_name= "priv.key");
	uint32_t crc32(std::string_view data);
	std::string aes256_cbc_encrypt(std::string plaintext, std::string_view key32, const std::array<uint8_t, 16>& iv_arr);
	std::string aes256_cbc_decrypt(std::string ciphertext, std::string_view key32, const std::array<uint8_t, 16>& iv_arr);
	std::string rsa_oaep_sha1_decrypt_from_file(const std::string& privkey_filename, const std::vector<uint8_t>& ciphertext);
}