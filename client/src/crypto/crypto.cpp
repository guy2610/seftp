#include "crypto.hpp"
namespace seftp::crypto {

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
	PublicKeyFormat generate_rsa2048_keypair_der(std::string key, std::string priv_key_file_name) {
		PublicKeyFormat key_pair;
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
				publicKey = CryptoPP::RSA::PublicKey(privateKey);
			}
			catch (const CryptoPP::Exception& e) {
				std::cerr << "Failed to load priv.key (DER): " << e.what() << std::endl;
				throw e;
			}
		}
		publicKey.Save(CryptoPP::StringSink(key_pair.publicKeyDer).Ref());

		CryptoPP::StringSource(key_pair.publicKeyDer, true,
			new CryptoPP::Base64Encoder(new CryptoPP::StringSink(key_pair.publicKeyB64), false)
		);
		// keep private key
		if (key.empty()) {
			privateKey.Save(CryptoPP::FileSink(priv_key_file_name.c_str()).Ref());
		}
		return key_pair;
	}
	uint32_t crc32(std::string_view data) {
		uint32_t crc_val = 0;
		CryptoPP::CRC32 hash;
		hash.Update(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
		hash.Final(reinterpret_cast<CryptoPP::byte*>(&crc_val));
		return crc_val;
	}
	std::string aes256_cbc_encrypt(std::string plaintext, std::string_view key32, const std::array<uint8_t, 16>& iv_arr) {
		if (key32.size() != CryptoPP::AES::MAX_KEYLENGTH) {
			std::cerr << "AES key must be exactly 32 bytes (got " << key32.size() << ")\n";
			return {};
		}

		// Use raw 32-byte key as AES-256 key material
		CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key32.data()),
			CryptoPP::AES::MAX_KEYLENGTH);

		/***
		// Stage 1:
		// IV is generated randomly per file and sent to the server alongside the upload
		// (see request_828: packet_number=0 carries the IV).*/
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
		std::memcpy(iv, iv_arr.data(), CryptoPP::AES::BLOCKSIZE);
		std::string iv_str(reinterpret_cast<const char*>(iv), CryptoPP::AES::BLOCKSIZE);

		// Encrypt plaintext using AES-256-CBC (binary, no Base64)
		std::string cipher_text;
		try {
			std::cout << "encrypting the file " << std::endl;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
			encryptor.SetKeyWithIV(aes_key, aes_key.size(), iv);

			CryptoPP::StringSource(plaintext, true,
				new CryptoPP::StreamTransformationFilter(encryptor,
					new CryptoPP::StringSink(cipher_text)
				)
			);
		}
		catch (const CryptoPP::Exception& e) {
			std::cerr << "Encryption error: " << e.what() << std::endl;
			return {};
		}
		return cipher_text;

	}
	std::string aes256_cbc_decrypt(std::string ciphertext, std::string_view key32, const std::array<uint8_t, 16>& iv_arr) {
		if (key32.size() != CryptoPP::AES::MAX_KEYLENGTH) {
			std::cerr << "AES key must be exactly 32 bytes (got " << key32.size() << ")\n";
			return {};
		}
		CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key32.data()),CryptoPP::AES::MAX_KEYLENGTH);

		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
		std::memcpy(iv, iv_arr.data(), CryptoPP::AES::BLOCKSIZE);

		std::string plain;
		try {
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
			decryptor.SetKeyWithIV(aes_key, aes_key.size(), iv);

			CryptoPP::StringSource(ciphertext, true,
				new CryptoPP::StreamTransformationFilter(decryptor,
					new CryptoPP::StringSink(plain)
				)
			);
		}
		catch (const CryptoPP::Exception& e) {
			std::cerr << "Decryption error: " << e.what() << std::endl;
			return {};
		}
		return plain;
	}
	std::string rsa_oaep_sha1_decrypt_from_file(const std::string& privkey_filename, const std::vector<uint8_t>& ciphertext) {

		if (ciphertext.size() != 256) {
			throw std::runtime_error("RSA ciphertext must be 256 bytes (RSA-2048)");
		}
		// load private from file
		CryptoPP::RSA::PrivateKey privateKey;
		CryptoPP::FileSource file(privkey_filename.c_str(), true);
		privateKey.Load(file);
		//prepare decryptor OAEP-SHA
		CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
		//RNG must be lvalue, not temporary
		CryptoPP::AutoSeededRandomPool rng;

		std::string decrypted;
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
		if (decrypted.size() != CryptoPP::AES::MAX_KEYLENGTH) {
			throw std::runtime_error("Decrypted AES key must be 32 bytes");
		}
		return decrypted;
	}
	std::string sha256_hex(const std::vector<uint8_t>& data) {
		std::string digest;
		CryptoPP::SHA256 hash;

		CryptoPP::StringSource(
			data.data(),
			data.size(),
			true,
			new CryptoPP::HashFilter(
				hash,
				new CryptoPP::HexEncoder(
					new CryptoPP::StringSink(digest),
					false
				)
			)
		);

		std::transform(digest.begin(), digest.end(), digest.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		return digest;
	}
	bool verify_server_hello_signature(uint8_t security_version,
		const std::array<uint8_t, seftp::proto::kStage7NonceLen>& client_nonce,
		const std::array<uint8_t, seftp::proto::kStage7NonceLen>& server_nonce,
		const std::vector<uint8_t>& server_public_key_der,
		const std::vector<uint8_t>& signature) {

		std::vector<uint8_t> transcript;
		const std::string context = "SEFTP_STAGE7_SERVER_HELLO";

		transcript.insert(transcript.end(), context.begin(), context.end());
		transcript.push_back(security_version);
		transcript.insert(transcript.end(), client_nonce.begin(), client_nonce.end());
		transcript.insert(transcript.end(), server_nonce.begin(), server_nonce.end());
		transcript.insert(transcript.end(), server_public_key_der.begin(), server_public_key_der.end());

		try {
			CryptoPP::RSA::PublicKey publicKey;
			CryptoPP::ArraySource keySource(
				server_public_key_der.data(),
				server_public_key_der.size(),
				true
			);
			publicKey.Load(keySource);
			CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(publicKey);

			return verifier.VerifyMessage(transcript.data(),
				transcript.size(),
				signature.data(),
				signature.size()
				);
		}
		catch (const CryptoPP::Exception& e) {
			return false;
		}
	}

}