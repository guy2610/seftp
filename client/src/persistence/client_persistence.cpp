#include "client_persistence.hpp"

#include <boost/asio/placeholders.hpp>

namespace seftp::persistence {
	bool load_identity(StoredIdentity& out, std::string& error) {
		error.clear();
		if (!seftp::util::files::read_me_info(out.username, out.client_id, &out.public_key_b64)) {
			error = "failed to load identity from me.info";
			return false;
		}
		return true;
	}
	bool save_identity(const StoredIdentity& in, std::string& error) {
		error.clear();
		if (!seftp::util::files::write_me_identity(in.username, in.client_id)) {
			error = "failed to save identity to me.info";
			return false;
		}
		return true;
	}
	bool save_public_key(const std::string& public_key_b64, std::string& error) {
		error.clear();
		if (!seftp::util::files::write_me_public_key(public_key_b64)) {
			error = "failed to save public key to me.info";
			return false;
		}
		return true;
	}
	bool load_aes_key(std::string& out, std::string& error) {
		error.clear();
		if (!seftp::util::files::read_aes_key(out)) {
			error = "failed to load AES key from aes.key";
			return false;
		}
		return true;
	}
	bool save_aes_key(const std::string& aes_key_b64, std::string& error) {
		error.clear();
		if (!seftp::util::files::write_aes_key(aes_key_b64)) {
			error = "failed to save AES key to aes.key";
			return false;
		}
		return true;
	}
	bool load_private_key(std::string& out, std::string& error) {
		error.clear();
		if (!seftp::util::files::read_private_key(out)) {
			error = "failed to load private key from priv.key";
			return false;
		}
		return true;
	}
	bool load_server_fingerprint(std::string& fingerprint, std::string& error) {
		error.clear();
		if (!seftp::util::files::read_fingerprint(fingerprint)) {
			error = "failed to load server fingerprint";
			return false;
		}
		return true;
	}
	bool save_server_fingerprint(const std::string& fingerprint, std::string& error) {
		error.clear();
		if (!seftp::util::files::write_fingerprint(fingerprint)) {
			error = "failed to save server fingerprint";
			return false;
		}
		return true;
	}
	bool load_server_pin(std::string& fingerprint, std::string& error) {
		error.clear();
		if (!seftp::util::files::read_server_pin(fingerprint)) {
			error = "failed to load server pin";
			return false;
		}
		return true;
	}
}
