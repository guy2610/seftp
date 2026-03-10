#pragma once
#include <string>
#include "../util/files.hpp"

namespace seftp::persistence {

    struct StoredIdentity {
        std::string username;
        std::string client_id;
        std::string public_key_b64;
    };

    bool load_identity(StoredIdentity& out, std::string& error);
    bool save_identity(const StoredIdentity& in, std::string& error);
    bool save_public_key(const std::string& public_key_b64, std::string& error);

    bool load_aes_key(std::string& out, std::string& error);
    bool save_aes_key(const std::string& aes_key_b64, std::string& error);

    bool load_private_key(std::string& out, std::string& error);

}