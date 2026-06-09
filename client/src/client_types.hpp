#pragma once
#include <string>
#include <vector>
#include <boost/asio/ip/tcp.hpp>
#include "protocol/protocol.hpp"

namespace seftp {

    using tcp = boost::asio::ip::tcp;

    struct ClientContext {
        std::string client_id;
        std::string username;
        std::string aes_key_b64;
        bool logged_in_or_has_aes = false;
        bool need_register = false;
        bool send_public_key = false;
        std::string last_error_text;
        uint8_t security_version = 0;
        std::array<uint8_t, seftp::proto::kStage7NonceLen> client_nonce{};
        std::array<uint8_t, seftp::proto::kStage7NonceLen> server_nonce{};
        bool stage7_handshake_complete = false;
        std::vector<uint8_t> server_public_key_der;
    };

    struct ClientConfig {
        std::string host;
        std::string port;
        std::string username;
    };

    enum class NextStep { None, NeedRegister, NeedSendPublicKey, Fatal };

    struct DispatchResult {
        NextStep step = NextStep::None;
        bool updated_client_id = false;
    };

}