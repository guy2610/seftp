#pragma once
#include <string>
#include <vector>
#include <boost/asio/ip/tcp.hpp>

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