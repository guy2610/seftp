#pragma once
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "../client_types.hpp"

namespace seftp {
    namespace flow {

        bool connect_and_handshake(boost::asio::io_context& io,
            boost::asio::ip::tcp::socket& s,
            boost::asio::ip::tcp::resolver& resolver,
            const seftp::ClientConfig& cfg,
            seftp::ClientContext& cc,
            std::string& out_aes_b64);

        void disconnect_socket(boost::asio::ip::tcp::socket& s);

    }
}