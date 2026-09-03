#pragma once

#include <boost/asio/ip/tcp.hpp>
#include "seftp_server/connection_handler.hpp"
#include <variant>

namespace seftp::server::listener {

    struct AcceptFailed {};

    using ListenerResult = std::variant<AcceptFailed, connection_handler::ConnectionResult>;

    inline ListenerResult accept_one_connection(boost::asio::ip::tcp::acceptor &acceptor) {
        boost::asio::ip::tcp::socket socket(acceptor.get_executor());
        boost::system::error_code ec;

        acceptor.accept(socket, ec);

        if (ec) {
            return AcceptFailed{};
        }

        return connection_handler::handle_connection(socket);
    }
}
