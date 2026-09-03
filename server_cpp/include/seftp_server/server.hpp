#pragma once
#include <boost/asio/ip/tcp.hpp>

#include "seftp_server/listener.hpp"
#include <variant>

namespace seftp::server {
    enum class ServerResult {
        AcceptFailed,
    };

    inline ServerResult run_server(boost::asio::ip::tcp::acceptor &acceptor) {
        while (true) {
            const auto result = listener::accept_one_connection(acceptor);
            if (std::holds_alternative<listener::AcceptFailed>(result)) {
                return ServerResult::AcceptFailed;
            }

        }
    }
}
