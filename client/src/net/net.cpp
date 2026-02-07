#include "net.hpp"
#include <array>

namespace seftp::net {
    ResponseFrame read_response_frame(tcp::socket& s) {
        auto read_some = [&](uint8_t* dst, size_t n) -> size_t {
            boost::system::error_code ec;
            const size_t got = s.read_some(boost::asio::buffer(dst, n), ec);

            if (ec) {
                if (ec == boost::asio::error::eof) return 0;
                throw boost::system::system_error(ec);
            }
            return got;
            };
        return detail::read_response_frame_from(read_some);
    }
}