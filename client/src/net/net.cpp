#include "net.hpp"
#include <array>

namespace seftp::net {
    static uint16_t read_u16_le(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) |
            (static_cast<uint16_t>(p[1]) << 8);
    }

    static uint32_t read_u32_le(const uint8_t* p) {
        return static_cast<uint32_t>(p[0]) |
            (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) |
            (static_cast<uint32_t>(p[3]) << 24);
    }
    ResponseFrame read_response_frame(tcp::socket& s) {
        // response header is 7 bytes: version(1) + code(2) + payload_size(4)
        std::array<uint8_t, 7> hdr{};
        boost::asio::read(s, boost::asio::buffer(hdr));

        ResponseFrame f{};
        f.version = hdr[0];

        const uint16_t code_u16 = read_u16_le(&hdr[1]);
        f.code = static_cast<seftp::proto::ResCode>(code_u16);
        const uint32_t payload_size = read_u32_le(&hdr[3]);

        f.payload.resize(payload_size);
        
        if (payload_size > 0) {
            boost::asio::read(s, boost::asio::buffer(f.payload.data(), f.payload.size()));
        }
        return f;
    }
}