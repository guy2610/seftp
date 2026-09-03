#pragma once

#include "seftp_server/protocol.hpp"

#include <cstddef>
#include <vector>
#include <cstdint>

#include "protocol.hpp"


namespace seftp::server::protocol {
    struct ResponseFrame {
        std::uint8_t version{};
        ResponseCode code{};
        std::vector<Byte> payload{};
    };

    inline std::vector<Byte> build_response_frame(const ResponseFrame& frame) {

        std::vector<Byte> bytes;
        bytes.reserve(static_cast<std::size_t>(kResponseHeaderSize) + frame.payload.size());

        bytes.push_back(frame.version);

        const auto raw_code = static_cast<uint16_t>(frame.code);

        bytes.push_back(static_cast<Byte>(raw_code & 0xFF));
        bytes.push_back(static_cast<Byte>((raw_code >> 8) & 0xFF));

        const auto payload_size = static_cast<std::uint32_t>(frame.payload.size());

        for (std::size_t i = 0; i < kPayloadSizeFieldSize; ++i) {
            bytes.push_back(static_cast<Byte>((payload_size >>(8*i)) & 0xFF));
        }

        bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());

        return bytes;
    }
}
