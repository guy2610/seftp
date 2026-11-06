#pragma once

#include "seftp_server/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

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

        const auto raw_code = static_cast<std::uint32_t>(frame.code);

        bytes.push_back(static_cast<Byte>(raw_code & 0xFFu));
        bytes.push_back(static_cast<Byte>((raw_code >> 8u) & 0xFFu));

        const auto payload_size = static_cast<std::uint32_t>(frame.payload.size());

        for (std::size_t i = 0; i < kPayloadSizeFieldSize; ++i) {
            bytes.push_back(static_cast<Byte>((payload_size >> (8u * i)) & 0xFFu));
        }

        bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());

        return bytes;
    }
} // namespace seftp::server::protocol
