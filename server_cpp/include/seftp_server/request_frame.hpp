#pragma once

#include "seftp_server/protocol.hpp"

#include <optional>
#include <vector>
#include <array>
#include <cstdint>

#include "protocol.hpp"


namespace seftp::server::protocol {
    struct RequestFrame {
        std::array<Byte, kClientIdSize> client_id{};
        std::uint8_t version{};
        RequestCode code{};
        std::vector<Byte> payload;
    };

    enum class ParseError {
        IncompleteHeader,
        PayloadSizeMismatch,
        UnknownRequestCode,
        PayloadTooLarge,
    };

    struct ParseResult {
        std::optional<RequestFrame> frame;
        std::optional<ParseError> error;
    };

     inline std::optional<RequestCode> request_code_from_raw(std::uint16_t raw) {
        switch (raw) {
            case static_cast<std::uint16_t>(RequestCode::Register):
                return RequestCode::Register;
            case static_cast<std::uint16_t>(RequestCode::SendPublicKey):
                return RequestCode::SendPublicKey;
            case static_cast<std::uint16_t>(RequestCode::Reconnect):
                return RequestCode::Reconnect;
            case static_cast<std::uint16_t>(RequestCode::Upload):
                return RequestCode::Upload;
            case static_cast<std::uint16_t>(RequestCode::ClientHello):
                return RequestCode::ClientHello;
            case static_cast<std::uint16_t>(RequestCode::ClientHandshakeAck):
                return RequestCode::ClientHandshakeAck;
            default:
                return std::nullopt;
        }
    }
}
