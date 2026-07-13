#pragma once

#include "seftp_server/protocol.hpp"

#include <optional>
#include <vector>
#include <array>
#include <cstdint>



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

    inline ParseResult parse_request_frame(const std::vector<Byte>& bytes) {
         if (bytes.size() < kRequestHeaderSize) {
             return {std::nullopt, ParseError::IncompleteHeader};
         }

         RequestFrame frame;
         std::size_t offset = 0;

         std::copy_n(
             bytes.begin(),
             kClientIdSize,
             frame.client_id.begin()
         );
         offset += kClientIdSize;

         frame.version = bytes[offset];
         offset += kVersionSize;

         const std::uint16_t raw_code =
             static_cast<std::uint16_t>(bytes[offset]) |
             (static_cast<std::uint16_t>(bytes[offset + 1]) << 8);

         offset += kCodeSize;

         const auto code = request_code_from_raw(raw_code);
         if (!code.has_value()) {
             return {std::nullopt, ParseError::UnknownRequestCode};
         }

         frame.code = code.value();

         std::uint32_t payload_size = 0;

         for (std::size_t i = 0; i < kPayloadSizeFieldSize; ++i) {
             payload_size |=
                 static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
         }

         offset += kPayloadSizeFieldSize;

         const std::size_t expected_size =
             kRequestHeaderSize + static_cast<std::size_t>(payload_size);

         if (bytes.size() != expected_size) {
             return {std::nullopt, ParseError::PayloadSizeMismatch};
         }

         frame.payload.assign(bytes.begin() + offset, bytes.end());

         return {std::move(frame), std::nullopt};
     }
}
