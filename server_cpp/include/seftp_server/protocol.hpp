#pragma once

#include <cstddef>
#include <cstdint>

namespace seftp::server::protocol {

    using Byte = std::uint8_t;
    using RequestCodeRaw = std::uint16_t;
    using ResponseCodeRaw = std::uint16_t;

    inline constexpr std::size_t kClientIdSize = 16;
    inline constexpr std::size_t kVersionSize = 1;
    inline constexpr std::size_t kCodeSize = 2;
    inline constexpr std::size_t kPayloadSizeFieldSize = 4;

    inline constexpr std::size_t kRequestHeaderLen = kClientIdSize + kVersionSize + kCodeSize + kPayloadSizeFieldSize; // 23
    inline constexpr std::size_t kResponseHeaderLen = kVersionSize + kCodeSize + kPayloadSizeFieldSize; //7

    inline constexpr std::size_t kDefaultMaxFileSize = 100 * 1024 * 1024; //100MB

    enum class ReqCode : std::uint16_t {
        Register = 825,
        SendPublicKey = 826,
        Reconnect = 827,
        Upload = 828,
        ClientHello = 829,
        ClientHandshakeAck = 830
    };

    enum class ResCode : uint16_t {
        RegistrationOk = 1600,
        RegistrationFailed = 1601,
        PublicKeyAccepted = 1602,
        CrcOk = 1603,
        MessageReceived = 1604,
        ReconnectOk = 1605,
        ReconnectRejected = 1606,
        ServerError = 1607,
        ServerHello = 1608,
        CrcRetry = 900,
        CrcFinalFailure = 901,
        CrcFatalFailure = 902,
    };
}