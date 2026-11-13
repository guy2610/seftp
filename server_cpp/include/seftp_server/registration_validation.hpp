#pragma once

#include "seftp_server/request_frame.hpp"

#include <string>

namespace seftp::server::application {
    enum class RegistrationInputStatus {
        Valid,
        InvalidUsername,
        Malformed,
    };

    struct RegistrationInputResult {
        RegistrationInputStatus status;
        std::string username;
    };

    // Pure validation: returns original UTF-8 username on success; no I/O.
    RegistrationInputResult validate_registration_request(
        const protocol::RequestFrame& request);

} // namespace seftp::server::application
