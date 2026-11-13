#include "seftp_server/registration_validation.hpp"

#include <utf8proc.h>
#include <algorithm>

namespace seftp::server::application {

    namespace {
        bool is_unicode_alphanumeric(utf8proc_category_t category) {
            return category == UTF8PROC_CATEGORY_LO ||
                   category == UTF8PROC_CATEGORY_LM ||
                   category == UTF8PROC_CATEGORY_LT ||
                   category == UTF8PROC_CATEGORY_LL ||
                   category == UTF8PROC_CATEGORY_LU ||
                   category == UTF8PROC_CATEGORY_NO ||
                   category == UTF8PROC_CATEGORY_NL ||
                   category == UTF8PROC_CATEGORY_ND;
        }
    }

    RegistrationInputResult validate_registration_request(const protocol::RequestFrame& request) {
        if (request.code != protocol::RequestCode::Register) {
            return {RegistrationInputStatus::Malformed, {}};
        }
        bool all_zero = std::all_of(request.client_id.begin(), request.client_id.end(), [](auto c) {
            return c == 0;
        });

        if (!all_zero) {
            return {RegistrationInputStatus::Malformed, {}};
        }

        if (request.payload.empty()) {
            return {RegistrationInputStatus::Malformed, {}};
        }

        if (request.payload.size() == 1 && request.payload.front() == '\0') {
            return {RegistrationInputStatus::InvalidUsername, {}};
        }

        for (std::size_t i = 0; i < request.payload.size()-1; ++i) {
            if (request.payload[i] == '\0') {
                return {RegistrationInputStatus::Malformed, {}};
            }
        }
        if (request.payload.back() != '\0') {
            return {RegistrationInputStatus::Malformed, {}};
        }

        const uint8_t* start_ptr = request.payload.data();
        const uint8_t* ptr = request.payload.data();
        utf8proc_ssize_t remaining_bytes = request.payload.size();

        if (remaining_bytes > 0 && request.payload.back() == '\0') {
            remaining_bytes--;
        }

        int32_t codepoint;
        bool invalid_username = false;
        std::size_t codepoint_counter = 0 ;

        while (remaining_bytes > 0) {
            utf8proc_ssize_t bytes_read = utf8proc_iterate(ptr, remaining_bytes, &codepoint);
            if (bytes_read <= 0) {
                return {RegistrationInputStatus::Malformed, {}};
            }
            const auto category = utf8proc_category(codepoint);
            bool valid_character = is_unicode_alphanumeric(category);

            if (codepoint_counter > 0) {
                valid_character = valid_character ||
                                  codepoint == '.' ||
                                  codepoint == '-' ||
                                  codepoint == '_';
            }
            if (!valid_character) {
                invalid_username = true;
            }

            ++codepoint_counter;

            if (codepoint_counter > 64) {
                invalid_username = true;
            }
            ptr += bytes_read;
            remaining_bytes -= bytes_read;
        }

        if (codepoint_counter == 0 || invalid_username) {
            return {RegistrationInputStatus::InvalidUsername, {}};
        }
        std::string username(reinterpret_cast<const char*>(start_ptr), ptr - start_ptr);
        return {RegistrationInputStatus::Valid, username};
    }

} // namespace seftp::server::application
