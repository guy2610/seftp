#pragma once
#include <cstdint>
#include <vector>
#include <boost/asio.hpp>
#include "../protocol/protocol.hpp"

namespace seftp::net {
	using boost::asio::ip::tcp;
	
	struct ResponseFrame {
		uint8_t version = 0;
		seftp::proto::ResCode code = static_cast<seftp::proto::ResCode>(0);
		std::vector<uint8_t> payload;

	};

	ResponseFrame read_response_frame(tcp::socket& s);
	namespace detail {
		constexpr uint32_t kMaxPayload = 128u * 1024u; //128kb

		inline uint16_t read_u16_le(const uint8_t* p) {
			return static_cast<uint16_t>(p[0]) |
				(static_cast<uint16_t>(p[1]) << 8);
		}
		inline uint32_t read_u32_le(const uint8_t* p) {
			return static_cast<uint32_t>(p[0]) |
				(static_cast<uint32_t>(p[1]) << 8) |
				(static_cast<uint32_t>(p[2]) << 16) |
				(static_cast<uint32_t>(p[3]) << 24);
		}
		template <class ReadSomeFn>
		inline void read_exact(ReadSomeFn&& read_some, uint8_t* dst, size_t n) {
			size_t off = 0;
			while (off < n) {
				const size_t got = read_some(dst + off, n - off);
				if (got == 0) throw std::runtime_error("EOF while reading frame");
				off += got;
			}
		}

		template <class ReadSomeFn>
		inline ResponseFrame read_response_frame_from(ReadSomeFn&& read_some) {
			// response header is 7 bytes: version(1) + code(2) + payload_size(4)
			std::array<uint8_t, 7> hdr{};
			read_exact(read_some, hdr.data(), hdr.size());

			ResponseFrame f{};
			f.version = hdr[0];

			const uint16_t code_u16 = read_u16_le(&hdr[1]);
			f.code = static_cast<seftp::proto::ResCode>(code_u16);

			const uint32_t payload_size = read_u32_le(&hdr[3]);
			if (payload_size > kMaxPayload) throw std::runtime_error("payload_size exceeds max");

			f.payload.resize(payload_size);
			if (payload_size > 0) read_exact(read_some, f.payload.data(), f.payload.size());

			return f;
		}
	}
}