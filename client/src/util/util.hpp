#pragma once
#include <string_view>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include "../protocol/protocol.hpp"
namespace seftp::util {

	inline seftp::proto::ClientId parse_client_id_hex32(std::string_view hex32) {
		if (hex32.size() != 32)
			throw std::invalid_argument("client_id must be exactly 32 hex characters");

		auto hexval = [](char c)-> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
			if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
			return -1;
			};
		seftp::proto::ClientId out = {};
		for (size_t i = 0; i < 16; i++)
		{
			int hi = hexval(hex32[i * 2]);
			int lo = hexval(hex32[i * 2 + 1]);
			if (hi < 0 || lo < 0) throw std::invalid_argument("client_id contains non-hex characters");
			out[i] = static_cast<uint8_t>((hi << 4) | lo);
		}
		return out;
	}
	static std::string client_id_to_hex(const seftp::proto::ClientId& cid)
	{
		std::ostringstream oss;
		oss << std::hex << std::setfill('0');
		for (uint8_t b : cid) oss << std::setw(2) << (int)b;
		return oss.str();
	}

	static std::vector<uint8_t> client_id_to_vec(const seftp::proto::ClientId& cid)
	{
		return std::vector<uint8_t>(cid.begin(), cid.end());
	}

}