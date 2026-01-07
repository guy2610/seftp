#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace seftp::proto {

	constexpr uint8_t kVersion = 3;
	constexpr size_t kClientIdLen = 16;

	constexpr size_t kReqHeaderLen = 16 + 1 + 2 + 4; // 23
	constexpr size_t kResHeaderLen = 1 + 2 + 4;      // 7

	using ClientId = std::array<uint8_t, kClientIdLen>;

	enum class ReqCode : uint16_t {
		Register = 825,
		PublicKey = 826,
		ReLogin = 827,
		FileChunk = 828,
		CrcOk = 900,
		CrcRetry = 901,
		CrcFail = 902,
	};

	enum class ResCode : uint16_t {
		RegisterOk = 1600,
		RegisterFail = 1601,
		AesKey = 1602,
		CrcResult = 1603,
		TransferDone = 1604,
		ReloginOk = 1605,
		ReloginFail = 1606,
		Error = 1607,
	};
	//----little-endian helpers


	inline void append_u8(std::vector<uint8_t>& b, uint8_t v) { b.push_back(v); }

	inline void append_u16_le(std::vector<uint8_t>& b, uint16_t v) {
		b.push_back(static_cast<uint8_t>(v & 0xFF));
		b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
	}

	inline void append_u32_le(std::vector<uint8_t>& b, uint32_t v) {
		b.push_back(static_cast<uint8_t>(v & 0xFF));
		b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
		b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
		b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
	}

	inline uint16_t read_u16_le(const uint8_t* p) {
		return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
	}

	inline uint32_t read_u32_le(const uint8_t* p) {
		return static_cast<uint32_t>(p[0]) |
			(static_cast<uint32_t>(p[1]) << 8) |
			(static_cast<uint32_t>(p[2]) << 16) |
			(static_cast<uint32_t>(p[3]) << 24);
	}

	//---ClientId helpers

	inline ClientId zero_client_id() {
		ClientId z{};
		z.fill(0);
		return z;
	}
	inline ClientId parse_client_id_hex32(std::string_view hex32) {
		if (hex32.size() != 32)
			throw std::invalid_argument("client_id must be exactly 32 hex characters");

		auto hexval = [](char c)-> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
			if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
			return -1;
			};
		ClientId out = {};
		for (size_t i = 0; i < 16; i++)
		{
			int hi = hexval(hex32[i * 2]);
			int lo = hexval(hex32[i * 2 + 1]);
			if (hi < 0 || lo < 0) throw std::invalid_argument("client_id contains non-hex characters");
			out[i] = static_cast<uint8_t>((hi << 4) | lo);
		}
		return out;
	}

	//-----Frame builders

	//Generic request: client_id(16) + version(1) + code(2) + payload_size(4) + payload
	inline std::vector<uint8_t> build_request(const ClientId& client_id, ReqCode code, const std::vector<uint8_t>& payload, uint8_t version = kVersion) {
		std::vector<uint8_t> msg;
		msg.reserve(kReqHeaderLen + payload.size());
		msg.insert(msg.end(), client_id.begin(), client_id.end());
		append_u8(msg, version);
		append_u16_le(msg, static_cast<uint16_t>(code));
		append_u32_le(msg, static_cast<uint32_t>(payload.size()));
		msg.insert(msg.end(), payload.begin(), payload.end());
		return msg;
	}

	inline std::vector<uint8_t> make_cstr_payload(std::string_view s) {
		std::vector<uint8_t> p;
		p.reserve(s.size() + 1);
		p.insert(p.end(), s.begin(), s.end());
		p.push_back('\0');
		return p;
	}

	// 825: payload = username + '\0' , client_id = 16 zeros
	inline std::vector<uint8_t> build_825_register(std::string_view username) {
		return build_request(zero_client_id(), ReqCode::Register, make_cstr_payload(username));
	}

	// 827: payload = username + '\0' , client_id = existing
	inline std::vector<uint8_t> build_827_relogin(const ClientId& client_id, std::string_view username) {
		return build_request(client_id, ReqCode::ReLogin, make_cstr_payload(username));
	}

	// 900/901/902: payload=filename +'\0'
	inline std::vector<uint8_t> build_900_crc_ok(const ClientId& client_id, std::string_view filename) {
		return build_request(client_id, ReqCode::CrcOk, make_cstr_payload(filename));
	}
	inline std::vector<uint8_t> build_901_crc_retry(const ClientId& client_id, std::string_view filename) {
		return build_request(client_id, ReqCode::CrcRetry, make_cstr_payload(filename));
	}
	inline std::vector<uint8_t> build_902_crc_fail(const ClientId& client_id, std::string_view filename) {
		return build_request(client_id, ReqCode::CrcFail, make_cstr_payload(filename));
	}

	// 826: payload = username + '\0' + publicKeyB64 (no trailing '\0')
	inline std::vector<uint8_t> build_826_public_key(const ClientId& client_id,
		std::string_view username,
		std::string_view public_key_b64) {
		std::vector<uint8_t> p;
		p.reserve(username.size() + 1 + public_key_b64.size());
		p.insert(p.end(), username.begin(), username.end());
		p.push_back('\0');
		p.insert(p.end(), public_key_b64.begin(), public_key_b64.end());
		return build_request(client_id, ReqCode::PublicKey, p);
	}

	// 828 packet layout:
	// payload = total_cipher_size(4) + orig_plain_size(4) + packet_no(2) + total_packets(2) + filename('\0') + data
	// packet 0: data = 16 bytes IV
	// packet N: data = ciphertext chunk bytes
	inline std::vector<uint8_t> build_828_packet0_iv(const ClientId& client_id,	uint32_t total_cipher_size, uint32_t orig_plain_size, uint16_t total_packets, std::string_view filename, const std::array<uint8_t,16>& iv) {
		std::vector<uint8_t> p;
		p.reserve(4 + 4 + 2 + 2 + filename.size() + 1 + 16);
		append_u32_le(p, total_cipher_size);
		append_u32_le(p, orig_plain_size);
		append_u16_le(p, 0);
		append_u16_le(p, total_packets);
		p.insert(p.end(), filename.begin(), filename.end());
		p.push_back('\0');
		p.insert(p.end(), iv.begin(), iv.end());
		return build_request(client_id, ReqCode::FileChunk, p);
	}
	inline std::vector<uint8_t> build_828_packet_chunk(const ClientId& client_id, uint32_t total_cipher_size, uint32_t orig_plain_size, uint16_t packet_num, uint16_t total_packets, std::string_view filename, const std::vector<uint8_t>& chunk) {
		if (packet_num == 0) throw std::invalid_argument("packet_num must be >= 1 for chunk packets");
		std::vector<uint8_t> p;
		p.reserve(4 + 4 + 2 + 2 + filename.size() + 1 + chunk.size());
		append_u32_le(p, total_cipher_size);
		append_u32_le(p, orig_plain_size);
		append_u16_le(p, packet_num);
		append_u16_le(p, total_packets);
		p.insert(p.end(), filename.begin(), filename.end());
		p.push_back('\0');
		p.insert(p.end(), chunk.begin(), chunk.end());
		return build_request(client_id, ReqCode::FileChunk, p);
	}

	struct ResHeader
	{
		uint8_t version = 3;
		uint16_t code_le = 0;
		uint32_t payload_size_le = 0;

		ResCode code() const { return static_cast <ResCode>(code_le); }
		uint32_t payload_size() const { return payload_size_le; }
	};

	inline ResHeader parse_res_header_7(const uint8_t* hdr7) {
		ResHeader h;
		h.version = hdr7[0];
		h.code_le = read_u16_le(&hdr7[1]);
		h.payload_size_le = read_u32_le(&hdr7[3]);
		return h;
	}


}