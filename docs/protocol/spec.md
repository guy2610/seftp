# Secure File Transfer Protocol - Specification (v0.7.0)

This document defines the binary protocol used between the C++ client and the Python server. The protocol provides encrypted file transfer, registration/login flow, CRC validation, and the Stage 7 server-identity handshake.

Status: Stage 7 implemented. This version extends the v0.6.0 protocol with a mandatory server-identity handshake before registration, relogin, key exchange, upload, or CRC completion requests.

---

## 1. Frame Structure

The protocol uses different frame formats for requests and responses.

### Client -> Server (Request)

```text
[ 0..15 ] 16 bytes   client_id       (UUID raw bytes; 0x00..00 on first registration)
[ 16    ] 1 byte     version         (currently always 3)
[ 17..18] 2 bytes    code            (uint16 LE)
[ 19..22] 4 bytes    payload_size    (uint32 LE)
[ 23..  ] payload    (variable)
```

### Server -> Client (Response)
```text
[ 0     ] 1 byte     version         (currently always 3)
[ 1..2  ] 2 bytes    code            (uint16 LE)
[ 3..6  ] 4 bytes    payload_size    (uint32 LE)
[ 7..   ] payload    (variable)
```

### Notes:

* `client_id is` a raw 16-byte UUID in client requests, not a hex string.
* For code `825` (first registration), `client_id` must be all zero bytes.
* Server responses do not include `client_id` in the response header.
* Some response payloads include `client_id` as part of the payload.
* `payload_size` indicates the number of bytes after the header.

---

## 2. Security Handshake (Stage 7)

Before any application-level request (825–902), the client MUST complete the Stage 7 security handshake with the server.

If the handshake is not completed, the server MUST reject all requests with response `1607`.

### 2.1 Handshake Flow

1. Client connects via TCP
2. Client sends `829 CLIENT_HELLO`
3. Server replies with `1608 SERVER_HELLO`
4. Client verifies:
   - server signature
   - server fingerprint
   - TOFU or pinned-key trust requirements
5. Client sends `830 CLIENT_HANDSHAKE_ACK`
6. Server marks the handshake as complete
7. Only after successful handshake completion:
   - client may send requests 825 / 826 / 827 / 828

No fallback to pre-handshake behavior is allowed.

---

### 2.2 Request 829 - CLIENT_HELLO

**Payload:**

```text
uint8   security_version
bytes32 client_nonce
uint8   flags
```
**Notes:**

- MUST be the first request on every connection
- `client_nonce` MUST be randomly generated per connection
- server MUST reject any other request before this
### 2.3 Response 1608 - SERVER_HELLO

**Payload:**

```text
uint8   security_version
bytes32 server_nonce
uint16  server_public_key_len
bytes   server_public_key (DER)
uint16  signature_len
bytes   signature
```

### 2.4 Request 830 - CLIENT_HANDSHAKE_ACK

Direction:

client -> server

Purpose:

Indicates that the client successfully verified the server identity and accepted the handshake.

Payload:

```text
empty
```

Notes:

- MUST be sent only after successful verification of SERVER_HELLO
- MUST be the final step of the Stage 7 handshake
- Any application request received before CLIENT_HANDSHAKE_ACK MUST be rejected

### 2.5 Handshake Signature

The server signs the following transcript:

```text
"SEFTP_STAGE7_SERVER_HELLO" ||
security_version ||
client_nonce ||
server_nonce ||
server_public_key
```

The client verifies the signature using the provided server_public_key.

### 2.6 Trust Model

The protocol supports two trust modes:

#### TOFU (Trust On First Use)

- First connection: client stores server fingerprint
- Subsequent connections: fingerprint must match

#### Pinned Key

- Client is pre-configured with expected server fingerprint
- Mismatch → connection rejected

#### Client Persistence Files

The client uses two local trust files:

```text
server.fingerprint
server.pin
```

If `server.pin` exists, pinned mode is used and the fingerprint must match exactly.

If `server.pin` does not exist, TOFU mode is used. On first successful verification, the client stores the server fingerprint in `server.fingerprint`. On later connections, the stored fingerprint must match.

The client does not create `server.pin` automatically. A pin must be provisioned out-of-band from a trusted source.

### 2.7 Server Fingerprint
```text
SHA-256(server_public_key_der)
```

### 2.8 Enforcement Rules

#### Server

- MUST reject any application-level request before handshake completion
- MUST allow only CLIENT_HELLO and CLIENT_HANDSHAKE_ACK during the handshake phase
- MUST reject malformed handshake with 1607
- MUST enforce handshake completion before processing requests

#### Client

- MUST verify signature
- MUST enforce fingerprint match (TOFU or pinned)
- MUST abort on failure

### 2.9 Replay Protection
- Handshake uses client_nonce and server_nonce
- Signature binds both nonces
- Replay of SERVER_HELLO is rejected due to nonce mismatch

### 2.10 Handshake Completion

The server MUST NOT process application-level requests until a valid
CLIENT_HANDSHAKE_ACK has been received.

Upon receiving a valid CLIENT_HANDSHAKE_ACK:

```text
handshake_verified = true
```

Before handshake completion:

```text
handshake_verified = false
```

Requests 825, 826, 827, 828, 900, 901 and 902 MUST be rejected if the handshake has not completed successfully.

### 2.11 Backward Compatibility

This version does NOT support fallback to pre-handshake protocol.

**Rationale:**

- prevents downgrade attacks
---

## 3. Request Codes (Client -> Server)

### **829 - CLIENT_HELLO**

Starts the Stage 7 security handshake.

See section 2 for full definition.

### **830 - CLIENT_HANDSHAKE_ACK**

Completes the Stage 7 security handshake.

See section 2 for full definition.

### **825 - Register**

Registers a new user.

**Payload:**

```
username + '\0'
```

**Response:**

* `1600` - success, payload = 16-byte client_id
* `1601` - failure (username already exists)

---

### **826 - Upload RSA Public Key**

Client sends RSA-2048 public key in Base64 DER.

**Payload:**

```
username + '\0' + public_key_b64
```

Server:

* Decodes Base64 -> DER (strict)
* Imports RSA key and validates:
* Public key only (private keys rejected)
* Exact size: 2048 bits
* Generates AES-256 key
* Encrypts AES key using RSA-OAEP
* Stores AES key (Base64)

**Response:**

* `1602` - encrypted AES key + client_id

---

### **827 - Re-login / SSO**

Used when `me.info` exists.

**Payload:**

```
username + '\0'
```

**Responses:**

* `1605` - success (AES key re-issued)
* `1606` - rejected

  * If returned client_id = zeros -> user not registered
  * If returned client_id != zeros -> public key invalid

---

### **828 - Encrypted File Chunk**

Transfers an encrypted file in fixed-size chunks.

**Payload Format:**

```
uint32  total_cipher_size
uint32  original_plain_size
uint16  packet_number      (0 = init packet with IV, then 1..total_packets)
uint16  total_packets
filename + '\0'
cipher_chunk
```

Server logic:

1. If packet_number == 0: stores 16-byte IV and resets accumulator
2. Accumulates ciphertext chunks for packets 1..`total_packets`
3. Reconstructs full ciphertext
4. Decrypts with AES-256-CBC using the stored IV
5. Removes padding and trims to `original_plain_size`
6. Writes file to disk
7. Computes CRC32 over plaintext
8. Responds with `1603`

---
#### Validation Rules (Server-side)

The server enforces strict validation for code 828:

- `packet_number = 0` (IV packet) must be received before any data packets
- Packets must arrive strictly in order (`packet_number` increments by 1)
- `total_packets`, `total_cipher_size`, and `original_plain_size` must remain consistent across all packets
- Total received ciphertext must exactly match `total_cipher_size`
- Uploads exceeding configured limits (file size, packet count, chunk size) are rejected
- Any protocol violation results in:
  - `1607` error response
  - Upload state reset
  - The connection may remain open after an error, but the current upload is aborted.
- Note: Timeouts and inactivity limits are server-side policy and are not part of the wire protocol.
---

### **900 - CRC OK**

Client confirms CRC match.

**Payload:**

```
filename + '\0'
```

Server responds:

* `1604` - transfer finished

---

### **901 - CRC mismatch (retry)**

Client indicates mismatch and retries.

**Payload:**

```
filename + '\0'
```

---

### **902 - CRC mismatch after 4 retries**

Client gives up.

**Payload:**

```
filename + '\0'
```

Server responds:

* `1604` - transfer attempt ended

---

## 4. Response Codes (Server -> Client)

### **1608 - SERVER_HELLO**

Returned in response to CLIENT_HELLO.

Contains server identity and signature for handshake verification.

See section 2 for full structure.

### **1600 - Registration Success**

```
16-byte client_id
```

### **1601 - Registration Failure**

No payload.

### **1602 - Bound AES Key Response**

Returned after request `826`.

For `security_version = 1`, the payload is:

```text
client_id              16 bytes
encrypted_key_len      uint16 little-endian
encrypted_key          variable
signature_len          uint16 little-endian
signature              variable
```

The `encrypted_key` contains the server-generated AES key encrypted with the client's RSA public key.

The `signature` is produced by the server identity key over the Stage 7 AES key binding transcript:

```text
"SEFTP_STAGE7_AES_KEY_BINDING" ||
security_version ||
client_nonce ||
server_nonce ||
client_id ||
response_code ||
encrypted_key
```

For `1602`, `response_code = 1602`.

The client MUST verify this signature using the verified Stage 7 server public key before decrypting or saving the AES key.

### **1603 - CRC Result**

```
client_id (16 bytes)
uint32    content_size
filename
uint32    crc_value
```

### **1604 - Transfer Finished**

```
client_id
```

### **1605 - Re-login Success**

Same structure as `1602`.

For `1605`, the AES key binding transcript uses `response_code = 1605`.

### **1606 - Re-login Rejected**

```
client_id
```

Meaning:

* all zeros -> user not registered
* non-zero -> public key invalid

### **1607 - General Error**

Indicates a protocol or logic error.

**Payload:**

```text
client_id (16 bytes)
error_message (UTF-8 string)
```

---

## 5. Cryptography Details

### AES

* AES-256-CBC
* Key: 32 bytes
* IV: 16 random bytes per file (sent in 828 packet_number = 0)

### RSA

* 2048-bit key
* OAEP padding
* Used only to encrypt AES key

### CRC

* CRC32 (zlib / Crypto++)
* Computed on plaintext after decryption

---

## 6. Security Guarantees

With the Stage 7 server-identity handshake implemented:

* Server identity is verified by the client before handshake completion and AES key establishment
* In pinned mode, MITM is prevented from the first connection
* In TOFU mode, MITM is prevented after the first trusted connection
* Replay of handshake messages is mitigated via nonce binding
* Downgrade attacks are mitigated via signed security_version
* Unauthenticated requests are rejected early (1607)
* File contents remain encrypted over the network using AES-256-CBC
* AES key delivery responses (`1602` / `1605`) are signed by the verified server identity key and bound to the Stage 7 handshake nonces
* The client verifies AES key binding before decrypting or persisting the AES key

---

## 7. Known Limitations (v0.7.0)

* TOFU mode is vulnerable to MITM on the first connection
* No certificate-based trust or external CA
* No mutual authentication (client is not authenticated to server cryptographically)
* AES-CBC does not provide authenticated encryption (no AEAD)
* CRC32 is not a cryptographic integrity mechanism
* No forward secrecy (no ephemeral key exchange)
* Client-side keys are stored as plain files (no secure storage)
* No protection against traffic analysis

---

## 8. Future Improvements

* Authenticated encryption
* Deployment-level abuse protection beyond application-level limits
* Resumable uploads
* Stronger local key storage on the client
* Deeper observability and protocol-level diagnostics


