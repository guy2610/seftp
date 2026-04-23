# Secure File Transfer Protocol - Specification (v0.6.0)

This document defines the binary protocol used between the C++ client and the Python server. The protocol provides encrypted file transfer, registration/login flow, and CRC validation for correctness.

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

## 2. Request Codes (Client -> Server)

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

## 3. Response Codes (Server -> Client)

### **1600 - Registration Success**

```
16-byte client_id
```

### **1601 - Registration Failure**

No payload.

### **1602 - AES Key Encrypted With RSA**

```
RSA_ciphertext (256 bytes for RSA-2048)
client_id (16 bytes)
```

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

## 4. Cryptography Details

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

## 5. Known Limitations (v0.2.0)

* Single-process `asyncio` server (multi-client, event-loop based)
* No replay protection or authenticated encryption
* CRC32 is used for transmission integrity only and provides no authenticity or tamper resistance
* Client-side key persistence is file-based and not backed by platform-native secure storage

---

## 6. Future Improvements

* Authenticated encryption
* Rate limiting / abuse protection
* Resumable uploads
* Stronger local key storage on the client
* Deeper observability and protocol-level diagnostics

```
