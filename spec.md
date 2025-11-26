# Secure File Transfer Protocol - Specification (v0.1.0)

This document defines the binary protocol used between the C++ client and the Python server. The protocol provides encrypted file transfer, registration/login flow, and CRC validation for correctness.

---

## 1. Frame Structure

All messages (client -> server and server -> client) follow this binary format:

```
[ 0..15 ] 16 bytes   client_id       (UUID raw bytes; 0x00..00 on first registration)
[ 16    ] 1 byte     version         (currently always 3)
[ 17..18] 2 bytes    code            (uint16 LE)
[ 19..22] 4 bytes    payload_size    (uint32 LE)
[ 23..  ] payload    (variable)
```

### Notes:

* `client_id` is raw 16-byte UUID (not hex string).
* For code `825` (first registration), `client_id` must be all zero bytes.
* `payload_size` indicates number of bytes after the header.

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

* Decodes Base64 -> DER
* Imports RSA key
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
uint16  packet_number      (1-based)
uint16  total_packets
filename + '\0'
cipher_chunk
```

Server logic:

1. Accumulates chunks until `packet_number == total_packets`
2. Reconstructs full ciphertext
3. Decrypts with AES-256-CBC (IV = 0x00..00)
4. Removes padding and trims to `original_plain_size`
5. Writes file to disk
6. Computes CRC32 over plaintext
7. Responds with `1603`

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

Indicates protocol/logic error.
Payload unspecified in v0.1.0.

---

## 4. Cryptography Details

### AES

* AES-256-CBC
* Key: 32 bytes
* IV: 16 zero bytes (insecure; for assignment only)

### RSA

* 2048-bit key
* OAEP padding
* Used only to encrypt AES key

### CRC

* CRC32 (zlib / Crypto++)
* Computed on plaintext after decryption

---

## 5. Known Limitations (v0.1.0)

* Single-client server (no concurrency)
* Static AES IV = 0
* No replay protection or authentication
* No database
* Minimal handling of error code `1607`

---

## 6. Future Improvements

* Random IV per file
* HMAC or authenticated encryption
* Multi-client support
* Database-backed client management
* Stronger error handling

```
