# Secure File Transfer - C++ Client & Python Server (v0.2.0)

This project implements a simple **secure file transfer protocol** over TCP.

* **Client**: C++ (Boost.Asio, Crypto++)
* **Server**: Python (sockets, PyCryptodome)
* **Crypto**:

  * RSA-2048 (OAEP) for key exchange
  * AES-256-CBC for file encryption
  * CRC32 for integrity verification

!!Educational only - not production-grade security!!
Stage 2 focuses on **client-side architecture refactor**, modularization, and explicit flow control.  
The system is functional end-to-end, but not hardened for real-world deployment.

---

## Version

**v0.2.x - Stage 2 (client refactor complete, server refactor + JSON persistence)**

* Fully functional encrypted file transfer (client <-> server)
* Clear separation between protocol parsing, networking, crypto, and flow logic
* Explicit client state management (`ClientContext`)
* Centralized file I/O helpers for identity and key persistence
* Random IV per file (sent in the first `828` packet)
* RSA public key validation (DER, public-only, 2048-bit)
* Stable server-issued `client_id` persisted on client
* Proper `1607` error responses with textual payload
* Manually tested; no automated tests yet


---

## Project Structure

```
client/
  src/
    client_tirgul.cpp
    crypto/
      crypto.hpp
      crypto.cpp
    net/
      net.hpp
      net.cpp
    protocol/
      protocol.hpp
    util/
      util.hpp
      files.hpp
      files.cpp
  transfer.info        # client configuration (host:port, username)

server/
  server_tirgul.py
  port.info            # server port configuration
  data/
    clients_info.json
  src/
    router.py
    handlers.py
    answers.py
    session.py
    store.py           # JSON persistence; single-process; best-effort; no locking/atomic writes
    framing.py
protocol/
  spec.md              # full protocol specification
```

---

## Features

* Client registration (`825 -> 1600 / 1601`)
* RSA public key upload & AES-256 key exchange (`826 -> 1602`)
* Re-login / SSO support (`827 -> 1605 / 1606`)
* Encrypted file upload in fixed-size chunks (`828`)
* CRC validation with retry logic (`900 / 901 / 902 + 1603`)
* Persistent client identity and keys on the client side
* Server-side logging of client activity
* Minimal server-side persistence (clients_info.json)

---

## High-level Architecture

```
C++ client
  - Reads configuration from transfer.info
  - Maintains explicit client state (ClientContext)
  - Handles registration or re-login
  - Receives AES key encrypted with RSA-2048
  - Encrypts files using AES-256-CBC with a random per-file IV
  - Sends encrypted chunks via protocol code 828
  - Verifies CRC and retries on mismatch

Python server
  - Reads port.info and listens on TCP
  - Handles registration, SSO, and public key management
  - Generates an AES-256 key per client
  - Receives encrypted file chunks, decrypts, writes file
  - Computes CRC32 and returns result (1603)
```

---

# Protocol Overview (Short)

### Frame Format

```
[16 bytes] client_id (UUID raw bytes; 0s during first registration)
[1 byte ] version
[2 bytes] code (little-endian)
[4 bytes] payload_size
[payload] depends on code
```

---

## Request Codes (Client -> Server)

### **825 - Register**

Payload:

```
username + '\0'
```

Responses:

* **1600** - success (returns client_id)
* **1601** - failure

---

### **826 - Send RSA Public Key**

Payload:

```
username + '\0' + public_key_b64
```

Response:

* **1602** - AES key encrypted with RSA-OAEP

---

### **827 - Re-login / SSO**

Payload:

```
username + '\0'
```

Responses:

* **1605** - success (AES key sent again)
* **1606** - rejected (unknown user or invalid public key)

---

### **828 - Encrypted File Chunk**

Payload format:

```
uint32  total_cipher_size
uint32  original_plain_size
uint16  packet_number
uint16  total_packets
filename + '\0'
cipher_chunk
```

Purpose:

* Packet 0 carries a 16-byte random IV
* Packets 1..N carry AES-CBC ciphertext chunks
* Server reassembles, decrypts using the IV from packet 0, writes file, returns CRC (1603)
---

### **900 - CRC OK**

Client confirms CRC match.

### **901 - CRC mismatch (retry)**

Client retries sending file.

### **902 - CRC mismatch after 4 retries (give up)**

Client stops retrying.

---

## Response Codes (Server -> Client)

* **1600** - registration success
* **1601** - registration failed
* **1602** - AES key encrypted with RSA
* **1603** - server CRC result
* **1604** - transfer finished
* **1605** - re-login success
* **1606** - re-login rejected
* **1607** - general error

---

## Security Notes

* Uses random AES IV per file (sent in 828 packet_number = 0)
* AES key stored in `aes.key` on client (demo only)
* RSA private key stored in `priv.key`
* No replay protection or authentication
* Server supports only a single client connection
  *(multi-client support planned in a later stage)*
  *(Server state is persisted to server/data/clients_info.json (best-effort).)*


---

## Requirements

### Server

* Python 3.9+
* PyCryptodome

```
pip install pycryptodome
```

### Client

* C++17 compiler
* Boost.Asio
* Crypto++
  Example build:

```
g++ client/src/client_tirgul.cpp -o client -lboost_system -lcryptopp
```

---

## Running the Project

### 1. Start the server

```
Prerequisites (persistence)
- Create: server/data/clients_info.json
- Initialize it with: {}
The server loads this file on startup and saves updates on shutdown (Ctrl+C / process exit).

cd server
python server_tirgul.py
```

### 2. Prepare client configuration

Edit:

```
client/transfer.info
```

Format:

```
127.0.0.1:1256
myuser
file name (not in use)
```
### Example `transfer.info`

```text
127.0.0.1:1234
Michael Jackson
New_product_spec.docx
```
### 3. Build and run the client

```
cd client
g++ src/client_tirgul.cpp -o client -lcryptopp -lws2_32
./client
```
---
### Windows / MSYS2 Build

If you're compiling on Windows using MSYS2 (ucrt64), install Crypto++ and compile using:

```bash
pacman -S mingw-w64-ucrt-x86_64-crypto++
g++ src/client_tirgul.cpp -o client -lcryptopp -lws2_32
```
---

## Roadmap

### **Stage 1 - Security & Protocol Correctness** DONE
Completed

* Random IV per file (AES-256-CBC)
* RSA-2048 public key validation (Base64 DER, public-only)
* Stable server-issued `client_id`
* Proper 1607 error response with payload

---

### **Stage 2 - Architecture & Refactor** DONE  
Client complete, server refactor in progress

**Client (completed):**
* Refactored client into modules:
  * `crypto` - AES, RSA, Base64, CRC helpers
  * `protocol` - request/response framing and parsing
  * `net` - TCP framing and IO
  * `util` - file IO and helpers
* Introduced `ClientContext` as a single source of truth
* Explicit dispatch and flow handling (`DispatchResult`)
* Removed raw protocol codes in favor of enums
* File IO cleanup (`me.info`, `aes.key`, `priv.key`)
* Configuration cleanup (replaced ad-hoc parsing with structured config)

**Server (completed up to 2.3.5):**
* Modular router/handlers/answers
* ClientSession + Store (no global state)
* Pure handlers (no socket logic)
* JSON persistence (startup load / shutdown save)

---

### **Stage 3 - Testing & Reliability**
Planned

* Unit tests:
  * Protocol build/parse
  * Crypto helpers (AES, RSA, CRC)
  * Retry and edge-case logic
* Integration tests:
  * End-to-end register -> upload -> success
  * Re-login flows (1605 / 1606)
  * CRC retry scenarios
* CI setup (Linux + Windows)

---

### **Stage 4 - UX & Productization**
Planned

* Client-side console UI:
  * Connect / reconnect
  * Choose file / batch mode
  * Clear, structured error messages
* Structured logging (levels, client_id, request/response codes)
* Improved configuration system (files + CLI overrides)

---

### **Stage 5 - Scalability & Persistence**
Planned

* Multi-client support:
  * Thread-per-connection or async IO
  * Basic race and isolation testing
* Server-side persistence layer:
  * SQLite or JSON (initially minimal persistence)
  * Client metadata and session storage
* Advanced server-side concurrency and limits

---

### **Stage 6 - Extensions & Portfolio Polish**
Optional / Future work

* Optional C++ server implementation
* Cross-client communication (relay / messaging)
* Optional GUI client (Qt / ImGui / DearPyGui)
* Documentation:
  * Full protocol specification
  * Threat model
  * Usage and demo instructions
