# Secure File Transfer - C++ Client & Python Server (v0.1.0)

This project implements a simple **secure file transfer protocol** over TCP.

* **Client**: C++ (Boost.Asio, Crypto++)
* **Server**: Python (sockets, PyCryptodome)
* **Crypto**:

  * RSA-2048 (OAEP) for key exchange
  * AES-256-CBC for file encryption
  * CRC32 for integrity verification

> !!!Educational only - not production-grade security.!!!
> Some choices (like a fixed IV) are intentional simplifications.

---

## Version

**v0.1.0 - First Working MVP**

* Fully functional end-to-end encrypted file transfer
* Code still kept mostly in single files (minimal refactor)
* Future versions will include modularization, multi-client support, tests, etc.
* This version (v0.1.0) has been **manually tested end-to-end** (registration, SSO, file upload, CRC and retry logic), but there are no automated unit/integration tests yet.

---

## Project Structure

```
client/
  src/
    client_tirgul.cpp
  transfer.info        # client config (host, port, username)

server/
  server_tirgul.py
  port.info            # server port configuration

protocol/
  spec.md              # full protocol specification
```

---

## Features

* Client registration (`825 -> 1600 / 1601`)
* RSA public key upload & AES-256 exchange (`826 -> 1602`)
* Re-login / SSO (`827 -> 1605 / 1606`)
* Encrypted file upload in fixed-size chunks (`828`)
* CRC validation with retry logic (`900 / 901 / 902 + 1603`)
* Server-side logging of client activity

---

## High-level Architecture

```
C++ client
  - Reads config from transfer.info
  - Registers / logs in
  - Receives AES key (encrypted with RSA-2048)
  - Encrypts a chosen file with AES-256-CBC (IV=0)
  - Splits ciphertext into 1024-byte chunks
  - Sends chunks with protocol code 828
  - Compares CRC with server and retries if needed

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

* Client sends encrypted AES-CBC chunks
* Server reassembles, decrypts, writes file, returns CRC (1603)

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

* Uses **fixed AES IV = 0** (insecure for real systems)
* AES key stored in `aes.key` on client (demo only)
* RSA private key stored in `priv.key`
* No replay protection or authentication
* Server supports only a single client connection

**Not intended for production use.**

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

## Roadmap / TODO

* Create header files, add comments, and clean existing code
* Refactor client into modules (crypto, protocol, network)
* Refactor server into modules (remove global state)
* Replace static IV with random IV per file
* Add RSA key validation
* Add unit tests (protocol, CRC, retry logic)
* Add integration tests (end-to-end client <-> server)
* Add structured logging and improved configuration system
* Add multi-client support (threading / asyncio)
* Ensure **1607** error response works properly
* Replace temporary UUID logic with a proper global identifier
* Add a simple client-side console UI (menu for actions: reconnect, choose file, etc.)

### Additional Planned Tasks (Development Order)
1. Add a database layer on the server (SQLite / JSON / Postgres)
2. Implement advanced server-side concurrency for many clients
3. (Optional) Implement a C++ version of the server
4. Implement cross-client communication (client <-> server <-> client)
5. Add optional GUI for the client (Qt / ImGui / Tkinter / DearPyGui)
