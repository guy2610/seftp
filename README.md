# Secure File Transfer - C++ Client & Python Server (v0.5.0)

This project implements a simple **secure file transfer protocol** over TCP.

* **Client**: C++ (Boost.Asio, Crypto++)
* **Server**: Python (asyncio, PyCryptodome)
* **Crypto**:

  * RSA-2048 (OAEP) for key exchange
  * AES-256-CBC for file encryption
  * CRC32 for integrity verification

This is an independent engineering project focused on protocol design,
defensive validation, concurrency, and end-to-end reliability.
The system is not intended for production use.

Stage 5 is in progress, with the scalability track completed: upload backpressure, connection limits, and bounded CPU-bound worker execution.

Stages 1-4 completed: protocol hardening, architectural refactor,
async multi-client support, automated testing, CI validation,
client UX improvements, persistence polish, and operational improvements.

The system is functional end-to-end and includes defensive protocol validation, timeouts, and crash-safe persistence.

---

## Version

**v0.5.0 - Stage 5 scalability completed (server concurrency hardening)**

* Upload backpressure with bounded concurrent uploads
* Global and per-IP connection limits
* Rejection and recovery behavior under connection overload
* Bounded executor for CPU-bound upload finalization
* Improved server stability under idle and upload-heavy load
* Added unit and integration tests for connection limiting and concurrency control

**v0.4.0 - Stage 4 complete (Client UX, Persistence & Operational Polish)**

* Interactive console UI with connect / reconnect / status
* Single-file and batch upload modes from the client console
* Headless multi-file upload support via CLI (`--files=...`)
* Extracted client connection / handshake / send flow helpers
* Centralized client persistence layer for identity, AES key, and private key
* Atomic client-side writes for `me.info` and `aes.key`
* Clearer client-side error reporting across connection, handshake, upload, and persistence
* Improved server startup / shutdown behavior and configuration reporting
* Clearer server-side 1607 protocol error messages
* Added client persistence unit tests and atomic write coverage

**v0.3.0 - Stage 3 complete (Testing & Reliability)**

* Fully functional encrypted file transfer (client <-> server)
* Clear separation between protocol parsing, networking, crypto, and flow logic
* Explicit client state management (`ClientContext`)
* Centralized file I/O helpers for identity and key persistence
* Random IV per file (sent in the first `828` packet)
* RSA public key validation (DER, public-only, 2048-bit)
* Stable server-issued `client_id` persisted on client
* Proper `1607` error responses with textual payload
* Fully automated test coverage (unit + integration)
* Async multi-client server with per-connection session isolation (Stage 2.5)
* Async server with concurrent uploads and CPU-bound upload finalization offloaded using a bounded executor
* Graceful disconnect handling and session cleanup
* Idle and upload inactivity timeouts
* Defensive protocol validation for uploads (828)
* Atomic persistence for server state (crash-safe JSON writes)

---

## Prebuilt Client (Windows x64)

A prebuilt Windows x64 client binary is available.

- No build required
- Includes example runtime configuration
- Built in Release mode

Download:
https://github.com/guy2610/Portfolio/releases/tag/v0.4.0-win-x64

Run:
1. Start the server (see below)
2. Extract the zip
3. Edit `transfer.info`
4. Run `SEFFP-CLIENT.exe`

---

## Project Structure

```
client/
  src/
    client_tirgul.cpp
    client_types.hpp
    crypto/
      crypto.hpp
      crypto.cpp
    flow/
      flow.hpp
    net/
      net.hpp
      net.cpp
    persistence/
      client_persistence.hpp
      client_persistence.cpp
    protocol/
      protocol.hpp
    ui/
      console_ui.hpp
      console_ui.cpp
    util/
      util.hpp
      files.hpp
      files.cpp
  transfer.info        # client configuration (host:port, username)

server/
  server_async.py      # asyncio-based multi-client server
  server_tirgul.py     # legacy not in use
  port.info            # server port configuration
  data/
    clients_info.json
    uploads/
      <username>/
        <filename>
  src/
    router.py
    handlers.py
    answers.py
    session.py
    store.py           # JSON persistence; single-process; atomic save on shutdown
    config.py
    framing.py         # TCP stream framing and reassembly
    upload_limiter.py
    connection_limiter.py
    bounded_executor.py

tests/
  client/
    files_test.cpp
    persistence_test.cpp
    logger_test.cpp
    crypto_test.cpp
  server/
    test_answers.py
    test_framing.py
    test_handlers.py
    test_router.py
    test_session.py
    test_store.py
    test_connection_limiter.py
    test_connection_limits_integration.py
    test_bounded_executor.py

protocol/
  spec.md              # full protocol specification
```

---

## Features

* Client registration (`825 -> 1600 / 1601`)
* RSA public key upload & AES-256 key exchange (`826 -> 1602`)
* Re-login using persisted client_id and RSA keys (SSO) (`827 -> 1605 / 1606`)
* Encrypted file upload in fixed-size chunks (`828`)
* CRC validation with retry logic (`900 / 901 / 902 + 1603`)
* Persistent client identity and keys on the client side
* Minimal server-side persistence (`clients_info.json`) with atomic crash-safe writes
* Server-side idle and upload inactivity timeouts
* Strict server-side validation of upload sequencing, size limits, and malformed frames
* Graceful handling of client disconnects and protocol violations
* 1607 error enforcement for protocol violations (invalid headers, limit breaches)
* Interactive console UI with connect / reconnect / status
* Console upload modes: single file and batch
* Headless multi-file uploads via `--files=file1 file2 ...`
* Centralized client persistence abstraction
* Atomic client-side persistence writes
* Server-side logging of client activity and startup configuration
* Clear textual `1607` error enforcement for protocol and server failures
* Upload admission control with bounded concurrent uploads
* Global and per-IP connection limits
* Bounded execution for CPU-bound upload finalization
* Connection overload rejection and recovery behavior
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
  - Supports interactive console mode and headless CLI mode
  - Uses flow helpers for connect / handshake / upload
  - Uses a dedicated persistence layer for me.info / aes.key / priv.key
  - Stores client files with atomic writes

Python server
  - Reads port.info and environment-based runtime limits
  - Listens for TCP client connections
  - Handles registration, SSO, and public key management
  - Generates an AES-256 key per client
  - Receives encrypted file chunks, decrypts, writes file
  - Computes CRC32 and returns result (1603)
  - Logs effective startup configuration
  - Returns clearer 1607 protocol / internal error messages
  - Saves persistent state on graceful shutdown
  - Enforces upload backpressure and connection admission limits
  - Uses a bounded executor for CPU-bound upload finalization
  - Protects the event loop from unbounded CPU-bound work
```

---

## Testing & CI

The project includes automated testing and CI validation.

CI validates:

- Protocol correctness (frame format, codes, payload validation)
- Mandatory 1607 enforcement on invalid 828 headers
- max_file_size limit enforcement
- Parallel client isolation
- End-to-end flow integrity (register -> upload -> CRC)
- Client persistence behavior and atomic file writes
- Connection limit enforcement
- Idle connection rejection and recovery

### Continuous Integration

GitHub Actions:

- Ubuntu E2E workflow
- Windows E2E workflow
- Parallel client validation
- Server restart persistence validation
- Limit enforcement validation (1607 on invalid 828)
- CI fails on protocol violations or missing enforcement

### Unit Tests

- C++ (GoogleTest):
  - Protocol build/parse validation
  - Crypto helpers (AES, RSA key generation, CRC32)
  - Logger module
  - Client persistence round-trip tests
  - Atomic write behavior for client persistence files
- Python (pytest + pytest-asyncio):
  - Router dispatch validation
  - Handlers (825-828, 900-902)
  - 1607 enforcement on invalid 828 headers
  - Connection limiter tests
  - Bounded executor tests

### Integration (E2E) Tests

- Full flow: register -> key exchange -> encrypted upload -> CRC validation
- Re-login scenarios (1605 / 1606)
- Oversize file rejection (server max_file_size via environment)
- Parallel client uploads
- Connection limit enforcement scenarios
- Recovery after rejected connections

---

# Protocol Overview (Short)

### Frame Format

#### Client -> Server (Request)

```
[16 bytes] client_id
[1 byte ] version
[2 bytes] code (little-endian)
[4 bytes] payload_size
[payload]
```
#### Server -> Client (Response)
```
[1 byte ] version
[2 bytes] code (little-endian)
[4 bytes] payload_size
[payload]
```
Notes:
- `client_id` is included only in client requests.
- During initial registration (825), `client_id` is 16 zero bytes.
- Server responses intentionally omit `client_id`.

For the full, authoritative protocol definition, see protocol/spec.md.

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

* packet_number and total_packets are uint16 (max 65535 packets per file) This avoids protocol changes while allowing large files without overflow.
* Client dynamically adjusts chunk size to stay within this limit
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
  Payload format:
  ```
  [16 bytes] client_id
  [UTF-8 string] error_message
  ```


---

## Security Notes

* Uses random AES IV per file (sent in 828 packet_number = 0)
* AES key stored in `aes.key` on client (demo only)
* RSA private key stored in `priv.key`
* No replay protection or authentication
* Server supports multiple concurrent clients (asyncio, single-process, event-loop based concurrency).
  *(Server state is persisted to server/data/clients_info.json using atomic writes on shutdown.)*
* Concurrent uploads are isolated per client
* Server stores uploaded files under data/uploads/<username>/<filename>
* Uploads with identical filenames from different clients do not overwrite each other
* Upload protocol enforces strict packet ordering and size limits
* Malformed or out-of-order uploads are rejected with 1607
* Invalid 828 headers (size mismatch, limit violation, sequencing errors) are rejected with 1607
* Server enforces max_file_size limit (configurable via environment variable)

---

## Server Limits (Environment Variables)

The server enforces defensive runtime limits.  
Defaults can be overridden via environment variables:

- `SEFTP_MAX_FILE_SIZE` (default: 100MB)
- `SEFTP_MAX_PACKETS` (default: 12000)
- `SEFTP_MAX_CHUNK_SIZE` (default: 64KB)
- `SEFTP_MAX_PAYLOAD_SIZE` (default: 10,000,000 bytes)
- `SEFTP_IDLE_TIMEOUT_S` (default: 60)
- `SEFTP_UPLOAD_INACTIVITY_TIMEOUT_S` (default: 20)
- `SEFTP_READ_TIMEOUT_S` (default: 10)
- `SEFTP_LOG_LEVEL` (default: INFO)
- `SEFTP_MAX_CONCURRENT_UPLOADS` (default: 10)
- `SEFTP_MAX_CONNECTIONS` (default: 10)
- `SEFTP_MAX_CONNECTIONS_PER_IP` (default: 10)
- `SEFTP_CPU_WORKER_THREADS` (default: 4)
- `SEFTP_CPU_MAX_IN_FLIGHT` (default: 8)

Violations of size or sequencing constraints result in a `1607` error response.

---

## Requirements

### Server

* Python 3.9+
* PyCryptodome

```
pip install pycryptodome
```

### Client (Build from source)

* C++17 compiler
* CMake 3.21+
* vcpkg
* Boost (via vcpkg)
* Crypto++ (via vcpkg)

---

## Running the Project

### Quickstart

#### Start Server
```
cd server
python server_async.py
```
#### Run Client

Place `transfer.info` in the same directory as the executable, then run:
```
seffp_client.exe
```

The client will:

- Load configuration from transfer.info
- Connect and authenticate with the server
- Start the interactive console UI
- Allow single-file or batch uploads
- Validate CRC and retry if necessary

### Detailed Setup

#### 1. Start the server

```
Prerequisites (persistence)

On startup, the server loads `server/data/clients_info.json` if it exists.
Otherwise it creates the file automatically.

State updates are saved on graceful shutdown (Ctrl+C / process exit).

cd server
python server_async.py
(python server_tirgul.py legacy not in use)
*(server_tirgul.py is kept for reference only and is not maintained.)*
```

#### 2. Prepare client configuration

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
#### Example `transfer.info`

```text
127.0.0.1:1234
Michael Jackson
New_product_spec.docx
```

---

## Client CLI

Optional runtime flags:

- `--info` - run with info-level logs
- `--debug` - enable debug logs
- `--debug=0/1` - explicit debug toggle
- `--files=file1 file2 ...` - upload multiple files without entering the interactive menu (separated by space)

Positional file arguments are also supported for backward compatibility.

### Interactive Console Mode

When no `--files` argument is provided, the client starts in interactive console mode.

Available actions:

- Connect / reconnect
- View connection status
- Send a single file
- Send a batch of files
- Exit cleanly

Interactive batch mode accepts space-separated file paths.


### 3. Build from Source (Windows, CMake + vcpkg)

### Prerequisites

- Visual Studio 2022 (Desktop C++ workload)
- Git
- Python 3.9+ (for server)

### Clone Project
```
To clone only this project without downloading the entire portfolio:
git clone --depth 1 --filter=blob:none --sparse https://github.com/guy2610/Portfolio.git
cd Portfolio
git sparse-checkout init --cone
git sparse-checkout set Secure-Encrypted-File-Transfer-Protocol
cd Secure-Encrypted-File-Transfer-Protocol
```

### Setup vcpkg
```
git clone https://github.com/microsoft/vcpkg
.\vcpkg\bootstrap-vcpkg.bat
```

### Build (Windows, VS2022)
```
cmake --preset vs2022-x64 --fresh
cmake --build --preset release
```

### Run
```
cd build\Release
.\seffp_client.exe
```

### Notes:

- `transfer.info` is automatically copied next to the built executable.

## Roadmap

### **Stage 1 - Security & Protocol Correctness** DONE
Completed

* Random IV per file (AES-256-CBC)
* RSA-2048 public key validation (Base64 DER, public-only)
* Stable server-issued `client_id`
* Proper 1607 error response with payload

---

### **Stage 2 - Architecture & Refactor** DONE  
Client refactor complete, server async refactor, multi-client support, and stabilization complete (up to 2.6.5)

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

**Server (completed):**
* Modular router/handlers/answers
* ClientSession + Store (no global state)
* JSON persistence (startup load / shutdown save)
* Asyncio-based server with per-connection session isolation
* Concurrent multi-client support (single-process, event-loop based)
* Concurrent file uploads with per-client isolation
* CPU-bound upload finalization offloaded using a bounded executor
* User-scoped upload directories to avoid filename collisions
* Pure protocol handlers (no direct socket or transport logic)
* Graceful disconnect handling with disconnect summaries
* Idle and upload inactivity timeouts
* Defensive upload protocol validation for 828 (ordering, consistency, limits)
* Atomic persistence for clients_info.json (temp file + replace)


---

### **Stage 3 - Testing & Reliability** DONE

Completed

* C++ unit tests (GoogleTest)
  - Protocol build/parse
  - AES / RSA helpers
  - CRC validation
* Python async unit tests (pytest + pytest-asyncio)
  - Router dispatch
  - Handlers (825-828, 900-902)
  - 1607 enforcement on invalid 828 headers
* End-to-end integration tests
  - Register -> key exchange -> upload -> CRC validation
  - Re-login flows (1605 / 1606)
  - CRC retry scenarios
  - Oversize file rejection (max_file_size enforcement)
  - Parallel client uploads
* GitHub Actions CI (Ubuntu + Windows)
  - Automated E2E execution
  - Parallel validation
  - Limit enforcement checks
  - Fails on protocol violations

---

### **Stage 4 - Client UX, Persistence & Operational Polish** DONE

Completed

* Client-side console UI
  * Connect / reconnect
  * Status screen
  * Single-file upload
  * Batch upload
* Headless multi-file CLI upload mode
* Extracted client flow helpers for connection, handshake, and upload
* Centralized client persistence abstraction
* Atomic writes for client persistence files
* Clearer client-side error reporting
* Clearer server-side protocol error reporting
* Server startup and shutdown polish
* Additional unit tests for persistence and atomic writes

---

### **Stage 5 - Scalability & Persistence**
Improve server scalability and storage architecture.

* Server concurrency improvements
  * Async multi-client server (DONE)
  * Worker model / bounded executor for CPU-bound tasks (DONE)
  * Connection limits and backpressure (DONE)

* Persistence layer evolution
  * JSON persistence layer (DONE)
  * SQLite persistence layer
  * Client metadata storage
  * Migration from JSON store
  * Separation of runtime session state vs persistent storage
  * Avoid DB access on packet hot path
  * In-memory client index for low-latency lookups
  * Write-through cache for persistent client metadata
  * Keep upload/session transient state in memory


---

### **Stage 6 - Security Hardening**
Additional security protections beyond baseline protocol validation.

* Protocol hardening
  * Payload size and packet limits (DONE)
  * Strong payload validation (DONE)
  * Additional input validation (DONE)
  * Key lifecycle handling

* Abuse protection
  * Connection rate limiting
  * Basic DoS protection

---

### **Stage 7 - Observability & Production Behavior**
Operational visibility and diagnostics.

* Metrics
  * Connection statistics
  * Upload statistics
  * Protocol error counters
* Logging and diagnostics
  * Structured logging (DONE)
  * Request / response tracing

* Runtime behavior
  * Configuration validation (DONE)
  * Runtime configuration reporting (DONE)

---

### **Stage 8 - Extensions & Portfolio Polish**
Future work

* Optional C++ server implementation
* Cross-client communication (relay / messaging)
* Optional GUI client (Qt / ImGui / DearPyGui)
* Documentation & release
  * Full protocol specification
  * Threat model
  * Demo instructions

---