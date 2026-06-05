# Secure File Transfer - C++ Client & Python Server

Secure File Transfer Protocol, SEFTP, is an independent engineering project that implements encrypted file transfer over a custom binary TCP protocol.

The project is built around a C++ client, a Python asyncio server, strict protocol validation, client-side encryption, server-side persistence, controlled concurrency, and performance analysis.

The system is not intended for production use. It is a portfolio-grade systems project focused on protocol design, networking, cryptography integration, reliability, observability, and maintainability.

---

## Current Status

Current stable baseline: v0.7.0

v0.7.0 completed the Stage 7 core handshake:
- authenticated server identity verification
- signed server handshake transcript
- TOFU trust model
- optional pinned fingerprint validation
- protocol handshake gating
- server, client, and E2E test coverage

Stage 7 remains active for broader hardening work:
- key lifecycle improvements
- stronger local key storage
- upload streaming pipeline evolution
- abuse protection and rate limiting

See:
- `docs/roadmap/ROADMAP.md`
- `docs/roadmap/CHANGELOG.md`

---

## Why This Project Matters

This project demonstrates several backend and systems engineering concerns in one end-to-end system:

- custom binary protocol design
- C++ networking client using Boost.Asio
- Python asyncio server with per-connection session isolation
- RSA-based AES key bootstrap
- authenticated server identity verification with TOFU and pinned trust modes
- AES-256-CBC encrypted file transfer
- CRC-based upload completion flow
- strict malformed-frame validation
- SQLite-backed server persistence
- upload lifecycle tracking
- explicit connection limits and upload backpressure
- load testing, resource sampling, and bottleneck analysis

---

## Technology Stack

Client:
- C++17
- Boost.Asio
- Crypto++
- CMake
- GoogleTest

Server:
- Python
- asyncio
- PyCryptodome
- SQLite
- pytest

Protocol / crypto:
- custom binary TCP protocol
- Stage 7 authenticated server-identity handshake
- RSA-2048 server identity signatures (PKCS#1 v1.5 + SHA-256)
- RSA-2048 OAEP for AES key delivery
- AES-256-CBC for file encryption
- CRC32 for transfer validation
- TOFU and optional pinned fingerprint trust models

---

## Architecture at a Glance

High-level flow:

1. The client loads local configuration and identity material.
2. The client connects to the server over TCP.
3. The client performs the Stage 7 server-identity handshake.
4. The client validates the server signature and trust model.
5. The client performs registration or relogin.
6. The server issues an AES key encrypted with the client's RSA public key.
7. The client encrypts files locally using AES-256-CBC.
8. The client uploads encrypted chunks through request `828`.
9. The server validates ordering, limits, and upload state.
10. The server decrypts, stores the file, computes CRC32, and returns the result.
11. The client confirms the CRC result through `900`, `901`, or `902`.

Main design boundary:

- client owns local identity, encryption, request construction, and upload initiation
- server owns protocol validation, resource control, persistence, and upload finalization
- protocol spec defines the shared binary contract between both sides

---

## Project Structure

    client/
      src/
        client_main.cpp
        client_types.hpp
        crypto/
        flow/
        net/
        persistence/
        protocol/
        ui/
        util/
      transfer.info

    server/
      server_async.py
      port.info
      src/
        router.py
        handlers.py
        answers.py
        session.py
        store.py
        config.py
        framing.py
        upload_limiter.py
        connection_limiter.py
        bounded_executor.py
      data/
        seftp_server_sql.db
        uploads/

    docs/
      architecture/
        system_design.md
        client_design.md
        server_design.md
      protocol/
        spec.md
        protocol_extension_design.md
      performance/
        performance_analysis.md
      roadmap/
        ROADMAP.md
        CHANGELOG.md
        stage5_backpressure_notes.md
        stage7_threat_model.md
      operations/
        setup_and_usage.md

    tests/
      client/
      server/

---

## Key Capabilities

- first-time client registration
- relogin using persisted client identity
- RSA public-key submission and AES key bootstrap
- encrypted file upload in ordered chunks
- CRC-based completion and retry signaling
- client-side identity and key persistence
- server-side SQLite persistence for clients and uploads
- upload lifecycle states: `in_progress`, `completed`, `crc_mismatch`, `failed`
- in-memory client metadata index for low-latency server lookups
- strict server-side validation and `1607` protocol error responses
- idle and upload inactivity timeouts
- upload admission control and explicit backpressure
- global and per-IP connection limits
- bounded executor for CPU-heavy upload finalization
- interactive console mode and headless multi-file client mode
- automated unit, integration, and CI validation
- Stage 7 authenticated server-identity handshake
- SHA-256 server fingerprint validation
- TOFU trust model (`server.fingerprint`)
- optional pinned trust mode (`server.pin`)

---

## Protocol Summary

Client request frame:

    [16 bytes] client_id
    [1 byte ] version
    [2 bytes] code, little-endian
    [4 bytes] payload_size
    [payload]

Server response frame:

    [1 byte ] version
    [2 bytes] code, little-endian
    [4 bytes] payload_size
    [payload]

Stage 7 handshake:
- `829` CLIENT_HELLO
- `1608` SERVER_HELLO
- `830` CLIENT_HANDSHAKE_ACK

ֿMain request codes:
- `825` register
- `826` upload RSA public key and receive AES key
- `827` relogin
- `828` encrypted file chunk
- `900` CRC OK
- `901` CRC mismatch, retry
- `902` CRC mismatch, stop

Main response codes:
- `1600` registration success
- `1601` registration failure
- `1602` AES key encrypted with RSA
- `1603` server CRC result
- `1604` transfer finished
- `1605` relogin success
- `1606` relogin rejected
- `1607` protocol or server error

For the detailed protocol definition and Stage 7 draft evolution, see:
- `docs/protocol/spec.md`
- `docs/protocol/protocol_extension_design.md`

---

## Documentation

Architecture:
- `docs/architecture/system_design.md` - full system architecture
- `docs/architecture/client_design.md` - client internals
- `docs/architecture/server_design.md` - server internals

Protocol:
- `docs/protocol/spec.md` - protocol specification including the implemented Stage 7 handshake
- `docs/protocol/protocol_extension_design.md` - Stage 7 handshake design and implementation notes

Performance:
- `docs/performance/performance_analysis.md` - Stage 6 benchmark findings

Operations:
- `docs/operations/setup_and_usage.md` - detailed setup, runtime configuration, server limits, and client usage

Roadmap:
- `docs/roadmap/ROADMAP.md` - completed and planned stages
- `docs/roadmap/CHANGELOG.md` - version history
- `docs/roadmap/stage7_threat_model.md` - Stage 7 threat model
- `docs/roadmap/stage5_backpressure_notes.md` - historical Stage 5 backpressure note

---

## Running the Project

### Start the server

    cd server
    python3 server_async.py

The server initializes SQLite storage under `server/data/` if needed.

### Prepare client configuration

Edit:

    client/transfer.info

Format:

    127.0.0.1:1234
    myuser
    optional_file_path

### Run the client

After building the client, run the executable from the build output directory.

Interactive mode starts when no file arguments are provided.

Headless multi-file mode:

    ./seftp_client --files=file1.txt file2.txt

---

## Build From Source

Requirements:
- C++17 compiler
- CMake 3.21+
- vcpkg
- Boost
- Crypto++
- Python 3.9+

Windows example:

    cmake --preset vs2022-x64 --fresh
    cmake --build --preset release

macOS example:

    cmake --preset macos-arm64 --fresh
    cmake --build --preset macos-release

---

## Testing

Server tests:

    python3 -m pytest

Client tests are implemented with GoogleTest and run through the CMake build/test setup.

CI validates:
- protocol correctness
- invalid-frame rejection
- end-to-end register, key exchange, upload, and CRC flow
- relogin behavior
- parallel client isolation
- SQLite persistence
- connection limit behavior
- upload backpressure behavior

---

## Performance Findings

Stage 6 introduced benchmark tooling and performance analysis.

Main findings:
- upload is the dominant cost path
- register and relogin behave more like lighter control-plane operations
- upload capacity is affected by both concurrency and file size
- explicit upload backpressure prevents uncontrolled overload
- larger files increase RSS and CPU pressure more sharply
- mixed workloads are primarily constrained by upload pressure

See `docs/performance/performance_analysis.md`.

---

## Security Model

Current v0.7.0 security model:

- authenticated server identity verification before AES key establishment
- signed Stage 7 handshake transcript
- TOFU trust model through `server.fingerprint`
- optional pinned trust mode through `server.pin`
- AES keys delivered encrypted under the client RSA public key
- files encrypted client-side before upload
- fresh AES IV per file
- malformed protocol flows rejected with `1607`
- application requests rejected before handshake completion
- uploaded files validated through CRC32 completion flow

Known limitations:

- TOFU is vulnerable on first connection
- no certificate authority or PKI
- AES-CBC does not provide authenticated encryption
- CRC32 is not a cryptographic authentication mechanism
- client-side keys are stored as local files
- no forward secrecy
- no mutual authentication

---

## Roadmap Snapshot

Completed:
- Stage 1: security and protocol correctness
- Stage 2: architecture and refactor
- Stage 3: testing and reliability
- Stage 4: client UX, persistence, and operational polish
- Stage 5: scalability and persistence
- Stage 6: performance analysis, observability, and design documentation

Active:
- Stage 7: security hardening and protocol evolution

Future:
- Stage 8: observability and production behavior
- Stage 9: extensions and portfolio polish

See `docs/roadmap/ROADMAP.md`.

---

## Prebuilt Client

A prebuilt Windows x64 client binary exists for an earlier release, v0.5.0.
Release:
https://github.com/guy2610/Portfolio/releases/tag/v0.5.0-win-x64

See the GitHub Releases page for available binaries.
