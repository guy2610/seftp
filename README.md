# Secure File Transfer - C++ Client & Python Server

Secure File Transfer Protocol, SEFTP, is an independent engineering project that implements encrypted file transfer over a custom binary TCP protocol.

The project is built around a C++ client, a Python asyncio server, strict protocol validation, client-side encryption, server-side persistence, controlled concurrency, and performance analysis.

The system is not intended for production use. It is a portfolio-grade systems project focused on protocol design, networking, cryptography integration, reliability, observability, and maintainability.

---

## Current Status

Current development baseline: v0.9.0-draft

v0.9.0 starts Stage 9 as a focused production-hardening and C++ server foundation stage. Current Stage 9 work includes:

- runtime metric naming cleanup from `protocol_errors_1607` to `responses_1607`
- runtime metrics JSON export
- optional local-only HTTP metrics endpoint for development and benchmark visibility
- tests for metrics export and the HTTP metrics handler
- deployment-level abuse protection and hardening guidance
- planned experimental C++ server foundation

v0.8.0 is the Stage 8 observability checkpoint. It builds on the completed Stage 7 security and streaming-upload baseline with:

- Stage 7-compatible load testing
- per-phase benchmark timing breakdowns
- RSA key-pool support for cleaner upload measurements
- benchmark result comparison tooling
- Stage 8 benchmark plots and Stage 6 vs Stage 8 behavioral comparison plots
- runtime visibility counters for active connections, active uploads, controlled rejections, `1607` responses, and rate-limited requests
- runtime metric snapshots in server disconnect summaries
- documented upload backpressure validation with 10 successful uploads, 40 controlled rejections, and 0 failures under a 50-client load scenario

Stage 7 remains the completed security baseline:
- authenticated server identity verification
- signed server handshake transcript
- TOFU trust model
- optional pinned fingerprint validation
- protocol handshake gating before application requests
- AES key delivery signatures bound to Stage 7 handshake nonces
- key lifecycle hardening for sensitive local files
- application-level abuse protection and rate limiting
- end-to-end streaming upload pipeline for request `828`
- server, client, and E2E test coverage

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
7. The client uploads files through a streaming AES-256-CBC pipeline.
8. The client reads plaintext incrementally, updates CRC32, encrypts with continuous CBC state, and sends request `828` chunks.
9. The server validates ordering, limits, and upload state.
10. The server decrypts chunks incrementally, writes plaintext to a temporary file, computes CRC32, atomically finalizes the upload, and returns the result.
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
        abuse_protection_deployment.md

    tests/
      client/
      server/

---

## Key Capabilities

- first-time client registration
- relogin using persisted client identity
- RSA public-key submission and AES key bootstrap
- streaming encrypted file upload in ordered 828 chunks
- CRC-based completion and retry signaling
- client-side identity and key persistence
- server-side SQLite persistence for clients and uploads
- upload lifecycle states: `in_progress`, `completed`, `crc_mismatch`, `failed`
- in-memory client metadata index for low-latency server lookups
- strict server-side validation and `1607` protocol error responses
- idle and upload inactivity timeouts
- upload admission control and explicit backpressure
- global and per-IP connection limits
- bounded executor infrastructure for controlled CPU-heavy work
- interactive console mode and headless multi-file client mode
- automated unit, integration, and CI validation
- Stage 7 authenticated server-identity handshake
- SHA-256 server fingerprint validation
- TOFU trust model (`server.fingerprint`)
- optional pinned trust mode (`server.pin`)
- signed AES key responses bound to Stage 7 handshake nonces
- end-to-end streaming upload pipeline without full-file plaintext or ciphertext buffering
- Stage 8 benchmark timing breakdowns for connection, handshake, registration, RSA, AES key exchange, upload packet transmission, and CRC confirmation
- RSA key-pool benchmark mode to avoid measuring client-side RSA key generation inside upload workers
- benchmark JSON comparison CLI for before/after performance analysis
- Stage 8 comparison plots for RSA key-pool behavior, upload chunk-size behavior, and Stage 6 vs Stage 8 upload behavior
- server-side runtime visibility counters for active connections, active uploads, rejections, `1607` responses, and rate-limited requests
- runtime metrics snapshots in server disconnect summaries
- optional local-only HTTP metrics endpoint exposing runtime metrics as JSON

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
  - packet `0` carries upload metadata and IV
  - packets `1..N` carry ciphertext chunks
  - implementation streams encryption/decryption while preserving the same 828 wire semantics
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
- `docs/performance/performance_analysis.md` - Stage 6 benchmark findings and post-Stage-7 analysis context
- `docs/performance/stage8_performance_observability.md` - Stage 8 benchmark methodology, timing breakdowns, comparison plots, runtime visibility, and validation notes

Operations:
- `docs/operations/setup_and_usage.md` - detailed setup, runtime configuration, server limits, and client usage
- `docs/operations/abuse_protection_deployment.md` - deployment-level abuse protection and hardening guidance

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

### Protected Docker Compose demo

A minimal protected deployment demo is available under `docker/protected/`. It runs the Python SEFTP server behind an HAProxy TCP proxy and exposes only the proxy port to the host.

```bash
docker compose -f docker/protected/docker-compose.yml build
docker compose -f docker/protected/docker-compose.yml up
```

See `docs/operations/abuse_protection_deployment.md` for details and limitations.

### Optional runtime metrics endpoint

The server can expose a local-only HTTP metrics endpoint for development and benchmark visibility.

```bash
cd server

SEFTP_METRICS_ENABLED=1 \
SEFTP_METRICS_HOST=127.0.0.1 \
SEFTP_METRICS_PORT=9100 \
python3 server_async.py
```

Query the endpoint:

```bash
curl -i http://127.0.0.1:9100/metrics
```

Example response:

```json
{
  "runtime_metrics": {
    "active_connections": 0,
    "active_uploads": 0,
    "rejected_connections": 0,
    "rejected_uploads": 0,
    "responses_1607": 0,
    "rate_limited_requests": 0
  }
}
```

The endpoint is disabled by default and should remain bound to localhost unless protected by deployment-level controls.

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

Stage 7 upload streaming addresses the earlier upload memory-pressure concern by avoiding full-file plaintext and ciphertext buffering on both the client and server while preserving the same 828 wire protocol.

Stage 8 re-established performance observability after the Stage 7 protocol and upload-pipeline changes. It added Stage 7-compatible load testing, per-phase timing breakdowns, RSA key-pool benchmark cleanup, benchmark comparison tooling, generated comparison plots, and server-side runtime visibility counters. The Stage 8 upload backpressure validation showed controlled overload behavior: 50 concurrent upload workers with 10 allowed upload slots produced 10 successful uploads, 40 controlled rejections, and 0 failures.

See:
- `docs/performance/performance_analysis.md`
- `docs/performance/stage8_performance_observability.md`

---

## Security Model

Current v0.7.2 security model:

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
- AES key responses are signed and bound to the Stage 7 handshake transcript
- upload processing uses continuous file-level AES-CBC streaming with one IV per file
- PKCS#7 padding is applied only at end-of-file, not independently per chunk

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
- Stage 7: security hardening and protocol evolution
- Stage 8: performance observability checkpoint

Current / next:
- Stage 9: production hardening and C++ server foundation
- Stage 9 follow-up work: production deployment documentation, executor saturation visibility, queue-depth telemetry, and experimental C++ server skeleton
- Future protocol work: resumable uploads, parallel upload protocol, and chunked AEAD upload redesign

See `docs/roadmap/ROADMAP.md`.

---

## Prebuilt Client

A prebuilt Windows x64 client binary exists for an earlier release, v0.5.0.
Release:
https://github.com/guy2610/Portfolio/releases/tag/v0.5.0-win-x64

See the GitHub Releases page for available binaries.
