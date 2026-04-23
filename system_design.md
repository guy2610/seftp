# System Design

## 1. Purpose and Scope

This project implements a secure file transfer system composed of a C++ client and a Python `asyncio` server communicating over a custom binary TCP protocol. The system is designed to support registration, relogin, key exchange, encrypted file upload, CRC-based completion, and durable server-side metadata tracking.

The implementation focuses on protocol correctness, cryptographic separation of responsibilities, explicit persistence boundaries, controlled resource usage, and architecture clarity. It is intended as a serious engineering project rather than a production deployment.

The current scope includes:
- a C++ client for connection, handshake, encryption, upload, and local persistence
- a Python `asyncio` server for request handling, validation, upload finalization, and metadata persistence
- a custom binary request/response protocol
- RSA-based key bootstrap and AES-based file encryption
- chunked encrypted file upload
- CRC-based integrity confirmation
- server-side SQLite persistence
- local client identity and key persistence
- observability and benchmarking tooling

The current scope does not include:
- distributed deployment
- multi-node coordination
- resumable uploads across reconnects
- platform-native secure key storage
- GUI-based operation
- a production-grade authentication and authorization model beyond the implemented protocol flows

## 2. System Overview

At a high level, the client loads runtime configuration and local identity material, connects to the server, and executes either registration or relogin. The server validates the request, establishes or restores client identity, and delivers a server-generated AES key encrypted under the client's RSA public key. The client decrypts that AES key locally, encrypts files before transport, and uploads ciphertext in protocol-compliant chunks. The server reassembles and decrypts the upload, writes the plaintext file to disk, computes CRC32, and uses a final CRC exchange to conclude the upload lifecycle.

This creates a clear end-to-end separation:
- the client owns local identity, local encryption, and upload initiation
- the server owns protocol enforcement, upload admission, finalization, and durable metadata

## 3. High-Level Architecture

The system is composed of three major boundaries:
- a C++ client
- a shared protocol boundary over TCP
- a Python `asyncio` server

The client is responsible for local orchestration, persistence, cryptographic preparation, and request emission. The protocol boundary defines the binary frame format and request/response semantics. The server is responsible for framed request handling, validation, admission control, persistence, and upload completion.

> Diagram placeholder  
> A Mermaid system overview diagram should be inserted here.

## 4. End-to-End Flows

### 4.1 Registration and Identity Bootstrap

On first use, the client sends request `825` with its username. The server returns response `1600` with a persistent client ID. The client then generates an RSA keypair and sends request `826` with its public key. The server validates that key, generates a fresh AES key, encrypts it under the client's RSA public key, and returns it in response `1602`. The client decrypts that AES key locally and persists it.

This flow establishes:
- server-issued stable identity
- client-owned private key material
- server-issued symmetric encryption material for uploads

### 4.2 Relogin and Session Re-establishment

On later runs, the client attempts relogin using its persisted identity. It sends request `827`, and the server either restores the session by returning a fresh AES key in response `1605`, or forces the client into a recovery path if relogin cannot proceed.

This keeps identity stable across sessions while allowing session encryption material to rotate.

### 4.3 Secure File Upload Flow

Once handshake is complete, the client reads a file from disk, generates a fresh IV, encrypts the plaintext with AES-256-CBC, splits the ciphertext into chunks, and sends request `828` packet `0` followed by chunk packets.

The server validates packet ordering, size constraints, and upload state, acquires upload capacity, accumulates ciphertext, decrypts the final upload, writes the file to disk, computes CRC32, and returns response `1603`.

The key architectural point is that the file is encrypted client-side before transport.

### 4.4 CRC Validation and Completion

After receiving `1603`, the client decides whether to confirm or reject the transfer result:
- request `900` confirms CRC agreement
- request `901` indicates CRC mismatch
- request `902` indicates CRC mismatch after retry exhaustion

The server uses these requests to finalize the upload lifecycle in persistent metadata.

## 5. Component Boundaries

### 5.1 Client Responsibilities

The client is responsible for:
- loading runtime configuration
- managing local identity and key material
- generating and storing RSA private key material
- decrypting the server-issued AES key
- encrypting file contents before upload
- building protocol-compliant request frames
- interpreting response frames
- driving upload completion based on CRC outcome
- exposing interactive and headless execution modes

### 5.2 Server Responsibilities

The server is responsible for:
- accepting and managing TCP connections
- framing the byte stream into protocol requests
- validating request structure and semantics
- issuing and persisting stable client identity
- validating public keys and delivering AES key material
- enforcing connection and upload limits
- reassembling and finalizing uploads
- persisting client and upload metadata
- tracking upload lifecycle outcomes

### 5.3 Shared Protocol Boundary

The client and server communicate through a shared binary protocol boundary. This boundary defines:
- frame structure
- request and response codes
- payload semantics
- upload packet ordering
- CRC completion semantics

This shared boundary is the contract that lets the client and server evolve as separate components while still interoperating correctly.

## 6. Persistence Model

### 6.1 Client-Side Persistence

The client persists identity and key material locally using files such as `me.info`, `aes.key`, and `priv.key`. This allows relogin, RSA private key reuse, and reuse of decrypted symmetric material across runs.

### 6.2 Server-Side Persistence

The server persists durable metadata in SQLite. Client records include identity and key-related metadata, while upload records capture file metadata, lifecycle status, failure reasons, and completion information.

### 6.3 Transient vs Durable State

The system deliberately separates transient and durable state:
- on the client, runtime socket and flow state are transient, while identity and keys are durable
- on the server, per-connection upload/session state is transient, while client and upload metadata are durable

This separation simplifies recovery behavior and keeps lifecycle boundaries explicit.

## 7. Security Model

The system's security model is based on a split responsibility design:
- the server issues stable client identity
- the client generates and keeps its RSA private key locally
- the server generates the AES session key
- the AES key is delivered encrypted under the client's RSA public key
- files are encrypted on the client before transport
- each file uses a fresh IV
- CRC32 is used to confirm end-to-end transfer integrity
- strict protocol validation is used to reject malformed or inconsistent input

This model keeps plaintext file contents off the wire and avoids sharing private key material with the server.

## 8. Concurrency and Resource Control

The client is intentionally simple in execution behavior. It does not attempt concurrent uploads from a single process and generally operates as a sequential flow controller.

The server, by contrast, is explicitly concurrent. It uses `asyncio` for connection handling, per-connection session isolation, and admission-control mechanisms to prevent overload:
- connection limiter
- upload limiter
- bounded executor for CPU-heavy upload finalization

This gives the overall system an asymmetric but intentional structure:
- simple deterministic client behavior
- controlled multi-connection server behavior

## 9. Key Design Decisions and Tradeoffs

Several major decisions define the architecture.

Using a C++ client makes sense for explicit binary protocol handling, local file processing, and cryptographic integration, but it increases implementation complexity.

Using a Python `asyncio` server improves iteration speed, readability, and testability, but requires careful handling of CPU-heavy work.

Using a custom binary protocol gives strong control over framing and payload semantics, but requires the protocol contract to be maintained carefully.

Using SQLite for server metadata persistence provides durable storage with low operational complexity, but does not target distributed scale.

Using file-based local persistence on the client keeps the project portable and easy to inspect, but is weaker than platform-native secure credential storage.

Using explicit server-side backpressure is preferable to best-effort overload behavior, but means the system intentionally rejects work under pressure instead of absorbing all requests.

## 10. Observability and Performance Findings

The project includes dedicated benchmarking and plotting tooling focused primarily on server behavior under load. These tools evaluate latency, throughput, rejection rates, failure rates, CPU usage, RSS growth, and per-operation behavior under scenarios such as `register`, `relogin`, `upload`, `mixed`, `churn`, and `idle_upload`.

The main architectural takeaway is that upload handling is the dominant cost path. Registration and relogin behave more like control-plane operations, while upload traffic drives the main resource and capacity constraints. This validates the decision to treat upload handling as a separately controlled resource domain on the server.

## 11. Limitations and Future Work

Several future directions remain open:
- Mermaid-based architecture diagrams
- deeper observability and per-phase timing
- GUI-based client control
- more secure local key storage
- evaluation of additional client/server refactoring boundaries
- isolated profiling of the server's in-memory client index
- possible future server implementation in C++
- optional controlled parallel upload support if justified

These are future improvements, not missing correctness requirements for the current project.

## 12. Document Map

This document is the high-level architecture overview for the full system.

For component-specific detail:
- see `docs/client_design.md` for client internals
- see `docs/server_design.md` for server internals