# Changelog

This file tracks major project milestones by version.

Stage 7 is currently active. The core server-identity handshake has been implemented as v0.7.0, while broader Stage 7 hardening items remain in progress.

---

**v0.7.0 - Stage 7 core handshake (Server Identity & Trust Model)**

* Added mandatory Stage 7 handshake before application-level protocol requests
* Added `829 CLIENT_HELLO`
* Added `1608 SERVER_HELLO`
* Added `830 CLIENT_HANDSHAKE_ACK`
* Added persistent server RSA-2048 identity key generation/loading
* Added signed server handshake transcript using SHA-256 and RSA PKCS#1 v1.5 signatures
* Added client-side server signature verification
* Added SHA-256 server fingerprint calculation over `server_public_key_der`
* Added TOFU trust mode with `server.fingerprint`
* Added optional pinned trust mode with `server.pin`
* Added router gating so application requests are rejected before handshake completion
* Added hard-fail behavior for fingerprint mismatch, signature failure, malformed `SERVER_HELLO`, and unsupported security version
* Added server, client, and E2E tests for Stage 7 handshake behavior

Remaining Stage 7 work includes stronger key lifecycle handling, improved local key storage, upload streaming pipeline evolution, and additional abuse protection.

**v0.6.0 - Stage 6 complete (Performance Analysis, Observability & Design Documentation)**

* Ramp-based benchmark runner for register, relogin, upload, and mixed workloads
* Structured JSON benchmark output per run
* Latency percentiles, throughput, success / failure / rejection metrics
* Sampled server CPU, RSS, and thread metrics
* Visualization for latency, throughput, overload behavior, and file-size sensitivity
* Mixed workload analysis with per-operation breakdown (register / relogin / upload)
* Initial bottleneck identification: upload dominates capacity under realistic mixed load
* System, client, and server architecture/design documents
* Mermaid-based architecture diagrams for system, client, and server views
* Clear documentation of component boundaries, persistence model, data flow, and design tradeoffs

**v0.5.0 - Stage 5 scalability and persistence foundations**

 * Upload backpressure with bounded concurrent uploads
 * Global and per-IP connection limits
 * Rejection and recovery behavior under connection overload
 * Bounded executor for CPU-bound upload finalization
 * SQLite-backed server persistence for Clients and Uploads
 * Persisted upload lifecycle tracking (in_progress, completed, crc_mismatch, failed)
 * Separation of transient in-memory session state from persistent server metadata
 * Added unit and integration tests for connection limiting, concurrency control, and SQLite-backed persistence
 * In-memory client metadata index for low-latency lookups
 * Write-through synchronization between SQLite persistence and runtime client metadata state
 * Hot-path client metadata reads served from an in-memory index instead of direct SQLite lookups

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
