# Changelog

This file tracks major project milestones by version.

Stage 7 is functionally complete through v0.7.2. It includes the mandatory server-identity handshake, AES key response binding, key lifecycle hardening, application-level abuse protection, and end-to-end streaming upload pipeline evolution.

---

**v0.9.0-draft - Stage 9 Production Hardening & C++ Server Foundation**

* Defined Stage 9 scope around production hardening, runtime metrics export, and an experimental C++ server foundation
* Renamed the Stage 8 `1607` runtime metric from `protocol_errors_1607` to `responses_1607`
  * reflects that `1607` responses include protocol errors, upload backpressure, and rate-limit responses
* Added runtime metrics JSON export
* Added an optional local-only HTTP metrics endpoint
  * disabled by default
  * enabled with `SEFTP_METRICS_ENABLED=1`
  * binds to `127.0.0.1:9100` by default
  * exposes `GET /metrics`
* Added tests for runtime metrics export and the HTTP metrics handler
* Manually validated the metrics endpoint with `curl`
* Extended deployment-level abuse protection guidance
  * documents application-level vs infrastructure-level protection boundaries
  * covers TCP proxy placement, firewall recommendations, OS/kernel limits, and metrics endpoint exposure guidance
  * keeps large-scale public DDoS mitigation explicitly out of scope
* Added protected Docker Compose deployment demo
  * includes a Python SEFTP server container
  * places HAProxy in front as a TCP proxy
  * exposes only the proxy port to the host
  * keeps server data in a Docker volume
  * keeps the metrics endpoint internal to the server container
* Added `SEFTP_HOST` and `SEFTP_PORT` environment-variable overrides for containerized deployment
  * preserves `port.info` fallback for local runs

**v0.8.0-draft - Stage 8 performance observability checkpoint**

* Updated the load-test runner for Stage 7 protocol compatibility
  * performs the required `829` / `1608` / `830` handshake before application requests
  * parses the Stage 7 bound AES key response format used by `1602` and `1605`
* Added per-phase timing breakdowns to benchmark JSON output
  * connection and handshake
  * registration
  * RSA key generation or RSA key-pool selection
  * AES key exchange
  * RSA decrypt
  * client-side encryption preparation
  * upload packet transmission
  * CRC confirmation
* Added RSA key-pool support to the load-test runner
  * avoids measuring expensive client-side RSA key generation inside each upload worker
  * makes upload benchmarks better represent the server upload path
* Re-established post-Stage-7 performance baselines
  * register timing baseline
  * relogin timing baseline
  * upload timing baseline
  * RSA-pool upload timing baseline
  * upload chunk-size comparison results
* Updated the load-test default upload chunk size to `64 * 1024`
  * aligns benchmark behavior with the server default `max_chunk_size`
  * reduces upload packet count compared with the previous `60000` byte default
* Added cleanup for benchmark-created upload files
  * load-test uploads now use run-specific filenames
  * benchmark-created upload files are removed after the run
  * empty upload directories are removed when possible
* Added a benchmark result comparison CLI
  * compares two JSON benchmark reports by load stage
  * reports latency, throughput, success/rejection/failure counts, and timing breakdown changes
* Added Stage 8 benchmark comparison plots
  * RSA key-pool before/after plots for upload benchmark cleanup
  * upload chunk-size comparison plots for 60KB vs 64KB behavior
  * Stage 6 upload behavioral baseline vs Stage 8 post-streaming upload comparison plots
  * documented that Stage 6 vs Stage 8 is a behavioral comparison rather than a strict apples-to-apples microbenchmark
* Added server-side runtime visibility counters
  * tracks active connections and active uploads
  * tracks rejected connections and upload backpressure rejections
  * tracks `1607` protocol-error responses and rate-limited requests
  * includes runtime metric snapshots in disconnect summaries
* Validated upload backpressure runtime visibility
  * ran 50 concurrent upload workers with 10 allowed concurrent upload slots
  * observed 10 successful uploads, 40 controlled upload rejections, and 0 failures
  * confirmed server-side counters reported `rejected_uploads=40`, `responses_1607=40`, and `rejected_connections=0`
* Added Stage 8 performance observability documentation
  * documents benchmark methodology
  * explains RSA key-pool measurement cleanup
  * summarizes chunk-size findings
  * identifies future optimization candidates such as size-aware upload backpressure and richer plotting/reporting


**v0.7.2 - Stage 7 upload streaming pipeline**

* Replaced full-file client upload buffering with incremental upload processing
* Added client-side streaming upload path for request `828`
  * reads plaintext incrementally from disk
  * updates CRC32 incrementally
  * encrypts with continuous AES-256-CBC state
  * applies PKCS#7 padding only at end-of-file
  * packetizes ciphertext according to existing 828 semantics
* Replaced server-side ciphertext accumulation with streaming decrypt/write processing
  * decrypts 828 ciphertext chunks incrementally
  * writes plaintext to a temporary upload file
  * updates CRC32 incrementally
  * validates final PKCS#7 padding and plaintext size
  * atomically replaces the final upload path on success
* Preserved the existing 828 wire protocol semantics
  * packet 0 carries the IV
  * packets 1..N carry ciphertext chunks
  * `total_packets` excludes packet 0
  * `content_size` is ciphertext size excluding IV
* Separated control-plane burst limiting from upload data-plane chunks
  * 825 / 826 / 827 / 829 / 830 / 900 / 901 / 902 remain request-rate limited
  * 828 upload chunks are governed by upload-specific limits instead
* Increased default `max_packets` to 65535 to align with the uint16 packet-count field
* Hardened upload error flow so server/protocol errors (`1607`) abort upload instead of triggering CRC retry messages (`901` / `902`)
* Updated server handler tests for the streaming upload state model
* Verified upload correctness with boundary files:
  * 15 bytes
  * 16 bytes
  * 17 bytes
  * 65536 bytes
  * random 1MB

**v0.7.1 - Stage 7 hardening completion checkpoint**

* Added owner-only permissions for sensitive client-side files:
  * `priv.key`
  * `aes.key`
  * `server.fingerprint`
* Added owner-only permissions for server identity key storage:
  * `server_identity.pem`
* Refactored RSA private key persistence so crypto returns generated key material and persistence/files own disk writes
* Added private key overwrite prevention for `priv.key`
* Added fail-closed behavior for missing, unreadable, or corrupted client private keys during relogin/key recovery paths
* Added fail-closed behavior for corrupted server identity key loading
* Added Stage 7 key lifecycle policy documentation
* Added handshake timeout enforcement before Stage 7 completion
* Added request burst limiting using per-session sliding-window request tracking
* Added tests for local key permissions, server identity loading, private key overwrite prevention, handshake timeout, and request burst limiting
* Extended `1602` and `1605` AES key responses for `security_version = 1`
* Added server-side AES key binding signatures over:
  * security version
  * client nonce
  * server nonce
  * client ID
  * response code
  * encrypted AES key
* Added client-side AES key binding signature verification before decrypting and saving `aes.key`
* Added parser and answer tests for the new bound AES key response format

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

Follow-up Stage 7 work continued in v0.7.1 and v0.7.2 with key lifecycle hardening, application-level abuse protection, AES key response binding, and upload streaming pipeline evolution.

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
