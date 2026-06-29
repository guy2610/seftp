# Roadmap

This roadmap tracks completed project stages and planned future work.

The detailed stage breakdown was moved out of the top-level README to keep the README focused as a short project overview.

---

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

### **Stage 5 - Scalability & Persistence** DONE
Improve server scalability and storage architecture.

* Server concurrency improvements
  * Async multi-client server (DONE)
  * Worker model / bounded executor for CPU-bound tasks (DONE)
  * Connection limits and backpressure (DONE)

* Persistence layer evolution
  * JSON persistence layer (DONE)
  * SQLite persistence layer (DONE)
  * Client metadata storage (DONE)
  * Upload lifecycle persistence (DONE)
  * Migration from JSON store (DONE)
  * Separation of runtime session state vs persistent storage (DONE)
  * Keep upload/session transient state in memory (DONE)
  * Avoid DB access on packet hot path (DONE)
  * In-memory client index for low-latency lookups (DONE)
  * Write-through synchronization for persistent client metadata (DONE)

---

### **Stage 6 - Performance Analysis, Observability & Design Documentation** DONE

Measure and analyze runtime behavior under load to identify bottlenecks and guide future optimizations.
* Extend load and stress testing scenarios
  * Parallel clients (idle + active uploads) (DONE)
  * High connection churn (DONE)
  * Mixed workloads (registration, re-login, uploads) (DONE)

* Collect performance metrics
  * Request/response latency (p50 / p95 / p99) (DONE)
  * Upload duration and throughput (DONE)
  * Success / failure / rejection rates (DONE)

* Resource usage analysis
  * CPU utilization under load (DONE)
  * Memory usage (RSS / growth over time) (DONE)
  * Backpressure behavior under overload (DONE - first level)

* Output and visualization
  * Structured results (JSON / CSV) (DONE)
  * Summary tables per scenario (DONE)
  * Basic charts for latency, throughput, and resource usage (DONE)

* Bottleneck identification
  * Detect hot paths (CPU vs I/O vs DB) (DONE - first level)
  * Evaluate effectiveness of in-memory client index (deferred to future optimization work)
  * Identify whether additional caching or indexing is justified (deferred to future optimization work)

* Evidence-based optimization targets
  * Define concrete candidates for future improvements (DONE - basic level)
  * Feed results into Stage 8 (future work / optimizations)

* Architecture / design documentation (DONE)
  * Document component boundaries, data flow, and persistence model (DONE)
  * Capture key design decisions and tradeoffs (DONE)
  * Summarize measured bottlenecks and likely optimization directions (DONE)
  * Add system, client, and server design documents with Mermaid diagrams (DONE)

---
### **Stage 7 - Security Hardening & Protocol Evolution** DONE

Related documents:
- `../protocol/protocol_extension_design.md`
- `stage7_threat_model.md`

Current status:

Stage 7 is functionally complete and tested through protocol version `v0.7.2`.

Completed:
- mandatory `829 CLIENT_HELLO` / `1608 SERVER_HELLO` / `830 CLIENT_HANDSHAKE_ACK`
- persistent server RSA identity key
- signed handshake transcript
- client-side server signature verification
- SHA-256 server fingerprint calculation
- TOFU trust mode using `server.fingerprint`
- optional pinned mode using `server.pin`
- server-side router gating before handshake completion
- server, client, and E2E test coverage for the core handshake
- signed AES key responses (`1602` / `1605`) bound to the Stage 7 handshake transcript
- client-side verification of AES key binding signatures before AES key decryption
- owner-only permissions for sensitive local key material
- key lifecycle hardening for private key overwrite, corruption, and server identity loading
- application-level abuse protection: connection limits, per-IP limits, handshake timeout, upload inactivity timeout, upload slots, bounded executor, and request burst limiting
- end-to-end upload pipeline streaming for the existing AES-CBC upload model
  - client-side incremental file read, CRC calculation, AES-CBC encryption, and 828 packet transmission
  - server-side incremental 828 receive, AES-CBC decryption, temp-file write, CRC calculation, and atomic finalization
  - preserved existing 828 wire protocol semantics while removing full-file plaintext/ciphertext buffering from the upload path
  - separated control-plane burst limiting from 828 upload data-plane chunk handling

Strengthen the cryptographic model and extend the protocol to provide authenticated key establishment, improved transport security, and more robust resource handling.

* Protocol security extension
  * Introduce authenticated server identity during the bootstrap phase (DONE)
  * Extend the current protocol with a MITM-resistant key establishment flow (DONE - server identity handshake and AES key response binding implemented)
  * Preserve the existing request/response model (`825`/`826`/`827`/`828`/...) while strengthening the handshake (DONE)
  * Define a trust model for first connection (TOFU and pinned mode implemented)

* Cryptographic model improvements
  * Strengthen session key establishment and binding between identity and AES key (DONE - `1602` / `1605` AES key responses are signed and bound to the Stage 7 handshake transcript)
  * Evaluate replay resistance and handshake integrity guarantees (DONE - nonce-bound signed handshake and AES key binding implemented)
  * Improve key lifecycle handling (DONE for overwrite prevention, corruption fail-closed behavior, and server identity loading; future work may add explicit rotation/reset flows)

* Client-side key security
  * Improve storage of `priv.key` and `aes.key` beyond plain file-based persistence (PARTIAL - owner-only permissions and overwrite protection implemented)
  * Evaluate stronger protection or platform-native secure storage (FUTURE)

* Upload pipeline evolution (DONE)
  * Moved from full-file buffering to end-to-end incremental upload processing
    * Client: read plaintext chunk -> update CRC -> encrypt with continuous AES-CBC state -> send encrypted chunk
    * Server: receive encrypted chunk -> decrypt with continuous AES-CBC state -> write plaintext chunk to temporary file -> update CRC
  * Preserved current upload protocol semantics and AES-CBC file-level encryption model
  * Applied CBC padding only at the file boundary, not independently per chunk
  * Reduced peak memory usage by avoiding full-file plaintext or ciphertext buffering on both client and server
  * Deferred independent per-chunk encryption, retry, resume, and parallel upload semantics to a future AEAD-based upload protocol stage

* Abuse protection
  * Connection rate limiting (limit new connections per time window, per IP/global) (DONE)
  * Basic DoS protection (burst control, early rejection under load, guarding expensive paths) (DONE)
  * Hardening of edge-case protocol paths under adversarial input (DONE)
  * Document deployment-level abuse protection options (TCP proxy, firewall, OS limits) (FUTURE)
---

### **Stage 8 - Observability & Production Behavior** DONE
Operational visibility, diagnostics, and runtime insight into system behavior under real-world conditions.
Current status:

Stage 8 is complete through the `v0.8.0-draft` observability checkpoint.

The completed work focuses on benchmark observability, post-Stage-7 performance baselining, evidence-based upload-path analysis, comparison plots, and lightweight server-side runtime visibility.

Additional observability and production-behavior ideas are tracked as Stage 9 / future follow-up work rather than as required Stage 8 work.

Completed so far:
- Updated the load-test runner for the Stage 7 protocol flow
  - performs `829 CLIENT_HELLO`
  - accepts `1608 SERVER_HELLO`
  - sends `830 CLIENT_HANDSHAKE_ACK`
  - continues with application-level requests only after the handshake
- Updated benchmark parsing for Stage 7 bound AES key responses (`1602` / `1605`)
- Added per-phase timing breakdown to benchmark JSON output
  - connection and handshake time
  - registration time
  - RSA key generation or key-pool selection time
  - AES key exchange time
  - RSA decrypt time
  - client-side encryption preparation time
  - upload packet transmission time
  - CRC confirmation time
- Added RSA key-pool support to the load runner to avoid polluting upload benchmarks with client-side RSA key generation cost
- Re-established a post-Stage-7 upload baseline using the streaming upload pipeline
- Added Stage 8 benchmark result artifacts for:
  - register timing baseline
  - relogin timing baseline
  - upload timing baseline
  - RSA-pool upload baseline
  - upload chunk-size comparison
- Updated the load-test default upload chunk size to `64 * 1024`, matching the server default `max_chunk_size`
- Added automatic cleanup of benchmark-created upload files
- Added a benchmark result comparison CLI for before/after JSON report analysis
- Added Stage 8 benchmark comparison plots
  - RSA key-pool before/after plots
  - upload chunk-size comparison plots
  - Stage 6 upload behavioral baseline vs Stage 8 post-streaming baseline plots
- Added `docs/performance/stage8_performance_observability.md`
- Added server-side runtime visibility counters
  - active connections
  - active uploads
  - rejected connections
  - upload backpressure rejections
  - `1607` protocol-error responses
  - rate-limited requests
- Added runtime metric snapshots to server disconnect summaries
- Validated runtime visibility with an upload backpressure load test
  - 50 concurrent upload workers
  - 10 allowed concurrent upload slots
  - 10 successful uploads, 40 controlled upload rejections, and 0 failures

Key findings so far:
- The initial post-Stage-7 upload benchmark was polluted by client-side RSA key generation inside the load runner
- RSA key pooling exposed the real upload hot path more clearly
- With RSA key pooling enabled, 1MB upload latency dropped from multi-second values to sub-second values in the tested scenarios
- The upload packet phase remained mostly unchanged before/after RSA pooling, confirming that RSA pooling cleaned the measurement rather than changing server upload behavior
- Upload chunk size materially affects upload latency because smaller chunks increase per-packet overhead
- `64 * 1024` performed best among the tested chunk sizes (`16KB`, `60KB`, `64KB`)
- Under the tested overload case, the server rejected excess uploads through controlled backpressure with zero upload failures

Stage 8 is considered complete at the current observability checkpoint.

Follow-up work such as richer metrics export, deeper server-side internal timing, executor saturation visibility, size-aware upload backpressure, richer report generation, and improved client-side progress reporting is tracked under Stage 9 / future work.

* Metrics
  * Connection statistics (DONE - active and rejected counters)
  * Upload statistics (DONE - active upload and rejected upload counters)
  * Protocol error counters (DONE - `1607` response counter)
  * Rate-limit visibility (DONE - rate-limited request counter)
  * Active connection and active upload visibility (DONE - exposed through runtime metric snapshots in disconnect summaries)
  * Benchmark timing breakdowns (DONE - client-observed per-phase timings)
  * Benchmark before/after comparison CLI (DONE)
  * Per-IP runtime reporting, executor saturation, queue-depth telemetry, and dedicated metrics export moved to Stage 9 / future work

* Logging and diagnostics
  * Structured logging (DONE)
  * Request / response tracing across the full lifecycle
  * Correlation between `connection_id`, `request_id`, and `upload_id`
  * Improved visibility into upload phases (receive, finalize, persist)

* Runtime behavior
  * Configuration validation (DONE)
  * Runtime configuration reporting (DONE)
  * Exposure of internal state for debugging and benchmarking (DONE - log-based runtime metric snapshots)
  * Optional lightweight metrics export (moved to Stage 9 / future work)
  * Load-test artifact cleanup for benchmark-created uploads (DONE)
  * Post-Stage-7 performance baseline and benchmark methodology documentation (DONE)

---

### **Stage 9 - Production Hardening & C++ Server Foundation**
Focused follow-up stage for production-facing observability, deployment hardening, and an experimental C++ server foundation.

Current status:

Stage 9 is planned as a focused follow-up to the Stage 8 observability checkpoint.

The goal is to improve production-facing runtime visibility and deployment hardening while starting an experimental C++ server foundation without replacing the stable Python asyncio server.

Primary scope:
- Lightweight runtime metrics export beyond disconnect-summary snapshots
- Runtime metric naming cleanup and optional executor / queue visibility
- Production deployment hardening documentation
- Optional protected Docker Compose deployment demo
- Experimental C++ server foundation for protocol parsing and response building

Out of scope for Stage 9:
- Full C++ server feature parity
- Replacing the Python server
- SQLite persistence parity in C++
- Streaming upload (`828`) implementation in C++
- Resumable uploads
- Parallel upload protocol
- Chunked AEAD upload redesign
- GUI client
- Cross-client messaging

* Track A - Production hardening and metrics
  * Rename `protocol_errors_1607` to `responses_1607`
  * Add local-only runtime metrics JSON export
  * Add tests for metrics export
  * Add executor saturation and queue-depth visibility only if the implementation remains simple and low-risk
  * Extend production abuse/deployment documentation
  * Optionally add a protected Docker Compose deployment demo
  * Sync README / CHANGELOG / architecture docs after implementation

* Track B - Experimental C++ server foundation
  * Add `server_cpp/` skeleton
  * Add CMake/build integration
  * Add C++ protocol constants and frame structures
  * Add binary frame parser
  * Add response builders for basic protocol responses
  * Add C++ unit tests for parser and builders
  * Add `server_cpp/README.md` documenting current limitations and migration path

* Future upload model extensions
  * Evaluate resumable uploads across reconnects (protocol and persistence implications)
  * Evaluate controlled parallel uploads from the client (tradeoff between throughput and complexity)
    * Design a future chunked AEAD upload protocol
    * Independent authenticated encryption per chunk
    * Per-upload nonce / key derivation strategy
    * Chunk index and metadata bound as AEAD associated data
    * Optional upload session lifecycle (`UPLOAD_BEGIN`, `UPLOAD_CHUNK`, `UPLOAD_FINISH`)
    * Foundation for resumable uploads, retries, and controlled parallel chunk transmission

* Storage and performance exploration
  * Evaluate additional caching / indexing strategies on the server (based on measured bottlenecks)

* Observability follow-ups
  * Add richer runtime metrics export beyond disconnect-summary snapshots
  * Evaluate a lightweight metrics endpoint or export format
  * Add per-IP runtime reporting for connection pressure analysis
  * Add executor saturation visibility and queue-depth telemetry
  * Add deeper server-side internal timing for frame parsing, router dispatch, handler execution, SQLite interaction, upload packet processing, temporary file writes, and atomic finalization
  * Evaluate size-aware upload backpressure using active upload byte cost in addition to active upload count
  * Improve benchmark report generation beyond the current JSON, CLI, and plot outputs
  * Improve client-side upload progress and status reporting

* Production Deployment Hardening
  * Deployment-level abuse protection
    * Add a TCP-aware reverse proxy deployment profile
      * Example: Nginx `stream {}` or HAProxy in front of the SEFTP server
      * Enforce connection limits before traffic reaches the Python server
      * Support basic TCP health checks

    * Add Docker Compose demo for protected deployment
      * `seftp-server`
      * `tcp-proxy`
      * isolated network
      * documented exposed port

    * Document OS / kernel-level limits
      * file descriptor limit (`ulimit -n`)
      * listen backlog / socket queue tuning
      * per-process resource limits

    * Document host firewall recommendations
      * allow only expected TCP port
      * optionally restrict source IP ranges for private deployments
      * reject all unrelated inbound traffic

    * Distinguish application-level abuse protection from infrastructure-level DDoS mitigation
      * application limits
      * proxy limits
      * firewall limits
      * kernel limits

* Future system extensions
  * Full C++ server implementation beyond the Stage 9 foundation
  * Cross-client communication (relay / messaging)
  * Optional GUI client (Qt / ImGui / DearPyGui)

* Portfolio polish
  * Full protocol specification (aligned with implementation)
  * Demo instructions and usage flows
  * Release polish and packaging

---
