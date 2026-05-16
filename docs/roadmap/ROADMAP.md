# Roadmap

This roadmap tracks completed project stages and planned future work.

## Completed

### Stage 1 - Security & Protocol Correctness

Completed.

Focus:
- random IV per file
- RSA-2048 public key validation
- stable server-issued client_id
- structured 1607 error responses

### Stage 2 - Architecture & Refactor

Completed.

Focus:
- modular C++ client layers
- protocol, crypto, network, file, and flow separation
- async Python server refactor
- per-connection session isolation
- handler/router separation

### Stage 3 - Testing & Reliability

Completed.

Focus:
- C++ unit tests
- Python async unit tests
- end-to-end integration tests
- CI validation
- defensive protocol enforcement

### Stage 4 - Client UX, Persistence & Operational Polish

Completed.

Focus:
- interactive console UI
- headless multi-file upload
- centralized client persistence
- atomic writes
- clearer error reporting

### Stage 5 - Scalability & Persistence

Completed.

Focus:
- upload backpressure
- connection limits
- bounded executor
- SQLite persistence
- persisted upload lifecycle
- in-memory client metadata index

### Stage 6 - Performance Analysis, Observability & Design Documentation

Completed.

Focus:
- ramp-based load testing
- structured benchmark output
- latency, throughput, rejection, and resource metrics
- mixed workload analysis
- architecture documentation
- bottleneck identification

## Active

### Stage 7 - Security Hardening & Protocol Evolution

Goal:
strengthen the bootstrap phase by adding authenticated server identity verification before existing protocol operations.

Related documents:
- `../protocol/protocol_extension_design.md`
- `stage7_threat_model.md`

Planned work:
- add CLIENT_HELLO / SERVER_HELLO handshake
- add server identity keypair
- sign handshake transcript
- verify server fingerprint on the client
- support TOFU mode
- support pinned fingerprint mode
- reject unauthenticated requests before 825 / 826 / 827 / 828
- add tests for malformed handshake, fingerprint mismatch, replay attempts, and downgrade behavior

Out of scope for Stage 7:
- full TLS implementation
- certificate-chain validation
- mutual authentication
- resumable uploads
- GUI client
- distributed deployment

## Future

### Stage 8 - Observability & Production Behavior

Planned direction:
- structured runtime metrics
- active connection and active upload visibility
- executor saturation visibility
- request/response tracing
- improved upload phase diagnostics
- improved client-side progress reporting

### Stage 9 - Extensions & Portfolio Polish

Planned direction:
- resumable uploads exploration
- controlled parallel upload exploration
- optional GUI client
- optional C++ server implementation
- release packaging
- technical demo polish