# Changelog

This file tracks major project milestones by version.
Stage 7 is currently active and will become v0.7.0 once the server-identity handshake is implemented and tested.

## v0.6.0 - Stage 6 complete

Stage 6 added performance analysis, observability-oriented benchmarking, structured benchmark output, mixed workload analysis, resource sampling, performance plots, and system/client/server architecture documentation.

Main additions:
- ramp-based benchmark runner for register, relogin, upload, churn, idle_upload, and mixed workloads
- structured JSON benchmark output
- latency percentile reporting
- throughput and outcome-rate reporting
- sampled CPU, RSS, and thread metrics
- performance plots
- system, client, and server architecture documents

## v0.5.0 - Stage 5 complete

Stage 5 added scalability and persistence foundations.

Main additions:
- upload backpressure with bounded concurrent uploads
- global and per-IP connection limits
- bounded executor for CPU-heavy upload finalization
- SQLite-backed server persistence
- persisted upload lifecycle tracking
- in-memory client metadata index
- write-through synchronization between SQLite and runtime metadata

## v0.4.0 - Stage 4 complete

Stage 4 added client UX, persistence, and operational polish.

Main additions:
- interactive console UI
- connect, reconnect, and status flows
- single-file and batch upload modes
- headless multi-file upload support
- centralized client persistence
- atomic client-side persistence writes
- clearer client and server errors

## v0.3.0 - Stage 3 complete

Stage 3 added testing and reliability foundations.

Main additions:
- C++ unit tests
- Python async unit tests
- end-to-end integration tests
- CI validation
- defensive protocol validation
- parallel client isolation