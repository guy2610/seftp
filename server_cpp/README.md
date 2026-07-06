# SEFTP C++ Server Foundation

This directory contains an experimental C++ server foundation for SEFTP.

The stable SEFTP server remains the Python asyncio implementation under `server/`.
This C++ implementation is not intended to replace it during Stage 9B.

## Stage 9B Scope

Current scope:

- Define C++ protocol constants and frame types
- Parse binary SEFTP request frames
- Build binary SEFTP response frames
- Add unit tests for protocol parsing and response building
- Add a minimal router/session skeleton after the protocol layer is tested

Out of scope for Stage 9B:

- Full Python server feature parity
- Replacing the Python asyncio server
- SQLite persistence
- Streaming upload request `828`
- Full Stage 7 cryptographic handshake implementation
- Production TCP server behavior
- Resumable uploads
- Parallel uploads
- GUI or cross-client messaging

## Design Direction

The C++ server foundation is built by responsibility, not by translating Python files one-to-one.

The intended layering is:

1. Protocol constants and typed frame structures
2. Request frame parser
3. Response frame builder
4. Minimal router/session state machine
5. Minimal transport integration

This avoids a Python-shaped C++ rewrite and keeps the early implementation testable without sockets.

## Current Status

Skeleton only.
No runtime server is implemented yet.