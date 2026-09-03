# SEFTP C++ Server

This directory contains the experimental C++ server implementation for SEFTP.

The stable, feature-complete SEFTP server remains the Python `asyncio`
implementation under `server/`.

The C++ implementation is being developed incrementally as a separate
systems-oriented architecture exercise rather than as a line-by-line
translation of the Python server.

## Stage 9B - Synchronous Foundation

Stage 9B establishes a runnable synchronous C++ server baseline.

Implemented:

- C++ protocol constants and typed request / response codes
- Request and response frame structures
- Little-endian binary request-frame parsing
- Response-frame construction
- Protocol-code validation
- Handshake-aware request routing
- Per-connection session state
- Synchronous Boost.Asio framed reads and writes
- Partial TCP read handling
- Oversized-payload rejection before payload allocation
- Connection-level request orchestration
- Multiple requests over the same TCP connection
- TCP listener / acceptor handling
- Synchronous server accept loop
- Runnable `seftp_server_cpp` executable
- GoogleTest coverage across protocol, framing, routing, session,
  frame IO, connection handling, and listener behavior

The current development server binds only to:

```text
127.0.0.1:1234
```

Build and run on macOS:

```bash
cmake --preset macos-arm64
cmake --build build/macos-arm64
./build/macos-arm64/seftp_server_cpp
```

A basic TCP listener smoke test can be performed from another terminal:

```bash
nc -vz 127.0.0.1 1234
lsof -nP -iTCP:1234 -sTCP:LISTEN
```

## Current Execution Model

The Stage 9B server is deliberately synchronous.

At a high level:

```text
server_main
    |
    v
run_server
    |
    v
accept_one_connection
    |
    v
handle_connection
    |
    +--> read request frame
    +--> route / update session
    +--> build response
    +--> write response
    |
    +--> repeat until the connection terminates
```

One accepted client is handled until its connection ends before the server
accepts and handles the next client.

This behavior provides a simple known-good baseline before introducing
asynchronous lifetime and concurrency concerns.

## Current Limitations

The C++ server is not yet feature-compatible with the stable Python server.

Not yet implemented:

- Real Stage 7 cryptographic handshake payloads
- RSA server identity and transcript signing
- SQLite persistence
- Registration business logic
- Public-key exchange business logic
- Reconnect / relogin business logic
- Streaming upload request `828`
- AES upload decryption
- CRC retry / final-failure lifecycle parity
- Production-grade connection admission and abuse controls
- Runtime metrics parity
- Graceful shutdown
- Concurrent client handling

The current success responses after the handshake are intentionally minimal
foundation behavior rather than the final application handlers.

## Stage 9C - Async Boost.Asio Evolution

The next milestone keeps the protocol/session foundation while replacing the
blocking networking model with asynchronous Boost.Asio.

Planned hands-on topics:

1. `async_accept`
2. Explicit connection objects
3. `async_read`
4. `async_write`
5. `std::shared_ptr`
6. `std::enable_shared_from_this`
7. Asynchronous buffer lifetime
8. Multiple concurrent clients on one event loop
9. `boost::asio::steady_timer` timeouts
10. Cancellation-aware cleanup
11. Graceful `SIGINT` / `SIGTERM` shutdown
12. Bounded active-connection admission
13. Async integration tests
14. Optional multi-threaded `io_context`
15. `boost::asio::strand` if per-connection handler serialization becomes necessary

The goal of Stage 9C is not feature parity yet. It is to establish a sound
asynchronous C++ networking and ownership model before adding the heavier
application, persistence, cryptographic, and upload features.

## Design Direction

The C++ server is organized by responsibility:

```text
protocol
    |
    v
frame parsing / building
    |
    v
router
    |
    v
session
    |
    v
frame IO
    |
    v
connection handler
    |
    v
listener
    |
    v
server loop
    |
    v
server executable
```

This layering keeps protocol logic separate from transport and connection
lifetime concerns and provides a clean baseline for the Stage 9C async
refactor.
