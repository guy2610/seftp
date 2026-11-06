# SEFTP C++ Server

This directory contains the experimental C++17 server implementation for SEFTP.

The stable, feature-complete SEFTP server remains the Python `asyncio` implementation under `server/`. The C++ implementation is developed incrementally as a separate systems-oriented architecture exercise rather than as a line-by-line translation of the Python server.

## Stage 9B - Synchronous Foundation

Stage 9B established the first runnable C++ baseline:

- protocol constants and typed request / response codes
- request and response frame structures
- little-endian request-frame parsing and response construction
- protocol-code validation
- handshake-aware routing
- per-connection session state
- synchronous framed reads and writes
- partial TCP read handling
- oversized-payload rejection before payload allocation
- multiple requests over one TCP connection
- TCP listener / acceptor handling
- synchronous server accept loop
- runnable `seftp_server_cpp` executable
- GoogleTest coverage across protocol, framing, routing, session, frame IO, connection handling, and listener behavior

Stage 9B remains useful as the simple baseline from which the asynchronous model was derived.

## Stage 9C - Async Boost.Asio Evolution

Stage 9C is complete.

Implemented:

- asynchronous connection acceptance with `async_accept`
- one `AsyncConnection` object per accepted socket
- `std::shared_ptr` / `std::enable_shared_from_this` ownership across pending callbacks
- asynchronous framed header and payload reads with `async_read`
- asynchronous response writes with `async_write`
- connection-owned header, frame, and response buffers with explicit async lifetime
- per-connection `Session` state across repeated request/response cycles
- header and payload read timeouts with `boost::asio::steady_timer`
- read-generation checks to reject stale timeout callbacks after a newer read begins
- cancellation-aware, idempotent `stop()` behavior
- clean zero-byte EOF handling between requests
- active-connection tracking with `std::weak_ptr`
- bounded active-connection admission; development default: 128
- controlled `SIGINT` / `SIGTERM` shutdown
- delayed asynchronous retry after unexpected accept failures
- idempotent server startup to prevent duplicate `async_accept` loops
- explicit connection shutdown on oversized asynchronous payload headers
- one strand for `AsyncServer` state
- one independent strand per `AsyncConnection`
- one `io_context` executed by four worker threads in the development executable
- thread-safe console logging through a shared mutex
- async lifecycle, timeout, shutdown, limit, and concurrency tests
- concurrent multi-client / multi-request stress coverage
- ThreadSanitizer validation of the multi-threaded execution path

## Current Execution Model

```text
main
 |
 +--> io_context
 |      +--> worker thread 1
 |      +--> worker thread 2
 |      +--> worker thread 3
 |      +--> worker thread 4
 |
 +--> AsyncServer
        |
        +--> server strand
        |      +--> async_accept
        |      +--> active connection registry
        |      +--> accept retry timer
        |      +--> start / stop / shutdown
        |
        +--> AsyncConnection A
        |      +--> strand A
        |             +--> read header
        |             +--> read payload
        |             +--> route / mutate Session A
        |             +--> write response
        |             +--> timeout / stop
        |
        +--> AsyncConnection B
               +--> strand B
                      +--> independent request loop
```

A strand is a serialization boundary, not a worker thread. All handlers for one connection use that connection's strand, so they do not execute concurrently with each other even though the `io_context` is running on multiple threads. Different connection strands may execute in parallel.

The server strand separately protects `AsyncServer` state. This keeps server-level acceptance/registry/shutdown state serialized without removing parallelism between active clients.

## Connection Lifetime

`AsyncConnection` derives from `std::enable_shared_from_this`. Public `start()` / `stop()` first capture a `shared_ptr` and route work through the connection strand. Pending asynchronous handlers also capture `shared_ptr` ownership, so the connection object remains alive while its socket/timer operations are outstanding.

`AsyncServer` keeps `weak_ptr` references to active connections. The registry can observe and stop living connections during shutdown, but expired entries do not keep finished connections alive and are pruned before enforcing the active-connection limit.

## Timeouts and Shutdown

Each connection owns a `steady_timer` used for pending header/payload reads. Each armed read also has a generation number. A successful read invalidates the previous generation and cancels its timer; a timeout callback only stops the connection if its generation is current. This prevents an already-queued, stale timeout completion from stopping a newer read. Normal `operation_aborted` completions are ignored.

A peer that closes the socket while the server is waiting for a new header produces a zero-byte EOF and is treated as a normal disconnect. EOF after a partial frame remains an error.

`SIGINT` and `SIGTERM` request server shutdown. Shutdown closes the acceptor, cancels the accept-retry timer, requests stop on active connections, and lets the `io_context` drain the resulting completion handlers before worker threads join. `AsyncServer` uses non-owning `[this]` captures, so its lifetime relies on this shutdown-and-join ordering; `stop()` alone is asynchronous and is not a completion barrier. Connection cleanup uses `shutdown()` followed by `close()`, which also cancels outstanding socket operations. Stage 9C does not implement graceful application-level draining of in-flight requests; active sockets are closed as part of controlled shutdown.

Unexpected accept failures are retried through an asynchronous 100ms timer. This avoids both permanently disabling acceptance after one transient failure and a tight retry loop that would consume a worker thread/CPU.

## Validation

The async test suites cover:

- connection ownership while asynchronous operations are pending
- header/payload read chaining
- oversized payload rejection
- handshake-state routing
- multiple requests on one connection
- independent state across concurrent connections
- header and payload read timeouts, including rejection of stale callbacks
- explicit and idempotent stop behavior
- idempotent server `start()` behavior and a duplicate-accept-loop regression test
- explicit socket closure for oversized payload headers even while the test retains connection ownership
- acceptor shutdown and active-connection shutdown
- bounded active connections and slot reuse
- multiple clients with a multi-threaded `io_context`
- concurrent clients performing repeated stateful request/response sequences

The concurrency stress test uses eight client threads against four server worker threads; each client performs the handshake-state sequence followed by repeated application requests.

The same concurrency path was run under ThreadSanitizer. TSan exposed an unsynchronized `std::cout` race that was not visible as a functional failure in repeated stress runs. Console logging is now serialized through a shared mutex, and the final sanitizer validation is clean.

There is no dedicated fault-injection test that forces a transient OS-level `accept` failure and then verifies recovery; the delayed retry policy is implemented in the server path, while shutdown/cancellation and normal acceptance are covered by the existing tests.

## Stage 9C.1 - C++ Quality and Validation Tooling

Stage 9C.1 is complete. It adds:

- repository `.clang-format` configuration applied to server sources, headers, and tests
- repository `.clang-tidy` baseline (`bugprone-*`, `performance-*`); remaining warnings are reviewed rather than hidden globally
- compiler warnings scoped to C++ server and server-test targets: `-Wall -Wextra -Wpedantic` on GCC/Clang and `/W4` on MSVC
- separate CMake presets for ASan/UBSan (`macos-arm64-sanitizers`) and TSan (`macos-arm64-tsan`); they cannot be enabled together
- GitHub Actions checks for server formatting and ASan/UBSan on Ubuntu, alongside the existing C++ build and tests on Ubuntu and Windows
- regression tests for stale read-timeout callbacks, duplicate server startup, and explicit oversized-payload connection closure

ASan/UBSan server tests passed locally, and the asynchronous server/connection tests passed in the dedicated TSan build. Passing sanitizer runs do not prove the absence of memory or concurrency bugs. TSan is a local validation path, not currently a blocking CI job. `clang-tidy` is also not currently CI-blocking because its baseline contains reviewed outstanding warnings.

## Build and Run

The development server binds only to:

```text
127.0.0.1:1234
```

Build and run on macOS:

```bash
cmake --preset macos-arm64
cmake --build build/macos-arm64
./build/macos-arm64/seftp_server_cpp
```

Run the test suite:

```bash
ctest --test-dir build/macos-arm64 --output-on-failure
```

Build and run ASan/UBSan server tests on macOS:

```bash
cmake --preset macos-arm64-sanitizers
cmake --build build/macos-arm64-sanitizers --target seftp_server_cpp_tests
./build/macos-arm64-sanitizers/seftp_server_cpp_tests
```

Build and run ThreadSanitizer tests separately:

```bash
cmake --preset macos-arm64-tsan
cmake --build build/macos-arm64-tsan --target seftp_server_cpp_tests
TSAN_OPTIONS="halt_on_error=1:exitcode=66" ./build/macos-arm64-tsan/seftp_server_cpp_tests
```

Check formatting without modifying files:

```bash
find server_cpp -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0 | \
    xargs -0 clang-format --dry-run --Werror
```

For `clang-tidy` on macOS, use the active SDK to resolve the C++ standard library:

```bash
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" \
    clang-tidy -p build/macos-arm64 server_cpp/src/server_main.cpp
```


Basic listener checks:

```bash
nc -vz 127.0.0.1 1234
lsof -nP -iTCP:1234 -sTCP:LISTEN
```

## Current Limitations

The C++ server is not yet feature-compatible with the stable Python server.

Not yet implemented:

- real Stage 7 cryptographic handshake payloads
- RSA server identity and transcript signing
- SQLite persistence
- registration business logic
- public-key exchange business logic
- reconnect / relogin business logic
- streaming upload request `828`
- AES upload decryption
- CRC retry / final-failure lifecycle parity
- Python-server runtime metrics parity
- application-level graceful draining during shutdown

The current success responses after the handshake are intentionally minimal foundation behavior rather than final application handlers.

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
async connection
    |
    v
async server
    |
    v
server executable
```

Stage 9C deliberately solved networking concurrency and ownership before adding heavier application, persistence, cryptographic, and upload functionality. Future C++ work can build on this model rather than mixing feature parity with unresolved lifetime and synchronization concerns.
