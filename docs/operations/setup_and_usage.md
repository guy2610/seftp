# Setup and Usage

This document contains the detailed setup, runtime configuration, server limits, and client usage instructions that were moved out of the top-level README.

The top-level README is intentionally kept as a short project overview. This file preserves the operational detail from the original README.

---

## Windows Client

No prebuilt Windows client binary is currently attached to the GitHub releases.

Release history and source archives are available at:

https://github.com/guy2610/seftp/releases

Build the client from source using the instructions below.

---

---

## Stable Python Server Limits (Environment Variables)

The stable Python server enforces defensive runtime limits.
Defaults can be overridden via environment variables:

- `SEFTP_MAX_FILE_SIZE` (default: 100MB)
- `SEFTP_MAX_PACKETS` (default: 65535)
- `SEFTP_MAX_CHUNK_SIZE` (default: 64KB)
- `SEFTP_MAX_PAYLOAD_SIZE` (default: 10,000,000 bytes)
- `SEFTP_IDLE_TIMEOUT_S` (default: 60)
- `SEFTP_UPLOAD_INACTIVITY_TIMEOUT_S` (default: 20)
- `SEFTP_READ_TIMEOUT_S` (default: 10)
- `SEFTP_LOG_LEVEL` (default: INFO)
- `SEFTP_MAX_CONCURRENT_UPLOADS` (default: 10)
- `SEFTP_MAX_CONNECTIONS` (default: 10)
- `SEFTP_MAX_CONNECTIONS_PER_IP` (default: 10)
- `SEFTP_CPU_WORKER_THREADS` (default: 4)
- `SEFTP_CPU_MAX_IN_FLIGHT` (default: 8)

Violations of size or sequencing constraints result in a `1607` error response.

---

---

## Requirements

### Stable Python Server

* Python 3.9+
* PyCryptodome

```
pip install pycryptodome
```

### Experimental C++ Server

* C++17 compiler
* CMake 3.21+
* vcpkg
* Boost.Asio / Boost.System
* GoogleTest for tests

### Client (Build from source)

* C++17 compiler
* CMake 3.21+
* vcpkg
* Boost (via vcpkg)
* Crypto++ (via vcpkg)

---

---

## Running the Project

### Quickstart

#### Start Stable Python Server
```
cd server
python server_async.py
```

#### Start Experimental C++ Server

From the repository root on macOS:

```bash
cmake --preset macos-arm64
cmake --build build/macos-arm64
./build/macos-arm64/seftp_server_cpp
```

The current Stage 9C development executable listens only on:

```text
127.0.0.1:1234
```

It uses asynchronous Boost.Asio networking and runs one `io_context` from four worker threads. `AsyncServer` state is serialized through a server strand and every `AsyncConnection` has its own strand.

Verify the TCP listener with:

```bash
nc -vz 127.0.0.1 1234
lsof -nP -iTCP:1234 -sTCP:LISTEN
```

Stop it with `Ctrl+C`. `SIGINT` / `SIGTERM` trigger controlled shutdown of the acceptor and active connections.

The C++ server also enforces a bounded active-connection count (default 128), per-connection read timeouts, and delayed retry after unexpected accept failures.

The C++ server is still experimental. It does not yet provide full Stage 7 cryptographic handshake payloads, SQLite persistence, registration/key-exchange business logic, streaming upload handling, or full compatibility with the stable Python server.

##### C++ server tests

```bash
cmake --build build/macos-arm64
ctest --test-dir build/macos-arm64 --output-on-failure
```

Stage 9C was additionally validated with ThreadSanitizer. Stage 9C.1 adds explicit CMake presets for ASan/UBSan and TSan; these are development-validation builds, not alternate runtime protocol modes.

##### C++ server quality checks (Stage 9C.1)

Formatting (requires `clang-format` 23.1.1 for reproducibility):

```bash
find server_cpp -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0 | \
    xargs -0 clang-format --dry-run --Werror
```

Static analysis on macOS (requires `clang-tidy` and an existing `compile_commands.json` from the CMake build):

```bash
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" \
    clang-tidy -p build/macos-arm64 server_cpp/src/server_main.cpp
```

`clang-tidy` currently has reviewed outstanding warnings and is not a blocking CI check. Neither formatting nor analysis commands above modify source code.

ASan/UBSan server tests:

```bash
cmake --preset macos-arm64-sanitizers
cmake --build build/macos-arm64-sanitizers --target seftp_server_cpp_tests
ASAN_OPTIONS="halt_on_error=1" UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    ./build/macos-arm64-sanitizers/seftp_server_cpp_tests
```

TSan server tests (separate build; cannot be combined with ASan/UBSan):

```bash
cmake --preset macos-arm64-tsan
cmake --build build/macos-arm64-tsan --target seftp_server_cpp_tests
TSAN_OPTIONS="halt_on_error=1:exitcode=66" \
    ./build/macos-arm64-tsan/seftp_server_cpp_tests
```

Compiler warnings are applied to C++ server and test targets via CMake. GitHub Actions runs regular C++ builds and tests on Ubuntu/Windows plus an Ubuntu-only formatting job and ASan/UBSan server-test job. TSan remains a local validation path, and `clang-tidy` remains non-blocking.

#### Run Client

Place `transfer.info` in the same directory as the executable, then run:
```
seftp_client.exe
```

The client will:

- Load configuration from transfer.info
- Connect and authenticate with the server
- Start the interactive console UI
- Allow single-file or batch uploads
- Validate CRC and retry if necessary

### Detailed Setup

#### 1. Start the stable Python server

```
Prerequisites (persistence)

On startup, the server initializes the SQLite database under server/data/ if it does not already exist.

Client metadata and upload records are persisted in SQLite during runtime.

cd server
python server_async.py
(python server_tirgul.py legacy not in use)
*(server_tirgul.py is kept for reference only and is not maintained.)*
```

#### 2. Prepare client configuration

Edit:

```
client/transfer.info
```

Format:

```
127.0.0.1:1256
myuser
file name (not in use)
```
#### Example `transfer.info`

```text
127.0.0.1:1234
Michael Jackson
New_product_spec.docx
```

---

---

## Client CLI

Optional runtime flags:

- `--info` - run with info-level logs
- `--debug` - enable debug logs
- `--debug=0/1` - explicit debug toggle
- `--files=file1 file2 ...` - upload multiple files without entering the interactive menu (separated by space)

Positional file arguments are also supported for backward compatibility.

### Interactive Console Mode

When no `--files` argument is provided, the client starts in interactive console mode.

Available actions:

- Connect / reconnect
- View connection status
- Send a single file
- Send a batch of files
- Exit cleanly

Interactive batch mode accepts space-separated file paths.


### 3. Build from Source (Windows, CMake + vcpkg)

### Prerequisites

- Visual Studio 2022 (Desktop C++ workload)
- Git
- Python 3.9+ (for server)

### Clone Project
```
git clone https://github.com/guy2610/seftp.git
cd seftp
```

### Setup vcpkg
```
git clone https://github.com/microsoft/vcpkg
.\vcpkg\bootstrap-vcpkg.bat
```

### Build (Windows, VS2022)
```
cmake --preset vs2022-x64 --fresh
cmake --build --preset release
```

### Run
```
cd build\Release
.\seftp_client.exe
```

### Notes:

- `transfer.info` is automatically copied next to the built executable.
