# Setup and Usage

This document contains the detailed setup, runtime configuration, server limits, and client usage instructions that were moved out of the top-level README.

The top-level README is intentionally kept as a short project overview. This file preserves the operational detail from the original README.

---

## Prebuilt Client (Windows x64)

A prebuilt Windows x64 client binary is available.

- No build required
- Includes example runtime configuration
- Built in Release mode

Download:
A prebuilt Windows x64 client binary is currently available for v0.5.0.

https://github.com/guy2610/Portfolio/releases/tag/v0.5.0-win-x64

Run:
1. Start the server (see below)
2. Extract the zip
3. Edit `transfer.info`
4. Run `SEFFP-CLIENT.exe`

---

---

## Server Limits (Environment Variables)

The server enforces defensive runtime limits.  
Defaults can be overridden via environment variables:

- `SEFTP_MAX_FILE_SIZE` (default: 100MB)
- `SEFTP_MAX_PACKETS` (default: 12000)
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

### Server

* Python 3.9+
* PyCryptodome

```
pip install pycryptodome
```

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

#### Start Server
```
cd server
python server_async.py
```
#### Run Client

Place `transfer.info` in the same directory as the executable, then run:
```
seffp_client.exe
```

The client will:

- Load configuration from transfer.info
- Connect and authenticate with the server
- Start the interactive console UI
- Allow single-file or batch uploads
- Validate CRC and retry if necessary

### Detailed Setup

#### 1. Start the server

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
To clone only this project without downloading the entire portfolio:
git clone --depth 1 --filter=blob:none --sparse https://github.com/guy2610/Portfolio.git
cd Portfolio
git sparse-checkout init --cone
git sparse-checkout set Secure-Encrypted-File-Transfer-Protocol
cd Secure-Encrypted-File-Transfer-Protocol
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
.\seffp_client.exe
```

### Notes:

- `transfer.info` is automatically copied next to the built executable.
