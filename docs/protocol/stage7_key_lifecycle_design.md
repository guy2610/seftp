# Stage 7 Key Lifecycle Design

## 1. Scope

This document defines the key lifecycle policy for Stage 7.

It focuses on the lifecycle of local and protocol-related key material after the Stage 7 server-identity handshake has already been implemented.

This document covers:

- client private key lifecycle
- client AES key lifecycle
- server identity fingerprint lifecycle
- pinned server fingerprint behavior
- server identity key lifecycle
- overwrite, invalidation, and recovery behavior

This document does not introduce platform-native secure storage yet. Filesystem permission hardening was already implemented as the first local-storage hardening layer. Future work may evaluate Keychain, DPAPI, Linux keyrings, or encryption-at-rest.

## 2. Current Key Material

### Client-side files

The client currently persists the following local files:

- `me.info`
  - stores username
  - stores persistent client ID
  - may store the client public key in Base64

- `priv.key`
  - stores the client's RSA private key in DER format
  - used to decrypt server-issued AES keys

- `aes.key`
  - stores the latest server-issued AES key in Base64
  - used for file encryption during uploads

- `server.fingerprint`
  - stores the trusted SHA-256 fingerprint of the server identity public key
  - created automatically in TOFU mode after first successful server verification

- `server.pin`
  - optional manually provisioned pinned server fingerprint
  - never created automatically by the client

### Server-side files

The server currently persists:

- `server_identity.pem`
  - persistent RSA private identity key
  - used to sign the Stage 7 `SERVER_HELLO` transcript

### Server-side database state

The server persists client metadata in SQLite, including:

- client ID
- username
- stored client public key
- latest server-generated AES key
- upload metadata and lifecycle state

## 3. Current Behavior

### First-time registration

On first registration:

1. Client receives a server-issued client ID.
2. Client generates a new RSA keypair.
3. Client stores the private key locally in `priv.key`.
4. Client sends the public key to the server.
5. Server generates an AES key.
6. Server encrypts the AES key using the client's public key.
7. Client decrypts the AES key using `priv.key`.
8. Client stores the AES key locally in `aes.key`.

### Relogin

On relogin:

1. Client loads identity from `me.info`.
2. Client sends relogin request `827`.
3. Server validates the client identity and stored public key.
4. Server generates a fresh AES key.
5. Server encrypts the AES key using the stored client public key.
6. Client decrypts the AES key using `priv.key`.
7. Client overwrites `aes.key` with the new AES key.

### Server identity trust

Before registration or relogin:

1. Client sends `829 CLIENT_HELLO`.
2. Server returns `1608 SERVER_HELLO`.
3. Client verifies the server signature.
4. Client calculates `SHA-256(server_public_key_der)`.
5. Client validates the fingerprint using either pinned mode or TOFU.
6. Client sends `830 CLIENT_HANDSHAKE_ACK`.
7. Application-level protocol requests may proceed.

## 4. Problems

### 4.1 Private key overwrite risk

`priv.key` is part of the client's persistent identity.

If it is overwritten silently, the client may no longer be able to decrypt AES keys encrypted to the public key stored on the server.

This can create a public/private key mismatch:

- server has old public key
- client has new private key
- relogin appears valid until AES decryption fails

This failure mode is confusing and dangerous.

### 4.2 Private key corruption or deletion

If `me.info` exists but `priv.key` is missing or corrupted, the client has identity metadata but cannot prove possession of the corresponding private key.

Automatically generating a new private key in this state would not repair the server-side public key mismatch.

### 4.3 AES key staleness

`aes.key` is less identity-critical than `priv.key`.

The server already generates a fresh AES key during registration and relogin. Therefore, a missing or stale `aes.key` can usually be recovered through relogin.

### 4.4 Server fingerprint mismatch

If `server.fingerprint` exists and the current server fingerprint differs, the client cannot distinguish between:

- legitimate server identity rotation
- connecting to the wrong server
- MITM attack

Automatically replacing the fingerprint would defeat TOFU.

### 4.5 Pinned fingerprint mismatch

If `server.pin` exists and the current server fingerprint differs, this is a hard trust failure.

Pinned mode is expected to fail closed.

### 4.6 Server identity rotation

The server may eventually need to rotate `server_identity.pem`.

However, changing the server identity key breaks existing TOFU and pinned clients unless a controlled migration mechanism exists.

Stage 7 does not yet define an automatic server identity rotation protocol.

## 5. Proposed Policies

### 5.1 Client private key regeneration policy

The client must not silently overwrite an existing `priv.key`.

A new RSA private key may be generated only during first-time registration when no local identity exists, or during a future explicit local identity reset flow.

If `me.info` exists but `priv.key` is missing, unreadable, or corrupted, the client must fail closed and report that manual identity recovery or reset is required.

This prevents accidental client identity loss and avoids public/private key mismatch with the server-side stored public key.

Policy summary:

- `priv.key` does not exist and no local identity exists: generate new key.
- `priv.key` exists and is valid: reuse it.
- `priv.key` exists but is corrupted: fail closed.
- `me.info` exists but `priv.key` is missing: fail closed.
- generating a new `priv.key` over an existing one: forbidden by default.

### 5.2 Client private key overwrite policy

The client must refuse to overwrite `priv.key` by default.

Future explicit reset behavior may support backup and regeneration, but it must not happen implicitly during normal registration, relogin, or recovery.

A future reset flow should be explicit and should back up or remove related local identity state together:

- `me.info`
- `priv.key`
- `aes.key`
- possibly `server.fingerprint`

Until such a flow exists, the correct behavior is to fail with a clear error.

### 5.3 AES key lifecycle policy

`aes.key` may be overwritten when the server sends a new AES key during registration or relogin.

This is acceptable because the AES key is session/transfer material issued by the server, not the client's long-term identity key.

Policy summary:

- missing `aes.key`: recover through registration or relogin.
- corrupted `aes.key`: recover through relogin if possible.
- new AES key from server: overwrite `aes.key`.
- AES key size invalid after decryption: fail the current flow.

### 5.4 Server fingerprint policy in TOFU mode

If `server.pin` does not exist, the client uses TOFU mode.

Policy summary:

- no `server.fingerprint`: store the verified server fingerprint after successful signature verification.
- matching `server.fingerprint`: allow connection.
- mismatching `server.fingerprint`: fail closed.
- automatic fingerprint replacement: forbidden.

The client should report a clear error such as:

`server fingerprint mismatch; possible server rotation or MITM; manual trust reset required`

### 5.5 Server fingerprint policy in pinned mode

If `server.pin` exists, the client uses pinned mode.

Policy summary:

- matching `server.pin`: allow connection.
- mismatching `server.pin`: fail closed.
- `server.fingerprint` must not override `server.pin`.
- client must never auto-update `server.pin`.

Pinned mode is stricter than TOFU and represents an externally trusted server identity.

### 5.6 Server identity key lifecycle policy

The server must not silently rotate `server_identity.pem`.

If `server_identity.pem` exists, the server loads and reuses it.

If it does not exist, the server creates it once.

If the file is unreadable or corrupted, the server should fail startup rather than silently generating a new identity key.

This avoids accidental server identity rotation that would break TOFU and pinned clients.

Policy summary:

- missing `server_identity.pem`: generate new server identity key.
- existing valid `server_identity.pem`: reuse.
- existing corrupted `server_identity.pem`: fail startup.
- automatic overwrite: forbidden.

### 5.7 Local file permission policy

Sensitive key files must be owner-readable and owner-writable only.

Current covered files:

- `priv.key`
- `aes.key`
- `server.fingerprint`
- `server_identity.pem`

Expected permission mode on Unix-like systems:

`0600`

This is the first local-storage hardening layer.

Future stronger local storage may include:

- macOS Keychain
- Windows DPAPI
- Linux Secret Service or keyrings
- local encryption-at-rest

## 6. Implementation Plan

### Phase 1: Document policy

Add this document and align the Stage 7 roadmap with the policy decisions.

### Phase 2: Enforce private key overwrite behavior

Add a guard before generating or saving a new `priv.key`.

Expected behavior:

- if key generation is requested and `priv.key` already exists, refuse unless this is a controlled first-time registration path with no existing identity.
- normal flows must not overwrite `priv.key`.

### Phase 3: Harden corrupted private key handling

When relogin requires `priv.key` and loading fails:

- do not generate a replacement key.
- fail closed.
- report manual identity reset requirement.

### Phase 4: Harden server identity loading

Update server identity behavior:

- generate `server_identity.pem` only if missing.
- if the file exists but cannot be imported as a valid RSA key, fail startup.
- do not replace it automatically.

### Phase 5: Add tests

Client tests:

- `priv.key` is not overwritten when already present.
- corrupted `priv.key` causes fail-closed behavior.
- missing `aes.key` can be recovered through relogin.
- fingerprint mismatch fails closed.
- pinned mismatch fails closed.

Server tests:

- missing `server_identity.pem` creates a new key.
- existing valid `server_identity.pem` is reused.
- existing weak permissions are repaired to `0600`.
- corrupted `server_identity.pem` fails instead of being overwritten.

## 7. Non-Goals

This document does not implement:

- automatic server identity rotation
- certificate authority support
- platform-native secure storage
- password-based encryption of local keys
- resumable upload recovery
- multi-device client identity synchronization

These may be considered in future stages.

## 8. Summary

Stage 7 has already implemented authenticated server identity and the first local-storage hardening layer.

The next key lifecycle step is to make key behavior explicit and safe:

- do not silently overwrite long-term private identity keys.
- allow AES keys to rotate through normal registration and relogin.
- fail closed on server fingerprint mismatch.
- fail closed on pinned fingerprint mismatch.
- do not silently rotate server identity.
- require explicit future reset behavior for destructive local identity changes.

This keeps the protocol predictable, reduces confusing recovery behavior, and avoids accidental loss of cryptographic identity.