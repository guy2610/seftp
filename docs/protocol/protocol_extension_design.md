## Protocol Extension Design (Aligned with Existing Architecture)

Status: Stage 7 core handshake implemented. This document explains the server-identity handshake extension that was added to the protocol in v0.7.0. Broader Stage 7 hardening items remain tracked in the roadmap.

### Goal

Stage 7 introduces authenticated server identity verification during connection bootstrap.

The extension integrates into the existing client flow and server session model without replacing:

- request/response protocol structure  
- 825/826/827 handshake logic  
- AES key establishment  
- upload pipeline  

The goal is to ensure that all existing protocol operations execute only after verifying server identity.

---

### Integration with Existing Flow

#### Client side (flow layer)

The handshake is integrated into:

`flow::connect_and_handshake(...)`

Updated flow:

1. TCP connect
2. Stage 7 handshake:
   - send `829 CLIENT_HELLO`
   - receive `1608 SERVER_HELLO`
   - verify server signature
   - verify server fingerprint using TOFU or pinned mode
   - send `830 CLIENT_HANDSHAKE_ACK`
3. Only after the server receives `830`:
   - continue to existing flow:
     - 825 / 827 / 826
4. Proceed with upload

Important:

The Stage 7 handshake becomes a **mandatory precondition** for all existing flows.

---

#### Server side (session model)

The handshake integrates into `ClientSession` state.

Add fields:

```text
handshake_verified: bool
client_nonce: bytes
server_nonce: bytes
security_version: int
```

Initial state:

```text
handshake_verified = false
```

```text
if not handshake_verified:
    reject with 1607
```

This follows the existing strict validation model already used in the server.

### New Protocol Messages

#### 829 CLIENT_HELLO

client → server

Payload:

| Field | Size |
|------|-----|
| security_version | 1 byte |
| client_nonce | 32 bytes |
| flags | 1 byte |

Notes:

must be first request on connection
server rejects any other request before this

#### 1608 SERVER_HELLO

server → client

Payload:

| Field | Size |
|------|-----|
| security_version | 1 byte |
| server_nonce | 32 bytes |
| server_public_key_len | 2 bytes |
| server_public_key | variable (DER) |
| signature_len | 2 bytes |
| signature | variable |

#### 830 CLIENT_HANDSHAKE_ACK

client → server

Payload:

```text
empty
```

Purpose:

Confirms that the client accepted the server identity after verifying the signature and trust model.

Notes:

- Sent only after successful `SERVER_HELLO` verification
- Completes the Stage 7 handshake
- The server does not process application-level requests before this ACK

### Handshake Signing

Transcript:

```text
"SEFTP_STAGE7_SERVER_HELLO" ||
security_version ||
client_nonce ||
server_nonce ||
server_public_key
```

Server signs with server identity private key.

Client verifies using received server_public_key.

### Important Clarification (Critical)

The signature does not provide trust by itself.

It proves:

 * the sender owns the private key

Trust is established only by:

 * TOFU
 * or pinned fingerprint

### Trust Modes

#### TOFU
 * first connection → store fingerprint
 * next connections → require match

#### Pinned Key
 * client has expected fingerprint in config
 * mismatch → hard fail

### Server Fingerprint
```text
SHA-256(server_public_key_der)
```

Stored client-side alongside existing persistence files.

### Enforcement Rules

#### Server
 * if first request != CLIENT_HELLO → reject (1607)
 * if handshake incomplete → reject all requests
 * malformed → 1607

#### Client

must abort if:

 * signature invalid
 * fingerprint mismatch
 * malformed response
 * unsupported version

No fallback allowed.

### Binding to Existing Protocol
 * 826 AES key exchange remains unchanged
 * but only allowed after handshake

This ensures:

 * AES key is accepted only from a verified server
 * MITM cannot inject unverified key material

### Replay Protection

Uses:

 * client_nonce
 * server_nonce

Replay fails because:

 * client_nonce is fresh per connection
 * signature binds nonce

### Failure Behavior

Must follow existing behavior:

 * return 1607 with error message
 * log with session context

No silent fallback.

### Backward Compatibility

No fallback to old flow.

Rationale:

 * prevents downgrade attacks
 * keeps protocol consistent

### Impact on Existing Architecture

#### Client
 * change only in flow layer
 * protocol layer gets 829 builder + 1608 parser
 * persistence layer gets fingerprint storage

#### Server
 * router must allow 829 before others
 * session gets handshake state
 * all handlers gated by handshake_verified

#### System

No changes to:

 * upload pipeline
 * AES file encryption model
 * CRC flow
 * server database schema

Added persistence files:

 * `data/server_identity.pem` on the server
 * `server.fingerprint` on the client for TOFU
 * optional `server.pin` on the client for pinned mode

### Implementation Summary
Implemented in the Stage 7 core handshake:

1. Protocol definitions for `829`, `1608`, and `830`
2. Persistent server identity key generation/loading
3. Signed `SERVER_HELLO`
4. Server-side handshake session state
5. Router gating before handshake completion
6. Client-side handshake flow before registration/relogin
7. RSA signature verification
8. SHA-256 server fingerprint calculation
9. TOFU persistence through `server.fingerprint`
10. Optional pinned mode through `server.pin`
11. Unit and integration test coverage for handshake edge cases

---

### Known Limitations

Stage 7 improves server identity verification but does not provide a complete authentication or transport security model.

The following limitations remain:

- TOFU mode is vulnerable to MITM on the first connection
- No certificate chain or external trust authority is used
- No mutual authentication between client and server
- AES-CBC encryption does not provide authenticated encryption (no AEAD)
- CRC32 is not a cryptographic integrity mechanism
- No protection against traffic analysis
- No forward secrecy (session keys are server-generated and not ephemeral DH-based)
- No protection against a compromised client machine or leaked private key
- No secure local storage for private keys and AES keys (file-based only)

These limitations are acceptable for the current project scope but should be addressed in future stages.

---

### Security Guarantees

Given correct implementation, Stage 7 provides the following guarantees:

- The client can verify that the server owns the corresponding private key for the presented server public key
- In pinned mode, the client is protected against MITM from the first connection
- In TOFU mode, the client is protected against MITM after the first trusted connection
- The AES key exchange (826) occurs only after server identity verification
- Replay of SERVER_HELLO messages is prevented through nonce binding
- Downgrade attacks are mitigated by including security_version in the signed transcript
- Unauthenticated or malformed connections are rejected early using existing strict validation (1607)
- The existing upload encryption model (AES-256-CBC) continues to protect file confidentiality on the wire

These guarantees strengthen the bootstrap phase without changing the core protocol or upload pipeline.


### Stage 7 AES Key Binding

1602 / 1605 payload for security_version=1:

[16B client_id]
[2B encrypted_key_len]
[encrypted_key]
[2B signature_len]
[signature]

Signature transcript:

"SEFTP_STAGE7_AES_KEY_BINDING"
|| security_version
|| client_nonce
|| server_nonce
|| client_id
|| response_code
|| encrypted_key