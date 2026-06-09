# Stage 7 Threat Model

## System scope

SEFTP uses a C++ client and Python asyncio server over TCP with a custom binary protocol.

Existing protocol operations:

 - 825 register
 - 826 send client RSA public key and receive AES key
 - 827 relogin
 - 828 encrypted file upload
 - 900/901/902 CRC confirmation flow

Stage 7 focuses on strengthening bootstrap and key establishment without replacing the protocol.


## Assets to protect

1. File confidentiality
Attacker should not read uploaded file contents.
2. File integrity
Attacker should not modify uploaded file contents without detection.
3. Client identity
Attacker should not impersonate an existing registered client.
4. Server identity
Client should know it is talking to the intended server.
5. AES session key
Attacker should not learn, replace, or influence the AES key used for upload encryption.
6. Protocol state
Attacker should not replay old handshake/upload messages to confuse state or bypass validation.


## Attacker capabilities

Assume a network attacker can:

 * observe all TCP traffic
 * modify packets in transit
 * drop packets
 * replay previously captured packets
 * open new TCP connections to the server
 * attempt malformed protocol messages
 * attempt overload or burst traffic

Assume the attacker cannot:

 * break RSA-2048 / AES-256 / SHA-256
 * compromise the server private key
 * compromise the client private key
 * read local client files directly
 * read server database/storage directly


## Current weakness

The current protocol encrypts files, but server identity is not authenticated during bootstrap.

Main issue:

During initial key establishment, the client has no cryptographic proof that it is talking to the real server.

That means a MITM may be able to interfere with the bootstrap flow before the AES key is trusted.


## Threats

### T1: MITM during first connection

Attacker intercepts the first connection and pretends to be the server.

Risk:

 * client may trust the wrong server identity
 * attacker may control bootstrap messages
 * if TOFU is used, attacker can poison the first pinned key

Impact: high
Likelihood: medium
Mitigation:

 * secure mode: pre-configured pinned server public key/fingerprint
 * default mode: TOFU with clear first-use trust boundary


### T2: MITM after first successful pinning

Attacker intercepts a later connection and presents a different server key.

Risk:

 * attacker tries to replace the server identity after trust was established

Impact: high
Likelihood: medium
Mitigation:

 * client rejects changed server fingerprint
 * fail closed, not warning-only

### T3: Replay of old handshake messages

Attacker replays a previous server hello or handshake response.

Risk:

 * client may accept stale handshake data
 * attacker may confuse protocol state

Impact: medium
Likelihood: medium
Mitigation:

 * client nonce
 * server nonce
 * signature covers both nonces
 * handshake transcript hash
 * reject unexpected sequence/order

### T4: AES key substitution or downgrade

Attacker tries to influence which AES key is used or forces weaker behavior.

Risk:

 * attacker causes client/server to use an attacker-controlled or stale key
 * attacker downgrades security version

Impact: high
Likelihood: medium
Mitigation:

 * bind AES key establishment to verified server identity
 * sign `1602` / `1605` AES key responses over the Stage 7 AES key binding transcript
 * include client_nonce and server_nonce in the AES key binding transcript
 * include response_code in the AES key binding transcript to prevent cross-response replay
 * include protocol/security version in signed handshake
 * reject unsupported or downgraded versions

### T5: Client impersonation

Attacker reuses client_id or username to impersonate a client.

Risk:

 * attacker may attempt relogin or upload as another user

Impact: high
Likelihood: medium
Current mitigation:

 * client private key required to decrypt AES key
 * server validates registered client metadata

Stage 7 mitigation:

 * bind relogin/key exchange to verified handshake
 * consider challenge/response proof-of-private-key in later extension

### T6: Upload tampering

Attacker modifies encrypted upload chunks.

Risk:

 * decrypted file becomes corrupted
 * CRC mismatch catches accidental or malicious corruption, but CRC is not cryptographic authentication

Impact: medium/high
Likelihood: medium
Current mitigation:

 * AES-CBC encryption
 * CRC32 validation

Problem:

CRC32 is integrity checking, not cryptographic authenticity.

Future mitigation:

 * add HMAC or move to AEAD mode such as AES-GCM
 * for Stage 7, document limitation clearly unless we choose to extend upload authentication now

### T7: DoS / abuse

Attacker opens many connections, sends malformed frames, or triggers expensive crypto/upload work.

Risk:

 * resource exhaustion
 * executor saturation
 * upload slots exhausted

Impact: medium/high
Likelihood: high
Current mitigation:

 * global connection limits
 * per-IP connection limits
 * upload limits
 * bounded executor
 * request validation
 * early 1607 rejection
 * handshake timeout
 * upload inactivity timeout
 * per-session request burst limiting

Stage 7 mitigation:

 * connection rate limiting
 * stricter handshake timeout
 * reject unauthenticated clients before expensive work
 * malformed handshake tests


## Trust model options

### Option A: TOFU

Client stores server fingerprint on first successful connection.

Pros:

 * simple
 * fits current project
 * similar to SSH user experience

Cons:

 * first connection is still MITM-sensitive

Use as default/dev mode.

### Option B: Pre-configured pinned server key

Client ships with or receives server fingerprint out-of-band.

Pros:

 * blocks MITM from first connection
 * simple to implement
 * strong portfolio value

Cons:

 * requires secure distribution of the fingerprint/key

Use as secure mode.

### Option C: Certificate-based trust

Server presents a certificate chain.

Pros:

 * standard internet-scale solution

Cons:

 * much more complex
 * risks becoming partial TLS reimplementation

Keep as future direction, not Stage 7 core.


## Recommended Stage 7 decision

Implement:

1. Server identity keypair
2. CLIENT_HELLO / SERVER_HELLO handshake
3. Server signature over handshake transcript
4. Client verification
5. TOFU mode
6. Pinned server fingerprint mode
7. Tests for MITM-style key change and replay attempts

Do not implement full TLS, certificates, or upload streaming yet.


## Important limitation to document

TOFU does not prevent MITM on the first connection.

Pinned server key does.

Therefore Stage 7 should claim:

"SEFTP adds authenticated server identity with TOFU and optional pre-configured pinning. TOFU protects subsequent connections after first trust, while pinned mode protects from the first connection."

## Implementation Status

The Stage 7 core server-identity handshake has been implemented in `v0.7.0`.

Implemented:

- server identity keypair
- `829 CLIENT_HELLO`
- `1608 SERVER_HELLO`
- `830 CLIENT_HANDSHAKE_ACK`
- signed handshake transcript
- client-side signature verification
- TOFU mode using `server.fingerprint`
- pinned fingerprint mode using `server.pin`
- router gating before handshake completion
- tests for malformed and repeated handshake paths
- signed AES key binding for `1602` and `1605`
- client-side AES key binding verification before AES key decryption
- owner-only permissions for sensitive local/server key files
- key lifecycle hardening for private key overwrite and corruption handling
- handshake timeout
- request burst limiting

Still deferred:

- certificate-based trust
- mutual client authentication
- authenticated encryption / AEAD
- forward secrecy
- upload streaming encryption
- platform-native secure key storage beyond filesystem permissions
- deployment-level abuse protection beyond application-level limits