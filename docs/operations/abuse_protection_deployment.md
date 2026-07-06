# Deployment-Level Abuse Protection Guidance

## Scope

This document describes deployment-level protections around the SEFTP server.

The SEFTP server already implements application-level abuse protection, including connection limits, per-IP limits, handshake timeout, upload inactivity timeout, upload backpressure, bounded CPU offload, and request burst limiting.

Deployment-level protection is a separate layer. Its goal is to reduce pressure before traffic reaches the Python process and to document how the server should be exposed in safer single-node deployments.

This document is not a claim that SEFTP is production-ready or DDoS-resistant. It is hardening guidance for a portfolio-grade single-node protocol server.

---

## Protection Layers

A hardened deployment should separate responsibility across layers:

```text
Internet / client network
        |
        v
Firewall / host allow rules
        |
        v
TCP-aware reverse proxy
        |
        v
SEFTP Python asyncio server
        |
        v
SQLite + upload storage
```

Each layer protects against a different class of pressure.

- Firewall rules reduce unrelated inbound traffic.
- A TCP proxy can enforce connection-level limits before the Python server accepts sockets.
- The SEFTP server enforces protocol-aware limits after traffic reaches the application.
- OS and process limits bound worst-case resource usage.

---

## Application-Level Protection Already Implemented

The application already includes the following protection mechanisms:

- global active connection limit
- per-IP active connection limit
- Stage 7 handshake timeout
- idle connection timeout
- upload inactivity timeout
- upload slot limiter
- upload backpressure with controlled `1607` rejection
- bounded executor for controlled CPU-heavy work
- request burst limiter for control-plane requests
- strict frame and payload-size validation
- max file size, packet count, chunk size, and payload size limits
- runtime metrics counters for active connections, active uploads, rejected connections, rejected uploads, `1607` responses, and rate-limited requests
- optional local-only HTTP metrics endpoint for process-local visibility

These controls are useful only after a connection reaches the application. They do not replace network-layer controls.

---

## Deployment-Level Protections

### TCP Reverse Proxy

A TCP-aware reverse proxy can sit in front of the SEFTP server.

Possible options:

- Nginx `stream {}` module
- HAProxy TCP mode

The proxy can provide:

- connection limiting before traffic reaches Python
- source-IP based limits
- short TCP health checks
- a single exposed listener while the SEFTP server binds internally
- cleaner separation between public network exposure and application runtime

Recommended topology:

```text
external clients
      |
      v
tcp-proxy exposed port
      |
      v
seftp-server internal port
```

The SEFTP server should prefer binding to an internal interface or container network when placed behind a proxy.

---

## Docker Compose Protected Deployment

A protected Docker Compose profile can model a simple deployment with:

- `seftp-server`
- `tcp-proxy`
- isolated internal network
- only the proxy port exposed to the host
- server data stored in a named volume or explicit bind mount
- metrics endpoint kept local or internal only

Target shape:

```text
host:1256 -> tcp-proxy:1256 -> seftp-server:1256
```

The metrics endpoint should not be published publicly. If enabled, it should remain bound to `127.0.0.1` or an internal-only network unless protected by additional controls.

This is useful for demonstration and local hardening, not as a complete production deployment model.

### Running the Protected Docker Compose Demo

The repository includes a minimal protected deployment demo under:

```text
docker/protected/
```

It starts:

- `seftp-server`, the Python asyncio SEFTP server
- `tcp-proxy`, an HAProxy TCP proxy in front of the server
- an isolated Docker network
- a named volume for server data

Run it from the repository root:

```bash
docker compose -f docker/protected/docker-compose.yml build
docker compose -f docker/protected/docker-compose.yml up
```

In another terminal, smoke-test the exposed proxy port:

```bash
python3 - <<'PY'
import socket

s = socket.create_connection(("127.0.0.1", 1256), timeout=3)
print("connected")
s.close()
PY
```

Stop the demo:

```bash
docker compose -f docker/protected/docker-compose.yml down
```

Expected topology:

```text
host:1256 -> tcp-proxy:1256 -> seftp-server:1256
```

The SEFTP server binds to `0.0.0.0:1256` inside the container so the proxy can reach it over the internal Docker network. The metrics endpoint remains bound to `127.0.0.1:9100` inside the server container and is not published to the host.

---

## OS / Kernel Limits

The host should enforce resource limits outside the application.

Recommended areas to document or configure:

- file descriptor limit, for example `ulimit -n`
- process-level memory and CPU limits
- listen backlog and socket queue sizing
- maximum number of processes or threads
- disk space limits for upload storage
- log rotation to avoid unbounded log growth

The exact values depend on the deployment target and expected workload. The important point is that the process should not rely only on application logic for safety.

---

## Host Firewall

A minimal host firewall policy should:

- allow only the expected SEFTP TCP port
- optionally restrict source IP ranges for private deployments
- reject unrelated inbound traffic
- keep the metrics endpoint private
- avoid exposing SQLite files, upload directories, or internal admin ports

For private deployments, source-IP allowlisting is preferable to exposing the service broadly.

---

## Metrics Endpoint Exposure

Stage 9 adds an optional HTTP metrics endpoint for runtime visibility.

Default behavior:

```text
SEFTP_METRICS_ENABLED=0
SEFTP_METRICS_HOST=127.0.0.1
SEFTP_METRICS_PORT=9100
```

When enabled, it exposes:

```text
GET /metrics
```

The endpoint is intentionally lightweight and process-local. It should be used for local development, benchmarking, and protected deployments.

Do not expose it directly to the public internet. It reveals runtime pressure signals such as active connections, active uploads, rejections, and rate-limited requests.

---

## Threat Boundary

Application-level controls protect the Python server after traffic reaches it.

Proxy, firewall, and kernel controls reduce pressure before traffic reaches the Python process.

Large-scale public DDoS mitigation remains out of scope. That would require infrastructure-level controls such as upstream filtering, provider-level DDoS protection, rate limiting at the edge, and broader operational monitoring.

---

## Recommended Single-Node Hardening Profile

For a safer single-node deployment:

1. Keep the SEFTP server bound internally where possible.
2. Put a TCP-aware proxy in front of it.
3. Expose only the proxy port.
4. Keep the metrics endpoint local-only.
5. Configure OS file descriptor and process limits.
6. Restrict inbound firewall rules.
7. Store uploads and SQLite data in controlled paths.
8. Monitor logs and metrics snapshots during load testing.
9. Treat upload pressure as the dominant resource risk.
10. Prefer controlled rejection over unbounded queueing.

---

## Current Status

Implemented in the application:

- connection limits
- per-IP limits
- handshake timeout
- idle timeout
- upload inactivity timeout
- upload slot limiter
- request burst limiter
- bounded executor
- runtime metrics counters
- optional local-only metrics endpoint

Documented as deployment guidance:

- TCP reverse proxy placement
- Docker Compose protected deployment shape
- OS and kernel limit considerations
- host firewall recommendations
- application-level vs infrastructure-level threat boundary

Future optional work:

- add concrete Nginx stream example
- add concrete HAProxy TCP example
- add Docker Compose protected deployment demo
- add operational checklist for local benchmark runs