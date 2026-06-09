# Deployment-Level Abuse Protection Guidance
## Scope
This document describes future deployment-level protections around the SEFTP server.

## Application-Level Protection Already Implemented
- connection limits
- per-IP limits
- handshake timeout
- upload inactivity timeout
- upload slot limiter
- bounded executor
- request burst limiter

## Deployment-Level Protections
### TCP Reverse Proxy
- Nginx stream or HAProxy
- connection limits before Python server
- TCP health checks

### Docker Compose Protected Deployment
- seftp-server
- tcp-proxy
- isolated network
- expose only proxy port

### OS / Kernel Limits
- ulimit -n
- listen backlog
- process limits

### Host Firewall
- allow only SEFTP TCP port
- optionally restrict source IPs
- reject unrelated inbound traffic

## Threat Boundary
Application-level limits protect the Python server after traffic reaches it.
Proxy/firewall/kernel controls reduce pressure before traffic reaches the process.
Large-scale public DDoS mitigation remains out of scope.