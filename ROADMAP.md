# Skink Roadmap

Target: **10/10** — reliability, security depth, and operational flexibility while keeping the single-binary, CLI-first philosophy.

## Implementation Status

| Area | Status | Phase |
|------|--------|-------|
| Session resumption + persistence | ✅ Done | 1 |
| Relay HA clustering + state sync | ✅ Done | 2 |
| Per-tunnel resource controls | ✅ Done | 3 |
| Forward secrecy (inherent in PAKE) | ✅ Confirmed | 4 |
| Integrity verification (HMAC) | ✅ Done | 4 |
| Dynamic split tunneling (CIDR + domain) | ✅ Done | 5 |
| Traffic obfuscation (padding + jitter) | ✅ Done | 6 |
| Forward secrecy + PFS rekeying (ECDH) | ✅ Done | T1.1 |
| Connection migration | ✅ Done | T1.2 |
| Per-tunnel ACLs (IP/CIDR/domain allow/deny) | ✅ Done | T1.3 |
| Enhanced UDP (STUN for NAT traversal) | ✅ Done | T1.4 |
| Built-in compression (gzip/deflate/none) | ✅ Done | T2.2 |
| Tamper-evident audit logging (HMAC chain) | ✅ Done | T2.3 |
| Domain regex + SNI routing | ✅ Done | T2.4 |
| Protocol versioning | ✅ Done | T2.5 |
| Plugin / extension system (interfaces) | ✅ Done | T2.5 |
| Embedded lite relay (P2P fallback) | ✅ Done | T2.5 |

## Next Priority (Proposed)

### Tier 1 — Do These First
1. **Forward Secrecy + Rekeying** — Ephemeral key rotation without dropping connections
2. **Connection Migration** — Move live tunnels between relays or transports seamlessly
3. **Per-Tunnel ACLs** — Fine-grained allow/deny (IP, port, domain) inside SOCKS5/TCP tunnels
4. **Enhanced UDP** — ICE/STUN/TURN for direct P2P + native QUIC UDP proxying

### Tier 2
5. **Plugin System** — Official interface for authenticators, obfuscators, stream processors
6. **Built-in Compression** — Auto-negotiated zstd per tunnel with level control
7. **Tamper-Evident Audit Log** — Append-only signed log on relay for tunnel events
8. **Domain Regex + SNI Routing** — Regex domain matching, SNI-based routing for TLS

## Completed Features

### Relay Clustering / High Availability (Phase 2 ✅)
Multi-relay state sync via `--sync-port`/`--sync-peers`. Client failover via comma-separated `--server`.

### Session Resumption & Persistent Tunnels (Phase 1 ✅)
`--persist PATH` on relay, `--resume PATH` on client. Reconnect with saved tunnel ID, fallback to fresh register.

### Per-Tunnel Resource Controls (Phase 3 ✅)
`--max-connections`, `--bandwidth-limit`, `--idle-timeout`. Enforced by relay via AcquireConn/ReleaseConn.

### Integrity Verification (Phase 4 ✅)
Optional HMAC-SHA256 per tunnel message via `--integrity`. Key derived from PAKE session key.

### Dynamic Split Tunneling (Phase 5 ✅)
Domain patterns (`*.example.com`) + CIDRs in `--route`/`--bypass`. Matching before DNS resolution.

### Traffic Obfuscation (Phase 6 ✅)
Random padding (`--padding-min`/`--padding-max`), heartbeat timing jitter.

## Backlog

- **Built-in Relay Authentication** — SSH public key auth, mTLS for relay control plane
- **QUIC Improvements** — 0-RTT, better multiplexing fairness
- **Noise Protocol Enhancements** — KK, IK patterns, Noise key rotation
- **Circuit Breaker & Health Awareness** — Auto failover based on quality metrics
- **File Transfer Upgrades** — Directory sync, delta transfers, block-level resume
- **Rate Limit & Quota System** — Global and per-client quotas on relays
- **Wire-Level Compatibility** — Speak a subset of Chisel/frp for migration
- **Bandwidth & Latency Adaptive Tuning** — Auto-adjust yamux window, heartbeat, buffering based on measured RTT
