# Skink Roadmap

Target: **10/10** — reliability, security depth, and operational flexibility while keeping the single-binary, CLI-first philosophy.

## Priority Order

1. [Session resumption + relay HA](#critical-features-must-have-for-1010)
2. [Resource controls + per-tunnel limits](#critical-features-must-have-for-1010)
3. [Forward secrecy + integrity verification](#critical-features-must-have-for-1010)
4. [Dynamic split tunneling + obfuscation](#strong-differentiators-high-value)

---

## Critical Features (Must-Have for 10/10)

### Relay Clustering / High Availability
Support running multiple relay instances that share tunnel state (active tunnels, private tokens, port allocations) so tunnels survive individual relay failures.

### Session Resumption & Persistent Tunnels
Allow tunnels to automatically reconnect and resume after network drops, restarts, or relay failover without manual intervention (with configurable persistence).

### Per-Tunnel Resource Controls
`--max-connections`, `--bandwidth-limit`, `--idle-timeout`, `--memory-limit` per tunnel (enforced on the relay).

### Protocol Versioning & Backward Compatibility
Clean wire protocol versioning so future changes don't break old clients/relays.

### End-to-End Integrity Verification
Optional cryptographic hash verification for tunneled streams (beyond just encryption).

### Built-in Relay Authentication Options
Add SSH public key auth and mTLS for relay control plane (in addition to current PAKE/bearer).

## Strong Differentiators (High Value)

- **Dynamic Split Tunneling Rules** — Support domain-based routing (not just CIDR), regex, or geobased bypass (via MaxMind or simple lists).
- **Traffic Obfuscation Layer** — Pluggable obfuscation (e.g. random padding, timing jitter, mimic common protocols) on top of existing transports.
- **QUIC Improvements** — 0-RTT support where safe, and better multiplexing fairness.
- **UDP Tunnel Enhancements** — Better NAT traversal (ICE/STUN/TURN built-in, not just framing).
- **Forward Secrecy** — Add PFS to all tunnel handshakes (including Noise and base PAKE flows).
- **Audit Logging** — Optional tamper-evident audit log of tunnel creation, access tokens used, connection events (for enterprise/self-hosted use).

## Quality & Polish Features

- **Connection Migration** — Seamlessly move active tunnels between relays or transports without dropping connections.
- **Circuit Breaker & Health Awareness** — Automatic failover to backup relays or transports when quality drops.
- **Compression Options** — Per-tunnel configurable compression (zstd, brotli) with auto-negotiation.
- **Selective Proxying** — In SOCKS5 mode, allow fine-grained allow/deny lists per application or domain.
- **Noise Protocol Enhancements** — Support more Noise patterns (e.g. KK, IK) and key rotation.
- **File Transfer Upgrades**:
  - Directory sync mode (like a lightweight rsync over the encrypted channel)
  - Delta transfers / block-level resume for large files

## Advanced / Power-User Features

- **Plugin System** — Official plugin interface for custom transports, authentication methods, or stream processors.
- **Embedded Relay Mode** — Ability to run a lightweight embedded relay inside the tunnel client for direct P2P fallback.
- **Rate Limit & Quota System** — Configurable global and per-client quotas on relays.
- **Wire-Level Compatibility Mode** — Option to speak a subset of Chisel/frp protocol for easier migration.
