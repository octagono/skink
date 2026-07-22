# src/tunnel/ — Reverse tunnel system

## Purpose

An ngrok-like reverse tunnel system built on top of Skink relay infrastructure. Exposes local services (HTTP, TCP, UDP) through a public relay server, with optional private sharing mode (no public port, access by token). Includes Noise Protocol, health checking, Prometheus metrics, REST API, config hot-reload, QUIC transport, zero-copy splice, and fuzz-tested parsers.

## Ownership

This package owns all tunnel protocol logic:

- `protocol.go` — Message structs, tunnel types, `Config` / `ConfigFile` / `RouteRule`, heartbeat config, TLS config, access request/grant structs, send/receive helpers.
- `protocol_test.go` — Unit tests for heartbeat jitter, route rules, proxy ID generation, tunnel types.
- `config.go` — YAML config file loader, `Client.ApplyHotReload` for live config updates.
- `registry.go` — Thread-safe `Registry` with TTL cleanup, subdomain and access token indexes. `TunnelEntry` with stats, concurrency semaphore, `DataHandler`.
- `server.go` — `Server` with dual-listener (control + data), PAKE auth, stream multiplexing, `RequestProxy`, `TunnelEventHandler`, forward proxy (`FWD|`), exec (`EXEC|`), private access (`ACCESS|`), multi-hop relay hop, WSS transport, named pipe, upstream relay registration.
- `client.go` — `Client` with reconnect, PAKE, stream data session (yamux or QUIC), jittered heartbeat, SOCKS5 handler, forward stream opening, TLS wrapping, WSS/pipe/QUIC transport, private access mode (`StartAccess`).
- `stream_session.go` — `StreamSession` interface abstracting yamux and QUIC. `YamuxSessionWrapper` adapts `*yamux.Session`. Both yamux and QUIC sessions satisfy this interface for transparent transport selection.
- `transport_quic.go` — QUIC transport via quic-go. `QuicDial`, `QuicListen`, `QuicSessionWrapper` (StreamSession over native QUIC streams), `QuicStreamConn` (net.Conn adapter), `GenerateEphemeralCert`.
- `zerocopy_linux.go` — Linux-only zero-copy via `splice(2)` through kernel pipe buffer and `sendfile(2)` for file-to-socket. `PipeConnZeroCopy` auto-detects splice eligibility.
- `zerocopy_other.go` — Non-Linux fallback to pooled `io.CopyBuffer`.
- `fuzz_test.go` — Fuzz tests: `FuzzParseStreamID`, `FuzzClassifyStreamID`, `FuzzParseAccessHeader`. Extracts `parseStreamID`/`classifyStreamID`/`parseAccessHeader` as pure functions.
- `config_fuzz_test.go` — Fuzz tests: `FuzzConfigFileYAML`, `FuzzConfigApply`.
- `api.go` — REST API server with JSON endpoints (`/api/v1/status`, `/api/v1/tunnels`, `/api/v1/tunnels/{id}`), optional bearer token auth.
- `transport_ws.go` — `wsConn` net.Conn adapter for gorilla/websocket, utls-based WSS dialer (Chrome JA3), Noise-wrapped WebSocket encryption.
- `transport_pipe.go` / `transport_pipe_windows.go` — Cross-platform named pipe transport (Windows SMB).
- `relayhop.go` — `RelayHop` for multi-hop relay chaining (`--upstream`).
- `noise.go` — Noise Protocol `NK` handshake (flynn/noise), `NoiseConn`, key generation.
- `health.go` — `HealthChecker` with TCP/HTTP probes per tunnel entry.
- `metrics.go` — Prometheus `/metrics` handler, tunnel/proxy/byte counters.
- `reloader.go` — `ConfigReloader` for JSON tunnel defs, `YAMLConfigWatcher` for hot-reload of YAML client config.
- `secret.go` — `SecretSource` interface with `FileSource`/`ExecSource`/`StaticSource` implementations.

## Local Contracts

- **Dual-port design** — Control connections (PAKE + comm.Comm framing) on `port`, stream-multiplexed proxy data on `port+1`.
- **Proxy-aware egress via `comm.Dial`** — All tunnel client dials (control `client.go`, data plane `ensureDataSession`/`getOrCreateDataSession`/`StartAccess`, WSS `transport_ws.go`, multi-hop upstream `relayhop.go`) go through `comm.Dial(addr, timeout)`, which honors the global `--socks5` / `--connect` flags (set into `comm.Socks5Proxy`/`comm.HttpProxy` by the app `Before` hook). Local targets bypass the proxy (`utils.IsLocalIP`). **QUIC (`transport_quic.go`) cannot traverse a TCP SOCKS5/HTTP proxy and dials directly** — use `--transport tcp|wss` to route through Tor/HTTP proxies. Data-port addresses are always built as `host:port+1` (never empty host) so remote relays and `.onion` addresses resolve via the proxy's remote DNS.
- **StreamSession abstraction** — `dataSession` field on `Client` is `StreamSession` (interface), not `*yamux.Session`. Supports yamux (TCP/WSS) and QUIC (native streams) transparently. `getOrCreateDataSession()` selects based on `config.Transport`.
- **Transport selection** — `--transport tcp|wss|quic`. QUIC uses native multiplexing (no yamux, no head-of-line blocking). TCP/WSS use yamux.
- **Proxy connection delivery** — `RequestProxy` stores `chan net.Conn` in `sync.Map pendingProxy[proxyID]` before sending `ReqProxy` over control connection. The stream data delivers the connection.
- **Data stream protocol** — 2-byte big-endian length prefix + payload. Prefix determines stream type: raw proxyID (reverse proxy), `FWD|target` (forward/SOCKS5), `EXEC|cmd` (remote exec), `ACCESS|token|target` (private access), `REG|`/`DATA|` (multi-hop relay).
- **Zero-copy path** — On Linux, `PipeConnZeroCopy` uses `splice(2)` through a kernel pipe buffer for TCP-to-TCP, bypassing user space. Falls back to pooled `io.CopyBuffer` for non-TCP (WSS, QUIC streams, named pipes).
- **Noise Protocol** — `Noise_NK` pattern (server static key), `NoiseConn` wrapping `net.Conn`.
- **Metrics** — Prometheus `/metrics` on configurable port. Also JSON `/status` and `/tunnels`.
- **Buffer pool** — `copyBufferPool` (`sync.Pool` of 32KB `[]byte` slices) in `server.go`. All hot-path data copying uses `io.CopyBuffer` with pooled buffers via `getCopyBuf()`/`putCopyBuf()`. Returns buffers to pool after use.
- **HTTP local connection pool** — `client.go` `localConnPool` (max 16 idle, 30s idle timeout) reuses TCP connections to `config.LocalAddr` for `TunnelTypeHTTP`. Initialized in `NewClient` only for HTTP tunnels; closed in `cleanup()`. TCP/UDP/SOCKS5 tunnels dial fresh per request. `handleProxyRequest` returns the connection via `Put` after bidirectional copy completes.
- **`--yamux-window` flag** — `config.YamuxWindowSize` overrides the default 16MB `MaxStreamWindowSize` in both client data-session paths (`ensureDataSession`, `getOrCreateDataSession`) and server `handleDataSession`. Guard is `if c.config.YamuxWindowSize > 0`.
- **Fuzz testing** — Run `make fuzz` for 30s per target. Fuzz targets in `fuzz_test.go`, `config_fuzz_test.go`, `comm/fuzz_test.go`, `mnemonicode/fuzz_test.go`.

## Work Guidance

- When modifying the proxy connection flow, ensure the data port protocol (2-byte length + prefix on stream) stays in sync between `client.go` and `server.go`'s `handleDataStream`.
- **yamux config: `cfg.LogOutput` must be `io.Discard`, never `nil`.** yamux v0.1.2 `VerifyConfig` rejects sessions where both `Logger` and `LogOutput` are nil (`"one of Logger or LogOutput must be set, select one"`), which silently kills every data session. `DefaultConfig()` sets `LogOutput` to `os.Stderr`; setting it back to `nil` re-introduces the bug.
- **CLI `scan`/`exec` commands dial the data port** (`controlPort+1`, derived via `cli.dataPortAddr`), not the control port — the control port expects a PAKE handshake, not yamux.
- When adding a new transport, implement `StreamSession` and add selection logic in `getOrCreateDataSession`.
- **New tunnel egress dials must use `comm.Dial(addr, timeout)`**, not `net.DialTimeout`, so the global `--socks5`/`--connect` flags apply (Tor/HTTP-proxy routing). QUIC (`transport_quic.go`) is the documented exception — it cannot traverse a TCP proxy.
- The control loop uses a dedicated blocking receive goroutine + channel, NOT polling with read deadlines.
- Any new message type added to the tunnel protocol must also be added to `src/message/message.go`.
- When adding new features that require credential resolution, extend `SecretSource` rather than adding new flag-specific logic.
- Private sharing access flows through the existing `RequestProxy` mechanism — the access stream is bridged to the tunnel's data session, not to the control connection.
- `configMu` protects hot-reloadable config fields on `Client`.
- REST API handlers must never hold registry locks across network I/O.
- Zero-copy splice requires both connections to be `*net.TCPConn`. Non-TCP connections automatically fall back to pooled buffers.
- QUIC connections use native streams — do not wrap in yamux. `QuicSessionWrapper` provides the `StreamSession` interface directly.

## Verification

- `protocol_test.go`: heartbeat jitter, route rules, proxy ID, tunnel types, tunnel state.
- `fuzz_test.go`: `FuzzParseStreamID`, `FuzzClassifyStreamID`, `FuzzParseAccessHeader` — run via `make fuzz`.
- `config_fuzz_test.go`: `FuzzConfigFileYAML`, `FuzzConfigApply`.
- `src/comm/fuzz_test.go`: `FuzzParseFrame`, `FuzzParseFrameOversized`.
- `src/mnemonicode/fuzz_test.go`: `FuzzEncode`, `FuzzEncodeConsistency`.

## Child DOX Index

No child directories. This is a leaf package.
