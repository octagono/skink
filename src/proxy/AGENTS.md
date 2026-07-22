# src/proxy/ — Tunnel proxy layer

## Purpose

HTTP and TCP reverse proxy layer that routes public internet connections through registered tunnels. Bridges the gap between incoming public connections and tunnel client connections.

## Ownership

- `http.go` — `HTTPProxy` using Go's standard `http.Server` + `ServeHTTP` handler. Virtual-host routing via `extractSubdomain(host, domain)`. Password auth via Basic Auth. Forwards HTTP requests through `Server.RequestProxy` and returns responses.
- `tcp.go` — `TCPProxy` per-port listener for raw TCP tunnels. `DynamicTCPProxy` manager that starts/stops listeners on tunnel register/unregister events. Supports `entry.DataHandler` for custom data path handling (e.g. SSH gateway).
- `udp.go` — `UDPProxy` per-port UDP datagram listener. `DynamicUDPProxy` manager. Frames UDP datagrams with 4-byte length prefix and forwards them through yamux streams (obtained via `Server.RequestProxy`). Each unique UDP source address gets its own yamux stream session. Stale sessions are evicted after 60s of inactivity.
- `manager.go` — Shared utilities: `PipeConnections` (bidirectional copy), `ProxyConn` (connection metadata wrapper), `ConnPool` (connection reuse pool), `AuthHandler` (simple password check), `RateLimiter` (per-IP token bucket), `IPAllowlist` (CIDR-based access control).

## Local Contracts

- **HTTP proxy** — Depends on `tunnel.Server.Registry()` for tunnel lookup and `tunnel.Server.RequestProxy()` for establishing the data channel. Extracts subdomain from the `Host` header by removing the configured domain suffix. Port is stripped before matching.
- **TCP proxy** — Depends on `tunnel.Server.Registry().List()` and `tunnel.Server.RequestProxy()`. Each tunnel gets a dedicated listener on its `PublicPort`. No virtual-host routing — port-based matching via `DynamicTCPProxy`.
- **PipeConnections** — Two concurrent `io.Copy` goroutines. Both directions get `Close()` called on both connections when either side finishes. Do not call `PipeConnections` on connections where the caller also holds a reference — ownership transfers.
- **RateLimiter** — Per-key token bucket with configurable rate and window. Not currently wired into the HTTP proxy (available for future use).

## Work Guidance

- When changing the HTTP proxy, ensure `extractSubdomain` stays correct for all host/domain formats (`sub.domain:port`, `sub.domain`, edge cases with matching suffixes).
- The HTTP proxy's `ServeHTTP` writes the full HTTP request via `r.Write(proxyConn)` and reads the response with `http.ReadResponse`. This works because the tunnel data channel is a raw TCP pipe.
- `writeHTTPError` and `writeHTTPAuthRequired` write to raw `net.Conn` — these are for the TCP proxy path and should not be used in the HTTP proxy (which has `http.ResponseWriter`).

## Verification

No test file exists yet.

## Child DOX Index

No child directories. This is a leaf package.
