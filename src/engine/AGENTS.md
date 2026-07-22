# src/engine/ — Plugin architecture

## Purpose

Defines the plugin interfaces for Skink's modular transport/protocol/crypto architecture. Transports, stream multiplexers, tunnel protocols, crypto providers, and proxy drivers all implement these interfaces, enabling runtime registration and compile-time feature selection.

## Ownership

- `engine.go` — Core interfaces: `Transport`, `StreamMultiplexer`, `TunnelProtocol`, `CryptoProvider`, `SecureConn`, `ProxyDriver`. `Registry` for runtime plugin registration. Factory function types for each plugin category.
- `adapters/transports.go` — Concrete adapters wrapping existing implementations: `TCPTransport`, `WSSTransport`, `QUICTransport`. `RegisterAll` registers built-in transports. Hook functions (`SetWSSDial`, `SetQUICDial`, etc.) avoid import cycles between `engine` and `tunnel` packages.

## Local Contracts

- **Transport interface** — `Dial`, `Listen`, `Name`, `IsStreamBased`. When `IsStreamBased()` returns true (QUIC), the yamux layer is bypassed and native streams are used directly.
- **Registry** — Thread-safe registration of transport/protocol/crypto/proxy factories. `GetTransport`, `ListTransports`, `ListProtocols` for runtime discovery.
- **Import cycle avoidance** — The `engine` package cannot import `tunnel` (circular dep). Adapters use hook functions set by the `tunnel` package during init.

## Work Guidance

- When adding a new transport, implement `Transport` and register via `Registry.RegisterTransport`.
- When the transport provides native streams (like QUIC), return `IsStreamBased() = true` so the caller bypasses yamux.
- Keep factory functions simple — they receive a config map and return an interface instance.

## Verification

No tests yet. Interface compliance is verified at compile time by the adapter implementations.

## Child DOX Index

- `adapters/` — Concrete transport implementations wrapping existing Skink code.
