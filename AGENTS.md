# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

## Child DOX Index

Project root owns project-wide build, release, and CI concerns. Each child owns its own scope.

- **`src/skink/`** — Core file transfer engine. Contains `skink.go` (~3k lines) with send/receive/relay logic, PAKE identity exchange, file encoding, progress tracking, peer discovery, and all transfer orchestration. `context.go` provides context wrappers. This is the largest and most complex package — the heart of the application.

- **`src/cli/`** — CLI command definitions and user-facing interface. Defines `skink send`, `skink relay`, `skink tunnel`, `skink exec`, `skink noise-keygen`, and generic receive modes. Owns flag parsing, help text, usage examples, `Run()` entry point, JSON logging (`log.go`), structured JSON output (`output.go`), and dual binary build tags (`cli_notunnel.go`). Provides AI-agent support via `--output json`, `--agent` meta-flag, and semantic exit codes.

- **`src/tcp/`** — TCP relay server for file transfers. Handles relay connections, room management, PAKE handshake, encrypted communication, and the WebSocket/SSE/Stdio UI. Includes `defaults.go`, `options.go`, `ctx.go`, `tcp.go`, and tests.

- **`src/tunnel/`** (AGENTS.md) — Reverse tunnel system (ngrok-like). Contains client and server for exposing local services through a public relay. Owns the tunnel protocol, PAKE-based registration, heartbeat, reconnection, lifecycle management, private sharing, REST API, config hot-reload, QUIC transport (`transport_quic.go`), zero-copy splice (`zerocopy_linux.go`), StreamSession abstraction (`stream_session.go`), and fuzz tests. Files: `protocol.go`, `protocol_test.go`, `config.go`, `config_fuzz_test.go`, `registry.go`, `server.go`, `client.go`, `client_test.go`, `security_test.go`, `stream_session.go`, `transport_quic.go`, `transport_ws.go`, `transport_pipe.go`, `transport_pipe_windows.go`, `zerocopy_linux.go`, `zerocopy_other.go`, `fuzz_test.go`, `api.go`, `keygen.go`, `store.go`, `embed.go`, `rekey.go`, `stun.go`, `health.go`, `metrics.go`, `reloader.go`, `secret.go`, `relayhop.go`.

- **`src/proxy/`** (AGENTS.md) — HTTP, TCP, and UDP reverse proxy layer for the tunnel system. Routes public connections through registered tunnels. Files: `http.go`, `tcp.go`, `udp.go`, `manager.go`.

- **`src/comm/`** — Communication primitives: length-framed read/write with timeouts and a `MAGIC_BYTES` prefix (`"Skink"`). `Write` prepends `MAGIC_BYTES` + 4-byte little-endian length; `Read`/`Receive` must read exactly `len(MAGIC_BYTES)` bytes for the magic check (a 4-vs-5 byte mismatch silently breaks every comm session — file transfer, tunnel PAKE, relay hops). **`Dial(address, timeout)` is the shared proxy-aware dialer**: when `Socks5Proxy`/`HttpProxy` are set (global `--socks5`/`--connect`) it routes through the proxy with remote DNS (`.onion` resolves via Tor); local addresses bypass the proxy. Used by `NewConnection` (file transfer) and all tunnel client egress dials (control, data, WSS, multi-hop). QUIC cannot use it and dials directly.

- **`src/compress/`** — Compression wrapper (currently gzip/deflate).

- **`src/crypt/`** (AGENTS.md) — Encryption layer using NaCl secretbox (XChaCha20-Poly1305) and AES-GCM, with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations, 16-byte salt per NIST SP 800-132). The PBKDF2 parameters are protocol-breaking — both peers must match.

- **`src/message/`** — Message type definitions and send/receive encoding. Defines all protocol message types including tunnel messages.

- **`src/models/`** — Shared constants (DEFAULT_RELAY, TCP_BUFFER_SIZE), DNS resolution (local + public DNS servers), and config path management.

- **`src/mnemonicode/`** — Human-readable code word generation for transfer codes.

- **`src/utils/`** — File helpers, config directory resolution, temp file marking/cleanup, stdin readiness detection.

- **`src/install/`** — Build-time version injection (`updateversion.go`).

- **`src/mcp/`** — MCP (Model Context Protocol) server for AI agent integration. Wraps Skink CLI via `os/exec` with `--agent` flag. Files: `tools.go`, `resources.go`, `client.go`, `guard.go`.
- **`cmd/mcp/`** — MCP server binary entry point (`skink-mcp`). Stdio transport for local agent integration.
- **`src/docs/`** — Documentation assets (currently empty of Go files).

- **`.agents/`** (AGENTS.md) — Project-level agent skills in agentskills.io format (opencode/Claude/Cursor-discoverable). Each skill is a folder under `skills/` with a `SKILL.md` (YAML frontmatter `name` + `description` + optional `metadata`) and optional `references/`. Currently ships `skills/skink/` (how to drive the skink CLI: file transfer, relay, tunnels, scan/exec, Tor/SOCKS5 routing, reverse-shell patterns, `--agent`/MCP integration). Mirrors the user-level install at `~/.agents/skills/skink/` so cloners get the same skill automatically. Update in lockstep with the user-level copy.

- **`.github/workflows/`** — GitHub Actions CI. `release.yml` cross-compiles skink for linux/darwin/windows x amd64/arm64 on every `v*` tag push (and via manual `workflow_dispatch` for existing tags), archives (tar.gz/zip), generates SHA256 checksums, and attaches the binaries to the corresponding GitHub release. Build uses `CGO_ENABLED=0` (static binaries) with `-X github.com/octagono/skink/src/cli.Version=$(tag)` ldflag. Mirrors the local `make release` target (Makefile `RELEASE_LD_FLAGS`).
