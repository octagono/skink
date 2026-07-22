---
name: skink
description: "Use for ANY task involving skink: encrypted file transfer (send/receive files or folders), running a relay, reverse tunnels to expose local services, reverse shells, SOCKS5 pivots, remote command execution, and routing skink through Tor/SOCKS5/HTTP proxies or .onion hidden services. Triggers: 'skink'; 'transfer/send a file securely or encrypted'; 'start/run a relay'; 'expose localhost / a local service publicly'; 'reverse shell'; 'tunnel SSH/RDP/HTTP/web'; 'SOCKS5 proxy/pivot'; 'run a command on/through the relay'; 'route through Tor'; '.onion relay'; skink MCP server; skink --agent/--output json. Also use when installing, configuring, hardening, or debugging a skink relay or tunnel, or wiring skink into an AI agent."
license: MIT
metadata:
  author: octagono
  version: "1.0"
---

# Skink

Encrypted file transfer **and** reverse-tunnel platform (ngrok/frp/Chisel-like). Move files, expose local services, and pivot networks through one encrypted tunnel. Single binary, PAKE identity exchange, XChaCha20-Poly1305 encryption, optional Noise-protocol tunnels, QUIC/WSS transports, multi-hop relay chaining, and SOCKS5/HTTP-proxy routing (incl. Tor).

Assumed in PATH (else `~/.local/bin/skink`). Project + full docs: `README.md`. Deep operational scenarios (reverse shells end-to-end, Tor/onion relay setup, multi-hop chaining, VPS hardening): `references/operations.md`.

## CRITICAL gotchas (agents get these wrong)

1. **`--socks5`, `--connect`, and `--pass` are GLOBAL flags — they MUST come before the subcommand.**
   - OK: `skink --socks5 127.0.0.1:9050 tunnel --server relay:9090 ...`
   - OK: `skink --pass SECRET send file.txt` (or set `SKINK_PASS` env)
   - FAILS: `skink tunnel --server ... --socks5 ...` -> `flag provided but not defined: -socks5`
   - `relay` has NO `--pass` flag at all. Set the relay password via global `--pass` (before `relay`) or `SKINK_PASS` env.

2. **Tunnel data port = control port + 1, and it is not in any flag list.** Control on `--tunnel-port` (default `9090`); the yamux data session runs on `9091` (= control+1). Both must be open in firewalls. Forgetting `9091` is the #1 reason tunnel/exec silently fail to connect.

3. **`tunnel` and `exec` subcommands redefine `--pass` with their own default (`pass123`).** The global `--pass` is shadowed. You MUST pass `--pass` AFTER the subcommand:
   - OK: `skink tunnel --server relay:9090 --pass REALPASS ...`
   - FAILS: `skink --pass REALPASS tunnel --server relay:9090 ...` (global ignored, uses `pass123` → PAKE handshake EOF)

4. **Only `--transport tcp` and `wss` traverse a SOCKS5/HTTP proxy (Tor).** QUIC uses UDP and cannot go through a TCP proxy. Use `--transport tcp|wss` when proxying.

5. **Local targets bypass `--socks5` automatically** (loopback, LAN/private IPs, `localhost` via `IsLocalIP`). A remote or `.onion` relay is proxied; a localhost relay is dialed direct. To test proxy routing, point at a non-local server.

6. **HTTP tunnels require auth headers to curl.** The relay allocates a subdomain + bearer token. Access requires BOTH:
   `curl -H "Host: <subdomain>:<port>" -H "Authorization: Bearer <token>" http://relay:<http-port>/`
   Without them you get `400`/`401`, which is NOT a real failure of the tunnel.

7. **Default relay password is `pass123`** (`DEFAULT_PASSPHRASE`). Always set a real password via `--pass`/`SKINK_PASS` before exposing any relay.

8. **Relay port model (memorize):**
   - File transfer: `9009-9013` (`--ports`)
   - Tunnel control: `9090` (`--tunnel-port`)
   - Tunnel data: `9091` (= control+1, implicit)
   - Tunnel HTTP proxy: `8080` (`--tunnel-http-port`)
   - Metrics (optional): `9092`

9. **No suto-generated tokens.** `--token ""` means no auth. Running tunnel without `--token` skips auth entirely.

10. **Subdomains are lowercase.** Case-insensitive matching now. Use lowercase subdomains in URLs.

11. **New flags:** `--rekey-interval N` (PFS), `--acl-allow`/`--acl-deny` (per-tunnel ACLs), `--adaptive-window` (RTT tuning), `--stun-server` (STUN), `--compress gzip|deflate|none`, `--dns remote|local|both` (SOCKS5 DNS), `--embedded-relay PORT` (P2P fallback), `--audit-log PATH`, `--migrate host:port`.

## Command reference

### File transfer
```bash
skink send file.txt                       # auto-generated codephrase
skink send --code SECRET file.txt         # fixed code
skink send --relay myrelay:9009 file.txt  # specific relay
skink                                     # interactive: paste code when prompted
SKINK_SECRET=YOUR_CODE skink              # receive with env secret (non-classic on Linux/macOS)
SKINK_SECRET=YOUR_CODE skink --relay myrelay:9009  # receive from a custom relay
```
Both peers must use the same relay + codephrase. Default public relay is `relay.octagono.dev:9009`.

### Run a relay (on a VPS with a public IP)
```bash
SKINK_PASS=real-secret skink relay \
  --tunnel-port 9090 --tunnel-http-port 8080
# password via SKINK_PASS env OR global `skink --pass X relay ...`
```
Open firewall ports: `9009-9013`, `9090`, `9091`, `8080`. NO port forwarding needed (the VPS already has a public IP) — only firewall/security-group rules.

### Tunnels (expose local services / pivots / reverse shells)
```bash
skink tunnel --server relay:9090 --type http    --local localhost:3000
skink tunnel --server relay:9090 --type tcp     --local localhost:22
skink tunnel --server relay:9090 --type udp     --local localhost:53
skink tunnel --server relay:9090 --type socks5                       # pivot whole network
skink tunnel --server relay:9090 --type tcp     --local :4444 --private   # token-only, no public port
```

### Remote exec through a relay
```bash
skink exec  --server relay:9090 -- id
skink exec  --server relay:9090 -- cat /etc/os-release
```
`exec` dials the relay's DATA port `9091` over yamux — NOT the control port. If it hangs, `9091` is not reachable.

### Proxy / Tor routing
```bash
skink --socks5 127.0.0.1:9050 send  --relay abcdef...onion:9009 file.txt
skink --socks5 127.0.0.1:9050 tunnel --server abcdef...onion:9090 \
      --type tcp --transport tcp --local localhost:22
skink --connect http://user:pass@proxy.host:3128 send --relay relay.example:9009 file.txt
```
Remote DNS is done by the proxy, so `.onion` resolves through Tor. Remember `--transport tcp|wss` (QUIC can't traverse a TCP proxy).

### Noise keypair (for static-auth tunnels)
```bash
skink noise-keygen      # prints a static Noise keypair for `--static-key`/server auth
```

## Reverse shell pattern (brief)

The target exposes a local bind shell through an outbound tunnel to the relay; you connect to the relay's allocated public port (or the SOCKS5 pivot). See `references/operations.md` for the three full patterns (skink-on-target bind shell, SOCKS5 pivot, no-skink classic one-liner), multi-hop chaining, and `.onion` hidden-service relay setup.

## Agent integration

- **Structured output:** `skink --output json ...` or the meta-flag `skink --agent ...` (sets `--quiet --log-format json --output json --yes`). Always prefer one of these in scripted/agent contexts.
- **Semantic exit codes (branch on these):**
  `0` ok - `1` general - `2` auth - `3` network - `4` bad input - `5` timeout - `6` unavailable
- **MCP server:** `skink-mcp` (build via `make build-mcp` or the `cmd/mcp` entrypoint) exposes 10 tools (`send_file`, `receive_file`, `tunnel_start`, ...) and 5 resources over stdio. Wire it into opencode/Claude/Cursor as a local MCP server.

## Debugging checklist

- `send`/`receive` hang at the relay step -> relay ports `9009-9013` not reachable, or wrong `--relay` host.
- `tunnel`/`exec` hang or refuse -> data port `9091` (= control+1) not open on the relay.
- `flag provided but not defined: -socks5` (or `-connect`, `-pass`) -> global flag placed after the subcommand. Move it before: `skink --socks5 X tunnel ...`.
- HTTP tunnel returns `400`/`401` -> missing `Host:` + `Authorization: Bearer` headers on the curl.
- Tor: `--socks5` set but connection times out -> QUIC transport used. Force `--transport tcp|wss`.
- `--version` shows stale string -> built without the version ldflag. Rebuild with `make build` (uses `git describe --tags --always`).

## Reference

- Project source + README: the `skink` repo (`AGENTS.md` hierarchy describes every package).
- Deep scenarios (reverse shells end-to-end, Tor/onion relay hidden service, multi-hop relay chaining, VPS install + firewall, opsec notes): `references/operations.md`.
