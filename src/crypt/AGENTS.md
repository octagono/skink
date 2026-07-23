# src/crypt/ — Encryption layer

## Purpose

Symmetric encryption and key derivation for all Skink transfers (file transfer, TCP relay, tunnel control plane). Wraps NaCl secretbox (XChaCha20-Poly1305) via `golang.org/x/crypto/nacl/secretbox` and derives keys from passphrases with PBKDF2-HMAC-SHA256.

## Ownership

- `crypt.go` — `New` (PBKDF2 key derivation), `Encrypt` (AES-GCM, random 12-byte nonce prepended), `Decrypt`.

## Local Contracts

- **PBKDF2 parameters are protocol-breaking.** `New` uses **600,000 iterations** of PBKDF2-HMAC-SHA256 with a **16-byte salt** and a 32-byte (256-bit) key output, per NIST SP 800-132. Both sender and receiver MUST use the same iteration count and salt. Changing either value breaks interop with binaries built from a different version. This is safe for Skink because ad-hoc transfers always run the same binary version on both ends.
- **Salt lifecycle.** When `usersalt == nil`, `New` generates a fresh 16-byte cryptographically-random salt and returns it; callers transmit it to the peer, who passes it back as `usersalt`. The primary file-transfer path generates the salt directly in `src/skink/skink.go` (not via `New`'s nil branch) — it MUST stay 16 bytes to match. The TCP relay and tunnel paths use the `nil` branch on the sender, so they inherit this file's salt size automatically.
- **AES-GCM nonce.** `Encrypt` prepends a 12-byte random nonce; `Decrypt` requires `len(encrypted) >= 13`.

## Work Guidance

- Do not lower the iteration count. If tuning performance, measure first; 600K is a deliberate brute-force floor, not a default.
- Any change to iteration count or salt length is a coordinated protocol break — update both `crypt.go` and the standalone salt generation in `src/skink/skink.go`.

## Verification

- `go test ./src/crypt/...` — round-trip encrypt/decrypt. Tests use the `nil`-salt path so they exercise real iteration count and salt size; allow extra wall-clock time (600K iterations are CPU-bound).

## Child DOX Index

No child directories. This is a leaf package.
