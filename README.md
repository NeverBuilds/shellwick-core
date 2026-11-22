# Shellwick Core

The open-source Rust security core powering **[Shellwick](https://shellwick.app)** — a lightweight, local-first SSH client for Windows, macOS and Linux.

An SSH client handles your most sensitive credentials and keys. We publish the SSH engine and encrypted sync engine under the **MIT license** so anyone can inspect, audit, and test exactly how connections, host keys, credentials, and encrypted sync files are handled.

## What's in this repository

- [`crates/sshcore`](crates/sshcore/README.md) — UI-independent Rust SSH engine built on `russh` and `russh-sftp`:
  - Strict TOFU host-key verification on every hop (direct + up to 3 chained jump hosts)
  - OS Keychain / Credential Manager / Secret Service credential storage (secrets never written to disk config)
  - SFTP file & recursive folder transfers, port forwarding (`-L`, `-R`, `-D` SOCKS5), SOCKS5/HTTP proxies, 2FA/PAM prompts, SSH agent forwarding, legacy SSH compatibility toggle, and config importers (PuTTY, SecureCRT, MobaXterm, OpenSSH)
- [`crates/sync`](crates/sync/README.md) — End-to-end encrypted folder sync engine:
  - `Argon2id` (64 MiB, 3 iterations) key derivation + `AES-256-GCM` authenticated encryption
  - Deterministic per-item last-writer-wins merge & cloud conflict-copy resolution
  - Zero cloud servers, zero passwords or private keys ever included in sync payloads

## Verify & run tests locally

```bash
cargo test --workspace
```

## Security & downloads

- Security architecture & vulnerability disclosure: [`SECURITY.md`](SECURITY.md)
- Pre-built installers (Windows, macOS, Linux): [NeverBuilds/shellwick-releases](https://github.com/NeverBuilds/shellwick-releases/releases/latest)
- Website: [https://shellwick.app](https://shellwick.app)
