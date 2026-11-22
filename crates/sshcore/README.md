# sshcore

UI-independent SSH, SFTP, port-forwarding, and credential engine powering **Shellwick**.

## Highlights

- **Built on pure Rust** (`russh` + `russh-sftp` + `tokio`), zero Electron or C-SSH wrapper dependencies.
- **Resilient sessions**: Keepalives, automatic reconnect with exponential backoff, and optional `tmux` resume.
- **OS Keychain only**: Secrets are stored via `keyring` (macOS Keychain, Windows Credential Manager, Linux Secret Service) — never serialized to config files.
- **Strict host-key verification**: SHA-256 TOFU pinning, explicit mismatch rejection, and per-hop verification across up to 3 ProxyJump hops.
- **Full workflow support**: SOCKS5/HTTP proxies, OpenSSH agent / Pageant / 1Password / Bitwarden agents, interactive 2FA/PAM prompts, local/remote/SOCKS5 port forwarding, SFTP transfers with atomic staging, session logging, agentless Linux resource sampling, and importers for PuTTY, SecureCRT, MobaXterm, and `~/.ssh/config`.

## Running Tests

```bash
cargo test -p sshcore --lib
```

## License

Intended for dual-licensing under **MIT OR Apache-2.0** when published as part of Shellwick's open-core release.
