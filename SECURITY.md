# Security Architecture & Policy

Shellwick is a **local-first** SSH client built on an **open-core** security model: the security-critical Rust engines (`crates/sshcore` and `crates/sync`) are designed to be independently audited, while keeping your credentials strictly on your own device.

## 1. Where Your Secrets Live

- **Passwords, key passphrases, proxy passwords, sync passphrases, and activation codes** are stored exclusively in your operating system's native credential store:
  - **macOS**: Keychain
  - **Windows**: Credential Manager
  - **Linux**: Secret Service (`libsecret`)
- **Zero plaintext secrets on disk**: `hosts.json`, `settings.json`, `snippets.json`, and encrypted sync files never contain server passwords or private-key passphrases.
- **Zero cloud accounts, zero servers**: Shellwick has no user accounts and operates no sync/credential servers.

## 2. Network Activity (Complete List)

Shellwick sends **zero analytics and zero telemetry**. Outside of the SSH/SFTP/proxy connections you explicitly initiate, the only optional outbound HTTPS requests are:

1. **Auto-update check** (optional, can be disabled in *Settings → Updates*): fetches `latest.json` from the public GitHub releases repository and verifies downloaded installers against the embedded minisign public key.
2. **Online Pro activation** (only if you activate an online store key): calls the store License API once on activation and re-validates about once every 7 days. Offline Ed25519 keys (`SHELLWICK1-…`) and the 14-day free trial make **zero** network requests.

## 3. Cryptography & Host Key Verification

- **SSH transport**: Pure Rust `russh` + `aws-lc-rs` (no bundled OpenSSL).
- **Host keys**: Trust-on-first-use (TOFU) with SHA-256 fingerprint pinning, explicit mismatch blocking, and per-hop verification for ProxyJump chains.
- **Encrypted folder sync (`crates/sync`)**:
  - Key derivation: **Argon2id** (`m = 64 MiB`, `t = 3`, `p = 1`, random 128-bit salt).
  - Authenticated encryption: **AES-256-GCM** with a fresh random 96-bit nonce on every write and header parameters bound as Associated Data (AAD).
  - Passwords and private keys are **never** included in sync files.
- **Local license & trial integrity**: Offline keys are verified with **Ed25519** (`verify_strict`); cached online activations and 14-day trials are sealed with **HMAC-SHA256**.

## 4. Reporting a Vulnerability

If you discover a security issue in Shellwick, `sshcore`, or `sync`, please report it responsibly before public disclosure by emailing the maintainer (replace with your security contact email before publishing) or opening a GitHub Security Advisory on the public repository.
