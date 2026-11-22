# shellwick-sync

Zero-server, end-to-end encrypted folder synchronization engine for **Shellwick**.

## How It Works

Sync your hosts and command snippets through any folder you already sync (iCloud Drive, OneDrive, Dropbox, Syncthing, Nextcloud) with **zero vendor lock-in**:

- **Key Derivation**: Argon2id (`64 MiB`, `t = 3`, `p = 1`, random 16-byte salt).
- **Encryption**: AES-256-GCM with a fresh random 12-byte nonce on every write.
- **Integrity**: Envelope format version and KDF parameters are authenticated as Associated Data (AAD).
- **Conflict-Free Merging**: Per-item merge with tombstones so simultaneous edits across devices converge cleanly.
- **Zero Secrets Synced**: Server passwords, key passphrases, and proxy passwords stay in each computer's OS credential store and are never written to the sync file.

## Running Tests

```bash
cargo test -p shellwick-sync
```

## License

Intended for dual-licensing under **MIT OR Apache-2.0** when published as part of Shellwick's open-core release.
