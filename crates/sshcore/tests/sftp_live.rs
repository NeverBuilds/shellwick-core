//! End-to-end SFTP test against a real server. Ignored by default; run with
//!
//!   SHELLWICK_TEST_SSH=user@host[:port] SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test sftp_live -- --ignored
//!
//! Uses key authentication only (no passphrase), so no secret is ever needed
//! on the command line. Everything it creates lives in a fresh directory
//! under the remote home and is removed at the end.

use sshcore::sftp::{join_remote, EntryKind, SftpClient};
use sshcore::{AuthMethod, Error, HostConfig, Secrets};
use std::path::PathBuf;

fn test_host() -> HostConfig {
    let target = std::env::var("SHELLWICK_TEST_SSH").expect("set SHELLWICK_TEST_SSH=user@host[:port]");
    let key = std::env::var("SHELLWICK_TEST_KEY").expect("set SHELLWICK_TEST_KEY=<private key path>");
    let (user, rest) = target.split_once('@').expect("SHELLWICK_TEST_SSH must be user@host[:port]");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (rest.to_string(), 22),
    };
    HostConfig {
        id: "sftp-live-test".into(),
        name: "sftp-live-test".into(),
        host,
        port,
        user: user.into(),
        auth: AuthMethod::KeyFile { path: key },
        host_key_fingerprint: None,
        startup_command: None,
        tags: vec![],
        environment: None,
        folder: None,
        forwards: vec![],
        jump_host: None,
        confirm_new_key: false,
        session_log: false,
        terminal_theme: None,
        proxy: None,
        forward_agent: false,
        keepalive_secs: None,
        legacy_algorithms: false,
    }
}

fn local_dir() -> PathBuf {
    // Cargo's per-target scratch dir lives under the build dir, not the user profile.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("sftp-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn sftp_roundtrip_against_live_server() {
    let cfg = test_host();
    let client = SftpClient::connect(&cfg, &Secrets::default()).await.expect("connect");
    assert!(client.fingerprint().starts_with("SHA256:"));
    assert!(client.home().starts_with('/'), "home should be absolute: {}", client.home());

    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let dir = join_remote(client.home(), &format!("shellwick-sftp-test-{nonce}"));
    client.mkdir(&dir).await.expect("mkdir");
    let remote = join_remote(&dir, "payload.bin");

    let local = local_dir();
    let up1 = local.join("up1.bin");
    let up2 = local.join("up2.bin");
    let down = local.join("down.bin");
    let first = payload(300 * 1024, 1);
    let second = payload(150 * 1024 + 7, 2);
    std::fs::write(&up1, &first).unwrap();
    std::fs::write(&up2, &second).unwrap();

    // Upload, with progress ending at the full size.
    let mut last = None;
    let n = client.put(&up1, &remote, |p| { last = Some(p); true }).await.expect("put");
    assert_eq!(n, first.len() as u64);
    let last = last.unwrap();
    assert_eq!((last.done, last.total), (first.len() as u64, Some(first.len() as u64)));

    // Overwrite an existing remote file.
    client.put(&up2, &remote, |_| true).await.expect("overwrite");
    let listing = client.list(&dir).await.expect("list");
    assert_eq!(listing.len(), 1, "no temp files left behind: {listing:?}");
    assert_eq!(listing[0].name, "payload.bin");
    assert_eq!(listing[0].kind, EntryKind::File);
    assert_eq!(listing[0].size, second.len() as u64);

    // Download and compare byte-for-byte.
    client.get(&remote, &down, |_| true).await.expect("get");
    assert_eq!(std::fs::read(&down).unwrap(), second);

    // Cancelled upload: the existing remote file is untouched, no temp file.
    let err = client.put(&up1, &remote, |p| p.done == 0).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err}");
    let listing = client.list(&dir).await.unwrap();
    assert_eq!(listing.len(), 1, "{listing:?}");
    assert_eq!(listing[0].size, second.len() as u64);

    // Cancelled download: the existing local file is untouched, no .part file.
    std::fs::write(&down, b"keep me").unwrap();
    let err = client.get(&remote, &down, |p| p.done == 0).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err}");
    assert_eq!(std::fs::read(&down).unwrap(), b"keep me");
    assert!(!local.join("down.bin.shellwick-part").exists());

    // rm is not recursive.
    assert!(client.rm(&dir).await.is_err(), "non-empty dir must not be removed");
    client.rm(&remote).await.expect("rm file");
    client.rm(&dir).await.expect("rm empty dir");
    let home = client.list(client.home()).await.unwrap();
    assert!(!home.iter().any(|e| e.path == dir));

    client.close().await;
    let _ = std::fs::remove_dir_all(&local);
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn sftp_refuses_changed_host_key() {
    let mut cfg = test_host();
    cfg.host_key_fingerprint = Some("SHA256:not-the-real-key".into());
    match SftpClient::connect(&cfg, &Secrets::default()).await {
        Err(Error::HostKeyMismatch { expected, .. }) => assert_eq!(expected, "SHA256:not-the-real-key"),
        Err(e) => panic!("expected HostKeyMismatch, got {e}"),
        Ok(_) => panic!("connected despite a wrong fingerprint"),
    }
}
