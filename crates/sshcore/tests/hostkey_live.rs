//! Forgotten / pinned host keys against a real SSH server. Ignored by default:
//!
//!   SHELLWICK_TEST_SSH=user@127.0.0.1 SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test hostkey_live -- --ignored --nocapture

use sshcore::sftp::SftpClient;
use sshcore::{parse_fingerprint, spawn_session_with, AuthMethod, Error, HostConfig, Jump, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::time::Duration;
use tokio::sync::mpsc;

fn host(id: &str) -> HostConfig {
    let target = std::env::var("SHELLWICK_TEST_SSH").expect("set SHELLWICK_TEST_SSH=user@host[:port]");
    let key = std::env::var("SHELLWICK_TEST_KEY").expect("set SHELLWICK_TEST_KEY=<private key path>");
    let (user, rest) = target.split_once('@').expect("user@host[:port]");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (rest.to_string(), 22),
    };
    HostConfig {
        id: id.into(),
        name: id.into(),
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

/// First Connected / Closed / HostKeyMismatch / HostKeyUnknown / Reconnecting.
async fn outcome(cfg: HostConfig, jump: Option<Jump>) -> SessionEvent {
    let (tx, mut rx) = mpsc::channel(256);
    let policy = ReconnectPolicy { enabled: false, ..ReconnectPolicy::default() };
    let s = spawn_session_with(cfg, Secrets::default(), TermSize { cols: 80, rows: 24 }, policy, vec![], jump.into_iter().collect(), tx);
    let ev = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match rx.recv().await.expect("an outcome") {
                SessionEvent::Data(_) | SessionEvent::JumpConnected { .. } | SessionEvent::Forward { .. } => {}
                ev => break ev,
            }
        }
    })
    .await
    .expect("in time");
    s.close().await;
    ev
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn forgotten_keys_must_be_confirmed() {
    // Forgotten: no key recorded, confirmation required -> refused, key reported.
    let mut forgotten = host("target");
    forgotten.confirm_new_key = true;
    let actual = match outcome(forgotten.clone(), None).await {
        SessionEvent::HostKeyUnknown { host_id, actual } => {
            assert_eq!(host_id, "target");
            actual
        }
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    };
    eprintln!("server presents {actual}");

    // SFTP refuses the same way.
    match SftpClient::connect(&forgotten, &Secrets::default()).await {
        Err(Error::HostKeyUnknown { actual: a, .. }) => assert_eq!(a, actual),
        Err(e) => panic!("expected HostKeyUnknown from SFTP, got {e}"),
        Ok(_) => panic!("SFTP connected without confirmation"),
    }

    // Through a jump host whose key was forgotten: refused at the jump host, named as such.
    let mut bastion = host("bastion");
    bastion.confirm_new_key = true;
    match outcome(host("target"), Some(Jump { cfg: bastion, secrets: Secrets::default() })).await {
        SessionEvent::HostKeyUnknown { host_id, .. } => assert_eq!(host_id, "bastion"),
        other => panic!("expected the jump host's key to need confirming, got {other:?}"),
    }

    // Once trusted (the reported key recorded), it connects.
    let mut trusted = forgotten;
    trusted.host_key_fingerprint = Some(actual);
    assert!(matches!(outcome(trusted, None).await, SessionEvent::Connected { .. }));
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn pinned_keys_are_enforced_from_the_first_connection() {
    // Learn the real key, then pin it the way a user would paste it.
    let real = match outcome(host("probe"), None).await {
        SessionEvent::Connected { fingerprint } => fingerprint,
        other => panic!("expected to connect, got {other:?}"),
    };
    let pasted = format!("256 {real} root@server (ED25519)");
    let mut pinned = host("pinned");
    pinned.host_key_fingerprint = Some(parse_fingerprint(&pasted).unwrap());
    assert!(matches!(outcome(pinned, None).await, SessionEvent::Connected { .. }));

    // A pin that doesn't match is a changed key from the very first try.
    let mut wrong = host("pinned");
    wrong.host_key_fingerprint = Some(parse_fingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap());
    assert!(matches!(outcome(wrong, None).await, SessionEvent::HostKeyMismatch { .. }));
}
