//! Chains of jump hosts, end to end: four SSH servers inside the test (three
//! jump hosts and the target), reached as hop-a → hop-b → hop-c → target.
//! Every hop signs in on its own and has its own key; errors name the hop.
//! Runs by default (no external server needed).

#[path = "support/dir_sftp.rs"]
mod dir_sftp;
#[path = "support/files_server.rs"]
mod files_server;

use sshcore::sftp::SftpClient;
use sshcore::{Error, HostConfig, Jump, Secrets};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("chain-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn named(id: &str, port: u16) -> HostConfig {
    HostConfig { id: id.into(), name: id.into(), ..files_server::host("127.0.0.1", port) }
}

fn hop(cfg: HostConfig) -> Jump {
    Jump { cfg, secrets: files_server::secrets() }
}

/// Starts the three jump hosts and the target; returns (hops, target).
async fn servers(tag: &str) -> (Vec<HostConfig>, HostConfig, PathBuf) {
    let root = scratch(tag);
    let mut hops = Vec::new();
    for id in ["hop-a", "hop-b", "hop-c"] {
        hops.push(named(id, files_server::start(root.join(id)).await));
    }
    let target = named("target", files_server::start(root.join("target")).await);
    (hops, target, root)
}

#[tokio::test]
async fn three_hops_each_with_its_own_key() {
    let (hops, target, root) = servers("ok").await;
    let jumps: Vec<Jump> = hops.iter().cloned().map(hop).collect();
    let c = SftpClient::connect_via(&target, &files_server::secrets(), &jumps).await.expect("through three jump hosts");
    assert_eq!(c.home(), files_server::HOME);
    let seen: Vec<_> = c.jump_fingerprints().iter().map(|(id, fp)| (id.to_string(), fp.starts_with("SHA256:"))).collect();
    assert_eq!(seen, [("hop-a".to_string(), true), ("hop-b".to_string(), true), ("hop-c".to_string(), true)]);
    let keys: Vec<String> = c.jump_fingerprints().iter().map(|(_, fp)| fp.to_string()).collect();
    assert!(keys[0] != keys[1] && keys[1] != keys[2], "each hop has its own key");
    let target_key = c.fingerprint().to_string();
    c.close().await;

    // With every key recorded, the same chain connects again (keys are checked per hop).
    let pinned: Vec<Jump> = hops.iter().zip(&keys).map(|(h, k)| hop(HostConfig { host_key_fingerprint: Some(k.clone()), ..h.clone() })).collect();
    let known_target = HostConfig { host_key_fingerprint: Some(target_key), ..target.clone() };
    SftpClient::connect_via(&known_target, &files_server::secrets(), &pinned).await.expect("all keys match").close().await;

    // A wrong key recorded for the middle hop: refused, and it says whose key it is.
    let mut wrong = pinned.clone();
    wrong[1].cfg.host_key_fingerprint = Some("SHA256:wrongwrongwrongwrongwrongwrongwrongwrongwro".into());
    match SftpClient::connect_via(&known_target, &files_server::secrets(), &wrong).await {
        Err(Error::HostKeyMismatch { host_id, .. }) => assert_eq!(host_id, "hop-b"),
        Err(e) => panic!("expected a key mismatch, got {e}"),
        Ok(_) => panic!("connected with a wrong key"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn failures_name_the_hop() {
    let (hops, target, root) = servers("fail").await;

    // The middle hop can't sign in: fatal, named.
    let mut jumps: Vec<Jump> = hops.iter().cloned().map(hop).collect();
    jumps[1].secrets = Secrets { password: Some("wrong".into()), ..Default::default() };
    match SftpClient::connect_via(&target, &files_server::secrets(), &jumps).await {
        Err(e @ Error::Jump { .. }) => assert!(e.to_string().starts_with("jump host hop-b: authentication failed"), "{e}"),
        Err(e) => panic!("expected a jump host error, got {e}"),
        Ok(_) => panic!("signed in with a wrong password"),
    }

    // The first hop can't reach the second (nothing listens there).
    let mut jumps: Vec<Jump> = hops.iter().cloned().map(hop).collect();
    jumps[1].cfg.port = 1;
    match SftpClient::connect_via(&target, &files_server::secrets(), &jumps).await {
        Err(e @ Error::Unreachable(_)) => assert!(e.to_string().starts_with("The jump host hop-a couldn't reach hop-b ("), "{e}"),
        Err(e) => panic!("expected Unreachable, got {e}"),
        Ok(_) => panic!("reached port 1?"),
    }

    // The last hop can't reach the target.
    let jumps: Vec<Jump> = hops.iter().cloned().map(hop).collect();
    let gone = HostConfig { port: 1, ..target.clone() };
    match SftpClient::connect_via(&gone, &files_server::secrets(), &jumps).await {
        Err(e @ Error::Unreachable(_)) => assert!(e.to_string().starts_with("The jump host hop-c couldn't reach target ("), "{e}"),
        Err(e) => panic!("expected Unreachable, got {e}"),
        Ok(_) => panic!("reached port 1?"),
    }

    // One hop and two hops work too (the same code path as before).
    for n in [1, 2] {
        let jumps: Vec<Jump> = hops.iter().take(n).cloned().map(hop).collect();
        let c = SftpClient::connect_via(&target, &files_server::secrets(), &jumps).await.expect("shorter chain");
        assert_eq!(c.jump_fingerprints().len(), n);
        c.close().await;
    }
    let _ = std::fs::remove_dir_all(&root);
}
