//! End-to-end port forwarding against a real SSH server that allows TCP
//! forwarding (OpenSSH's default). Ignored by default; run with
//!
//!   SHELLWICK_TEST_SSH=user@host[:port] SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test forward_live -- --ignored --nocapture
//!
//! The remote-forward checks connect to the server's loopback, so they only
//! work when the SSH server runs on this machine (e.g. 127.0.0.1).

use sshcore::forward::{ForwardKind, ForwardRule, ForwardStatus};
use sshcore::{spawn_session_with, AuthMethod, HostConfig, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

fn test_host() -> HostConfig {
    let target = std::env::var("SHELLWICK_TEST_SSH").expect("set SHELLWICK_TEST_SSH=user@host[:port]");
    let key = std::env::var("SHELLWICK_TEST_KEY").expect("set SHELLWICK_TEST_KEY=<private key path>");
    let (user, rest) = target.split_once('@').expect("user@host[:port]");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (rest.to_string(), 22),
    };
    HostConfig {
        id: "forward-live-test".into(),
        name: "forward-live-test".into(),
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

/// A free port on 127.0.0.1 (released immediately; fine for a test).
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// TCP echo server on 127.0.0.1; returns its port.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// A TCP relay in front of the SSH server that the test can cut, to simulate
/// the network dropping. It keeps listening, so reconnects get through.
struct Relay {
    port: u16,
    live: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Relay {
    async fn start(target_host: String, target_port: u16) -> Relay {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let live: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let tracked = live.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = l.accept().await else { return };
                let target = (target_host.clone(), target_port);
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                tracked.lock().unwrap().push(task.abort_handle());
            }
        });
        Relay { port, live }
    }

    /// Drops every connection currently going through the relay.
    fn cut(&self) {
        for h in self.live.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

async fn echo_roundtrip(mut s: TcpStream, msg: &[u8]) -> Vec<u8> {
    s.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf)).await.expect("echo in time").unwrap();
    buf
}

/// Waits until every rule id has reported a status; drains shell output meanwhile.
async fn wait_statuses(rx: &mut mpsc::Receiver<SessionEvent>, ids: &[&str]) -> HashMap<String, ForwardStatus> {
    let mut seen = HashMap::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        while seen.len() < ids.len() {
            match rx.recv().await.expect("session ended early") {
                SessionEvent::Forward { id, status } => {
                    seen.insert(id, status);
                }
                SessionEvent::Closed { reason } => panic!("session closed: {reason}"),
                SessionEvent::HostKeyMismatch { .. } => panic!("host key mismatch"),
                _ => {}
            }
        }
    })
    .await
    .expect("forward statuses in time");
    seen
}

fn rule(id: &str, kind: ForwardKind, listen_port: u16, dest_port: u16) -> ForwardRule {
    ForwardRule { id: id.into(), kind, listen_port, dest_host: "127.0.0.1".into(), dest_port, enabled: true }
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn forwards_come_back_after_a_reconnect() {
    let echo = echo_server().await;
    let (local_p, remote_p) = (free_port().await, free_port().await);
    let mut host = test_host();
    let relay = Relay::start(host.host.clone(), host.port).await;
    host.host = "127.0.0.1".into();
    host.port = relay.port;

    let rules = vec![rule("local", ForwardKind::Local, local_p, echo), rule("remote", ForwardKind::Remote, remote_p, echo)];
    let (tx, mut rx) = mpsc::channel(1024);
    let session = spawn_session_with(host, Secrets::default(), TermSize { cols: 80, rows: 24 }, ReconnectPolicy::default(), rules, Vec::new(), tx);

    let first = wait_statuses(&mut rx, &["local", "remote"]).await;
    assert!(first.values().all(|s| *s == ForwardStatus::Active), "{first:?}");
    assert_eq!(echo_roundtrip(TcpStream::connect(("127.0.0.1", local_p)).await.unwrap(), b"before").await, b"before");

    relay.cut();

    // Expect: reconnecting -> connected -> remote forward requested again,
    // while the local listener stays up without being reopened.
    let mut saw_reconnecting = false;
    let mut reconnected = false;
    let mut remote_again = None;
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(ev) = rx.recv().await {
            match ev {
                SessionEvent::Reconnecting { .. } => saw_reconnecting = true,
                SessionEvent::Connected { .. } => reconnected = true,
                SessionEvent::Forward { id, status } if reconnected => {
                    assert_ne!(id, "local", "local listener survives reconnects and is not reopened");
                    remote_again = Some(status);
                    break;
                }
                SessionEvent::Closed { reason } => panic!("closed instead of reconnecting: {reason}"),
                _ => {}
            }
        }
    })
    .await
    .expect("reconnect in time");
    assert!(saw_reconnecting, "a Reconnecting event is reported");
    assert_eq!(remote_again, Some(ForwardStatus::Active));

    assert_eq!(echo_roundtrip(TcpStream::connect(("127.0.0.1", local_p)).await.unwrap(), b"after -L").await, b"after -L");
    let r = TcpStream::connect(("localhost", remote_p)).await.expect("server listens again for -R");
    assert_eq!(echo_roundtrip(r, b"after -R").await, b"after -R");
    session.close().await;
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn local_dynamic_and_remote_forwards_carry_traffic() {
    let echo = echo_server().await;
    let (local_p, socks_p, remote_p) = (free_port().await, free_port().await, free_port().await);
    // A port that is already taken, to see the failure reported.
    let squatter = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taken_p = squatter.local_addr().unwrap().port();
    let mut disabled = rule("off", ForwardKind::Local, free_port().await, echo);
    disabled.enabled = false;

    let rules = vec![
        rule("local", ForwardKind::Local, local_p, echo),
        rule("socks", ForwardKind::Dynamic, socks_p, 0),
        rule("remote", ForwardKind::Remote, remote_p, echo),
        rule("taken", ForwardKind::Local, taken_p, echo),
        disabled.clone(),
    ];
    let (tx, mut rx) = mpsc::channel(1024);
    let session = spawn_session_with(test_host(), Secrets::default(), TermSize { cols: 80, rows: 24 }, ReconnectPolicy::default(), rules, Vec::new(), tx);

    let statuses = wait_statuses(&mut rx, &["local", "socks", "remote", "taken"]).await;
    assert_eq!(statuses["local"], ForwardStatus::Active);
    assert_eq!(statuses["socks"], ForwardStatus::Active);
    assert_eq!(statuses["remote"], ForwardStatus::Active, "{:?}", statuses["remote"]);
    match &statuses["taken"] {
        ForwardStatus::Failed { reason } => assert!(reason.contains("already in use"), "{reason}"),
        s => panic!("expected the taken port to fail, got {s:?}"),
    }
    assert!(!statuses.contains_key("off"), "disabled rules are not started");

    // -L: localhost:local_p -> (server) -> 127.0.0.1:echo
    let got = echo_roundtrip(TcpStream::connect(("127.0.0.1", local_p)).await.unwrap(), b"through -L").await;
    assert_eq!(got, b"through -L");

    // -D by IPv4 and by domain name.
    for (atyp, addr) in [(1u8, vec![127, 0, 0, 1]), (3u8, [vec![9u8], b"localhost".to_vec()].concat())] {
        let mut s = TcpStream::connect(("127.0.0.1", socks_p)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut choice = [0u8; 2];
        s.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [5, 0]);
        let mut req = vec![5, 1, 0, atyp];
        req.extend_from_slice(&addr);
        req.extend_from_slice(&echo.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS reply code for atyp {atyp}");
        assert_eq!(echo_roundtrip(s, b"through -D").await, b"through -D");
    }

    // -R: the server listens on its loopback; same machine, so connect there.
    let r = TcpStream::connect(("localhost", remote_p)).await.expect("server listens for -R");
    assert_eq!(echo_roundtrip(r, b"through -R").await, b"through -R");

    // Closing the session releases the local ports.
    session.close().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(ev) = rx.recv().await {
            if matches!(ev, SessionEvent::Closed { .. }) {
                break;
            }
        }
    })
    .await
    .expect("session closes");
    tokio::time::sleep(Duration::from_millis(300)).await;
    TcpListener::bind(("127.0.0.1", local_p)).await.expect("local forward port released after close");
    TcpListener::bind(("127.0.0.1", socks_p)).await.expect("SOCKS port released after close");
    drop(squatter);
}
