//! Connecting through a jump host (ProxyJump), against a real SSH server that
//! allows TCP forwarding (OpenSSH's default). The server is its own jump host:
//! we sign in to it, then ask it to connect to itself. Ignored by default:
//!
//!   SHELLWICK_TEST_SSH=user@127.0.0.1 SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test jump_live -- --ignored --nocapture

use sshcore::sftp::SftpClient;
use sshcore::{spawn_session_with, AuthMethod, Error, HostConfig, Jump, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
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

fn jump(cfg: HostConfig) -> Vec<Jump> {
    vec![Jump { cfg, secrets: Secrets::default() }]
}

fn no_retry() -> ReconnectPolicy {
    ReconnectPolicy { enabled: false, ..ReconnectPolicy::default() }
}

/// Events up to the first Connected / Closed / HostKeyMismatch / Reconnecting.
async fn until_outcome(rx: &mut mpsc::Receiver<SessionEvent>) -> Vec<SessionEvent> {
    let mut seen = vec![];
    tokio::time::timeout(Duration::from_secs(45), async {
        while let Some(ev) = rx.recv().await {
            let done = matches!(
                ev,
                SessionEvent::Connected { .. } | SessionEvent::Closed { .. } | SessionEvent::HostKeyMismatch { .. } | SessionEvent::Reconnecting { .. }
            );
            if !matches!(ev, SessionEvent::Data(_)) {
                seen.push(ev);
            }
            if done {
                break;
            }
        }
    })
    .await
    .expect("an outcome in time");
    seen
}

async fn outcome(target: HostConfig, via: Vec<Jump>, policy: ReconnectPolicy) -> Vec<SessionEvent> {
    let (tx, mut rx) = mpsc::channel(256);
    let s = spawn_session_with(target, Secrets::default(), TermSize { cols: 80, rows: 24 }, policy, vec![], via, tx);
    let seen = until_outcome(&mut rx).await;
    s.close().await;
    seen
}

/// A TCP relay we can cut, standing in for a network drop to the jump host.
struct Relay {
    port: u16,
    live: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Relay {
    async fn start(to: (String, u16)) -> Relay {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let live: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let tracked = live.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = l.accept().await else { return };
                let to = to.clone();
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(to).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                tracked.lock().unwrap().push(task.abort_handle());
            }
        });
        Relay { port, live }
    }

    fn cut(&self) {
        for h in self.live.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn shell_and_sftp_through_a_jump_host() {
    // Shell: the jump host's key is reported first, then the target's.
    let seen = outcome(host("target"), jump(host("bastion")), no_retry()).await;
    let jump_fp = match &seen[..] {
        [SessionEvent::JumpConnected { host_id, fingerprint }, SessionEvent::Connected { fingerprint: target_fp }] => {
            assert_eq!(host_id, "bastion");
            assert_eq!(fingerprint, target_fp, "same server on both hops");
            fingerprint.clone()
        }
        other => panic!("expected JumpConnected then Connected, got {other:?}"),
    };
    eprintln!("jump host key {jump_fp}");

    // A recorded, matching jump key is accepted.
    let mut known = host("bastion");
    known.host_key_fingerprint = Some(jump_fp.clone());
    let seen = outcome(host("target"), jump(known.clone()), no_retry()).await;
    assert!(matches!(seen.last(), Some(SessionEvent::Connected { .. })), "{seen:?}");

    // SFTP goes through the same path.
    let sftp = SftpClient::connect_via(&host("target"), &Secrets::default(), &jump(known)).await.expect("SFTP via jump");
    assert!(sftp.home().starts_with('/'));
    assert_eq!(sftp.jump_fingerprints(), [("bastion", jump_fp.as_str())]);
    sftp.close().await;
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn changed_keys_name_the_host_they_belong_to() {
    // Jump host key changed: refused before the target is even tried.
    let mut bastion = host("bastion");
    bastion.host_key_fingerprint = Some("SHA256:not-the-real-key".into());
    match outcome(host("target"), jump(bastion), ReconnectPolicy::default()).await.last() {
        Some(SessionEvent::HostKeyMismatch { host_id, expected, .. }) => {
            assert_eq!(host_id, "bastion");
            assert_eq!(expected, "SHA256:not-the-real-key");
        }
        other => panic!("expected the jump host's key to be refused, got {other:?}"),
    }

    // Target key changed behind a fine jump host.
    let mut target = host("target");
    target.host_key_fingerprint = Some("SHA256:not-the-real-key".into());
    match outcome(target, jump(host("bastion")), ReconnectPolicy::default()).await.last() {
        Some(SessionEvent::HostKeyMismatch { host_id, .. }) => assert_eq!(host_id, "target"),
        other => panic!("expected the target's key to be refused, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn jump_host_problems_are_reported_plainly() {
    // The jump host can't sign in (no password saved): stop at once, naming it.
    let mut bastion = host("bastion");
    bastion.auth = AuthMethod::Password;
    match outcome(host("target"), jump(bastion), ReconnectPolicy::default()).await.last() {
        Some(SessionEvent::Closed { reason }) => {
            assert_eq!(reason, "jump host bastion: missing secret: password");
            eprintln!("reported: {reason}");
        }
        other => panic!("expected an immediate failure, got {other:?}"),
    }

    // The jump host is fine but can't reach the target.
    let mut target = host("target");
    target.port = 1;
    match SftpClient::connect_via(&target, &Secrets::default(), &jump(host("bastion"))).await {
        Err(e @ Error::Unreachable(_)) => {
            let msg = e.to_string();
            assert!(msg.starts_with("The jump host bastion couldn't reach target ("), "{msg}");
            eprintln!("reported: {msg}");
        }
        Err(e) => panic!("expected Unreachable, got {e}"),
        Ok(_) => panic!("connected to port 1?"),
    }
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn reconnects_when_the_jump_host_connection_drops() {
    let direct = host("bastion");
    let relay = Relay::start((direct.host.clone(), direct.port)).await;
    let mut bastion = direct;
    bastion.host = "127.0.0.1".into();
    bastion.port = relay.port;

    let (tx, mut rx) = mpsc::channel(256);
    let s = spawn_session_with(host("target"), Secrets::default(), TermSize { cols: 80, rows: 24 }, ReconnectPolicy::default(), vec![], jump(bastion), tx);
    assert!(matches!(until_outcome(&mut rx).await.last(), Some(SessionEvent::Connected { .. })));

    relay.cut();
    let after_cut = until_outcome(&mut rx).await;
    assert!(matches!(after_cut.last(), Some(SessionEvent::Reconnecting { .. })), "{after_cut:?}");
    let back = until_outcome(&mut rx).await;
    assert!(
        matches!(&back[..], [SessionEvent::JumpConnected { .. }, SessionEvent::Connected { .. }]),
        "expected to come back through the jump host, got {back:?}"
    );
    s.close().await;
}
