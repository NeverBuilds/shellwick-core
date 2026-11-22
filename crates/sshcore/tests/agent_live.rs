//! Agent authentication against a real SSH server. Ignored by default.
//!
//! `in_process_agent` runs its own agent (russh's agent server) on a private
//! pipe / socket and points `SSH_AUTH_SOCK` at it, so it needs no Pageant or
//! OpenSSH agent service:
//!
//!   SHELLWICK_TEST_SSH=user@host[:port] SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test agent_live in_process -- --ignored
//!
//! `system_agent` checks whatever agent this machine runs (SSH_AUTH_SOCK
//! unset in the test's own environment is up to you):
//!   SHELLWICK_TEST_AGENT_EXPECT=key  — an agent holding a key the server accepts
//!   SHELLWICK_TEST_AGENT_EXPECT=none — no agent at all: fail at once with a clear message

use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
use sshcore::sftp::SftpClient;
use sshcore::{spawn_session, AuthMethod, HostConfig, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

fn agent_host() -> HostConfig {
    let target = std::env::var("SHELLWICK_TEST_SSH").expect("set SHELLWICK_TEST_SSH=user@host[:port]");
    let (user, rest) = target.split_once('@').expect("user@host[:port]");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (rest.to_string(), 22),
    };
    HostConfig {
        id: "agent-live-test".into(),
        name: "agent-live-test".into(),
        host,
        port,
        user: user.into(),
        auth: AuthMethod::Agent,
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

/// First Connected / Closed / Reconnecting outcome of a session.
async fn first_outcome(cfg: HostConfig) -> SessionEvent {
    let (tx, mut rx) = mpsc::channel(256);
    let session = spawn_session(cfg, Secrets::default(), TermSize { cols: 80, rows: 24 }, ReconnectPolicy::default(), tx);
    let ev = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let e = rx.recv().await.expect("session ended without an outcome");
            if matches!(e, SessionEvent::Connected { .. } | SessionEvent::Closed { .. } | SessionEvent::Reconnecting { .. }) {
                break e;
            }
        }
    })
    .await
    .expect("an outcome in time");
    session.close().await;
    ev
}

fn closed_reason(ev: SessionEvent) -> String {
    match ev {
        SessionEvent::Closed { reason } => reason,
        other => panic!("expected an immediate, non-retrying failure, got {other:?}"),
    }
}

fn test_key() -> PrivateKey {
    let raw = std::env::var("SHELLWICK_TEST_KEY").expect("set SHELLWICK_TEST_KEY=<unencrypted private key path>");
    let path = match raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        Some(rest) => {
            let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).expect("home dir");
            PathBuf::from(home).join(rest)
        }
        None => PathBuf::from(raw),
    };
    russh::keys::load_secret_key(path, None).expect("test key (must have no passphrase)")
}

/// Starts russh's agent server on a fresh pipe (Windows) or socket (Unix) and
/// returns the address to put in SSH_AUTH_SOCK.
fn start_agent() -> String {
    #[cfg(windows)]
    let addr = format!(r"\\.\pipe\shellwick-test-agent-{}", std::process::id());
    #[cfg(unix)]
    let addr = std::env::temp_dir().join(format!("shellwick-test-agent-{}.sock", std::process::id())).to_string_lossy().into_owned();
    start_agent_at(addr)
}

#[cfg(windows)]
fn start_agent_at(name: String) -> String {
    use tokio::net::windows::named_pipe::ServerOptions;
    let first = ServerOptions::new().first_pipe_instance(true).create(&name).expect("agent pipe");
    let pipe_name = name.clone();
    // Each client needs its own pipe instance: hand out the connected one and
    // create the next before waiting again.
    let listener = futures::stream::unfold(first, move |server| {
        let pipe_name = pipe_name.clone();
        async move {
            if let Err(e) = server.connect().await {
                return Some((Err(e), ServerOptions::new().create(&pipe_name).ok()?));
            }
            let next = ServerOptions::new().create(&pipe_name).ok()?;
            Some((Ok(server), next))
        }
    });
    tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
    name
}

#[cfg(unix)]
fn start_agent_at(path: String) -> String {
    let path = PathBuf::from(path);
    let _ =std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).expect("agent socket");
    let stream = futures::stream::unfold(listener, |l| async move {
        let r = l.accept().await.map(|(s, _)| s);
        Some((r, l))
    });
    tokio::spawn(russh::keys::agent::server::serve(Box::pin(stream), ()));
    path.to_string_lossy().into_owned()
}

async fn admin_client(sock: &str) -> AgentClient<impl russh::keys::agent::client::AgentStream + Send + Unpin> {
    #[cfg(windows)]
    let admin = AgentClient::connect_named_pipe(sock).await.expect("admin connection");
    #[cfg(unix)]
    let admin = AgentClient::connect_uds(sock).await.expect("admin connection");
    admin
}

/// Not a check: keeps an agent holding SHELLWICK_TEST_KEY at SHELLWICK_TEST_AGENT_PIPE
/// for SHELLWICK_TEST_AGENT_SECS (default 600), so the real app can be started
/// with SSH_AUTH_SOCK pointing at it.
#[tokio::test]
#[ignore = "manual helper for trying agent sign-in in the app; see doc comment"]
async fn hold_agent() {
    let sock = start_agent_at(std::env::var("SHELLWICK_TEST_AGENT_PIPE").expect("set SHELLWICK_TEST_AGENT_PIPE"));
    let secs = std::env::var("SHELLWICK_TEST_AGENT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(600);
    admin_client(&sock).await.add_identity(&test_key(), &[]).await.expect("add test key");
    eprintln!("agent ready at {sock} for {secs}s");
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

#[tokio::test]
#[ignore = "needs a live SSH server and SHELLWICK_TEST_KEY; see module docs"]
async fn in_process_agent() {
    let key = test_key();
    let sock = start_agent();
    // Only this test in this binary touches the environment, and it sets it
    // before any session starts.
    std::env::set_var("SSH_AUTH_SOCK", &sock);

    let mut admin = admin_client(&sock).await;

    // 1. Agent running, but empty.
    let reason = closed_reason(first_outcome(agent_host()).await);
    assert!(reason.starts_with("The SSH agent has no keys"), "{reason}");
    eprintln!("empty agent: {reason}");

    // 2. Agent holds only a key the server doesn't know.
    let stranger = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    admin.add_identity(&stranger, &[]).await.expect("add stranger key");
    let reason = closed_reason(first_outcome(agent_host()).await);
    assert!(reason.contains("didn't accept the SSH agent's key"), "{reason}");
    eprintln!("wrong key: {reason}");

    // 3. The right key is added (after the stranger): shell and SFTP both work.
    admin.add_identity(&key, &[]).await.expect("add test key");
    let ev = first_outcome(agent_host()).await;
    assert!(matches!(ev, SessionEvent::Connected { .. }), "shell via agent: {ev:?}");
    let sftp = SftpClient::connect(&agent_host(), &Secrets::default()).await.expect("SFTP via agent");
    assert!(sftp.home().starts_with('/'));
    sftp.close().await;
}

#[tokio::test]
#[ignore = "needs a live SSH server and a known agent state; see module docs"]
async fn system_agent() {
    match std::env::var("SHELLWICK_TEST_AGENT_EXPECT").as_deref() {
        Ok("key") => {
            let ev = first_outcome(agent_host()).await;
            assert!(matches!(ev, SessionEvent::Connected { .. }), "shell via agent: {ev:?}");
            let sftp = SftpClient::connect(&agent_host(), &Secrets::default()).await.expect("SFTP via agent");
            assert!(sftp.home().starts_with('/'));
            sftp.close().await;
        }
        Ok("none") => {
            let reason = closed_reason(first_outcome(agent_host()).await);
            assert!(reason.starts_with("No SSH agent is running"), "{reason}");
            eprintln!("reported: {reason}");
        }
        _ => panic!("set SHELLWICK_TEST_AGENT_EXPECT=key or none"),
    }
}
