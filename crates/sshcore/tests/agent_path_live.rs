//! Agent discovery end to end, against an SSH server and an agent that both
//! run inside the test: the agent path from settings, IdentityAgent from
//! ~/.ssh/config (with a temporary home), and `IdentityAgent none`. Runs by
//! default (no external server). One test function: it changes the process's
//! home directory and the global agent path, which parallel tests would race on.

use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sshcore::{AuthMethod, HostConfig, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn new_key(comment: &str) -> PrivateKey {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)), comment).unwrap()
}

/// Accepts exactly one public key.
struct Srv {
    allowed: russh::keys::ssh_key::PublicKey,
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _: &str, key: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        Ok(if key.public_key.key_data() == self.allowed.key_data() { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(&mut self, _: Channel<Msg>, reply: ChannelOpenHandle, _: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(&mut self, channel: ChannelId, _: &str, _: u32, _: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }
}

async fn start_server(allowed: russh::keys::ssh_key::PublicKey) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server::Config {
        keys: vec![new_key("server")],
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let srv = Srv { allowed: allowed.clone() };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, socket, srv).await {
                    let _ = running.await;
                }
            });
        }
    });
    port
}

#[cfg(windows)]
fn agent_address() -> String {
    format!(r"\\.\pipe\shellwick-path-agent-{}", std::process::id())
}
#[cfg(unix)]
fn agent_address() -> String {
    std::env::temp_dir().join(format!("shellwick-path-agent-{}.sock", std::process::id())).to_string_lossy().into_owned()
}

/// russh's agent server at `addr`, holding `key`.
async fn start_agent(addr: &str, key: &PrivateKey) {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let first = ServerOptions::new().first_pipe_instance(true).create(addr).expect("agent pipe");
        let name = addr.to_string();
        let listener = futures::stream::unfold(first, move |server| {
            let name = name.clone();
            async move {
                if let Err(e) = server.connect().await {
                    return Some((Err(e), ServerOptions::new().create(&name).ok()?));
                }
                let next = ServerOptions::new().create(&name).ok()?;
                Some((Ok(server), next))
            }
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let mut admin = AgentClient::connect_named_pipe(addr).await.expect("admin connection");
        admin.add_identity(key, &[]).await.expect("add key");
    }
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(addr);
        let listener = tokio::net::UnixListener::bind(addr).expect("agent socket");
        let stream = futures::stream::unfold(listener, |l| async move {
            let r = l.accept().await.map(|(s, _)| s);
            Some((r, l))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(stream), ()));
        let mut admin = AgentClient::connect_uds(addr).await.expect("admin connection");
        admin.add_identity(key, &[]).await.expect("add key");
    }
}

fn host(port: u16) -> HostConfig {
    HostConfig {
        id: "agent-path".into(),
        name: "agent-box".into(),
        host: "127.0.0.1".into(),
        port,
        user: "ops".into(),
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

/// Connects once; the first event that says how it went.
async fn outcome(port: u16) -> SessionEvent {
    let (tx, mut rx) = mpsc::channel(64);
    let no_retry = ReconnectPolicy { enabled: false, ..ReconnectPolicy::default() };
    let handle = sshcore::spawn_session_with(host(port), Secrets::default(), TermSize { cols: 80, rows: 24 }, no_retry, Vec::new(), Vec::new(), tx);
    let ev = loop {
        match tokio::time::timeout(Duration::from_secs(15), rx.recv()).await.expect("an event").expect("session alive") {
            SessionEvent::Data(_) => continue,
            other => break other,
        }
    };
    handle.close().await;
    ev
}

/// A home folder of our own, with an ~/.ssh/config saying `config`.
fn fake_home(name: &str, config: &str) -> PathBuf {
    let home = std::env::current_exe().unwrap().parent().unwrap().join("test-scratch").join(format!("agent-home-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh").join("config"), config).unwrap();
    home
}

fn use_home(home: &PathBuf) {
    // SAFETY: this test binary runs one test, and nothing else reads the environment meanwhile.
    unsafe {
        std::env::set_var("USERPROFILE", home);
        std::env::set_var("HOME", home);
        std::env::remove_var("SSH_AUTH_SOCK");
    }
}

#[tokio::test]
async fn agents_from_settings_and_identity_agent() {
    let key = new_key("shellwick-test");
    let port = start_server(key.public_key().clone()).await;
    let addr = agent_address();
    start_agent(&addr, &key).await;

    // 1. Nothing tells Shellwick about this agent: it isn't found (the server needs its key).
    use_home(&fake_home("empty", "# nothing here\n"));
    sshcore::agent::set_agent_path(None);
    let ev = outcome(port).await;
    assert!(!matches!(ev, SessionEvent::Connected { .. }), "found an agent it shouldn't know about: {ev:?}");

    // 2. The path from Settings.
    sshcore::agent::set_agent_path(Some(addr.clone()));
    assert!(matches!(outcome(port).await, SessionEvent::Connected { .. }), "agent path from settings");
    sshcore::agent::set_agent_path(None);

    // 3. IdentityAgent in ~/.ssh/config, for a Host block matching the server's address.
    use_home(&fake_home("config", &format!("Host other\n  IdentityAgent /nowhere\nHost 127.0.0.1\n  IdentityAgent \"{addr}\"\n")));
    assert!(matches!(outcome(port).await, SessionEvent::Connected { .. }), "IdentityAgent from ssh config");

    // 4. IdentityAgent none: no agent for this server, said plainly.
    use_home(&fake_home("none", "Host agent-box\n  IdentityAgent none\n"));
    match outcome(port).await {
        SessionEvent::Closed { reason } => assert!(reason.contains("IdentityAgent none"), "{reason}"),
        other => panic!("expected Closed, got {other:?}"),
    }
}
