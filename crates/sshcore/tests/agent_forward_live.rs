//! Agent forwarding end to end: an SSH server and an SSH agent both run inside
//! the test. With forwarding on, the server reaches the local agent through
//! the session and lists its key; with forwarding off, a server that tries
//! anyway is refused. Runs by default (no external server). One test function:
//! it sets the global agent path.

use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sshcore::{AuthMethod, HostConfig, ReconnectPolicy, Secrets, SessionEvent, TermSize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const PASSWORD: &str = "fwd-test";

fn new_key(comment: &str) -> PrivateKey {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)), comment).unwrap()
}

/// What the server learned: "asked" when the client requested forwarding,
/// then "keys:N" (it listed N keys through the agent) or "refused".
type Log = Arc<Mutex<Vec<String>>>;

struct Srv {
    log: Log,
}

impl Srv {
    /// Opens an agent channel back to the client and lists the agent's keys.
    fn try_agent(&self, session: &mut Session) {
        let handle = session.handle();
        let log = self.log.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            match handle.channel_open_agent().await {
                Ok(ch) => {
                    let mut agent = AgentClient::connect(ch.into_stream());
                    let r = tokio::time::timeout(Duration::from_secs(10), agent.request_identities()).await;
                    log.lock().unwrap().push(match r {
                        Ok(Ok(ids)) => format!("keys:{}", ids.len()),
                        _ => "no answer".into(),
                    });
                }
                Err(_) => log.lock().unwrap().push("refused".into()),
            }
        });
    }
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == PASSWORD { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(&mut self, _: Channel<Msg>, reply: ChannelOpenHandle, _: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(&mut self, channel: ChannelId, _: &str, _: u32, _: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn agent_request(&mut self, _: ChannelId, _: &mut Session) -> Result<bool, Self::Error> {
        self.log.lock().unwrap().push("asked".into());
        Ok(true)
    }

    // Like a hostile server, try the agent whether or not the client asked.
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.try_agent(session);
        Ok(())
    }
}

async fn start_server(log: Log) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server::Config {
        keys: vec![new_key("server")],
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let srv = Srv { log: log.clone() };
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
    format!(r"\\.\pipe\shellwick-fwd-agent-{}", std::process::id())
}
#[cfg(unix)]
fn agent_address() -> String {
    std::env::temp_dir().join(format!("shellwick-fwd-agent-{}.sock", std::process::id())).to_string_lossy().into_owned()
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

fn host(port: u16, forward_agent: bool) -> HostConfig {
    HostConfig {
        id: "fwd".into(),
        name: "fwd-box".into(),
        host: "127.0.0.1".into(),
        port,
        user: "ops".into(),
        auth: AuthMethod::Password,
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
        forward_agent,
        keepalive_secs: None,
        legacy_algorithms: false,
    }
}

/// Connects, waits until the server reports what happened with the agent.
async fn session_log(port: u16, forward_agent: bool, log: &Log) -> Vec<String> {
    log.lock().unwrap().clear();
    let (tx, mut rx) = mpsc::channel(256);
    let no_retry = ReconnectPolicy { enabled: false, ..ReconnectPolicy::default() };
    let secrets = Secrets { password: Some(PASSWORD.into()), ..Default::default() };
    let s = sshcore::spawn_session_with(host(port, forward_agent), secrets, TermSize { cols: 80, rows: 24 }, no_retry, Vec::new(), Vec::new(), tx);
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = rx.recv().await {
            match ev {
                SessionEvent::Connected { .. } => break,
                SessionEvent::Closed { reason } => panic!("closed: {reason}"),
                _ => {}
            }
        }
    })
    .await
    .expect("connects");
    for _ in 0..100 {
        if log.lock().unwrap().iter().any(|l| l.starts_with("keys:") || l == "refused" || l == "no answer") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    s.close().await;
    log.lock().unwrap().clone()
}

#[tokio::test]
async fn forwarding_reaches_the_agent_only_when_on() {
    let addr = agent_address();
    start_agent(&addr, &new_key("forwarded")).await;
    sshcore::agent::set_agent_path(Some(addr));
    let log: Log = Arc::default();
    let port = start_server(log.clone()).await;

    assert_eq!(session_log(port, true, &log).await, ["asked", "keys:1"], "the server lists the local agent's key through the session");
    assert_eq!(session_log(port, false, &log).await, ["refused"], "not asked, and a server trying anyway is refused");
    sshcore::agent::set_agent_path(None);
}
