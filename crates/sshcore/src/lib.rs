//! sshcore — UI-independent SSH session core.
//!
//! Design goals (the two PuTTY pain points):
//!   1. Sessions do not silently die: keepalive + automatic reconnect with backoff.
//!   2. Secrets live in the OS credential store, never in plaintext config.
//!
//! The crate knows nothing about Tauri, gpui or any UI. It exposes one
//! async API: [`spawn_session`] returns a [`SessionHandle`] you write/resize/close
//! through, and streams [`SessionEvent`]s back over a channel.

pub mod agent;
pub mod credentials;
pub mod folders;
pub mod forward;
pub mod import;
pub mod import_apps;
pub mod keygen;
pub mod prompt;
pub mod proxy;
pub mod quick;
pub mod sessionlog;
pub mod sftp;
pub mod stats;

use russh::client::{self, Handle, Handler};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub use bytes::Bytes;
pub use russh::keys::ssh_key;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Password is looked up at connect time; it is never serialized.
    Password,
    /// OpenSSH private key file (optionally passphrase-protected; passphrase
    /// also comes from the credential store).
    KeyFile { path: String },
    /// Keys held by a running SSH agent (OpenSSH agent, Pageant,
    /// SSH_AUTH_SOCK). Nothing secret is stored for such hosts.
    Agent,
    /// Like the ssh command (quick connect): the SSH agent's keys, then the
    /// default keys in ~/.ssh, then the password, asked for. Nothing is stored.
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    /// SHA-256 fingerprint recorded on first successful connection (TOFU).
    pub host_key_fingerprint: Option<String>,
    /// Optional command sent right after the shell opens, e.g.
    /// `tmux new -A -s shellwick` to make the remote side survive disconnects.
    pub startup_command: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub environment: Option<String>,
    /// Sidebar folder (one level). See [`folders`].
    #[serde(default)]
    pub folder: Option<String>,
    /// Port forwarding rules, run by this host's shell session.
    #[serde(default)]
    pub forwards: Vec<forward::ForwardRule>,
    /// Id of another saved host to connect through first (OpenSSH
    /// `ProxyJump`). The caller resolves it into a [`Jump`].
    #[serde(default)]
    pub jump_host: Option<String>,
    /// With no fingerprint recorded, refuse the server's key and report it
    /// ([`SessionEvent::HostKeyUnknown`]) instead of trusting it on first use.
    /// Set when the user forgets a recorded key.
    #[serde(default)]
    pub confirm_new_key: bool,
    /// Save what this host's terminal sessions print (see [`sessionlog`]).
    #[serde(default)]
    pub session_log: bool,
    /// This host's terminal color scheme (an id the UI knows); `None` = the one in settings.
    #[serde(default)]
    pub terminal_theme: Option<String>,
    /// Reach this host through a SOCKS5 / HTTP proxy (its password is in
    /// [`Secrets::proxy_password`]). Not used together with `jump_host`.
    #[serde(default)]
    pub proxy: Option<proxy::ProxyConfig>,
    /// Let this host's terminal sessions use the local SSH agent (ssh -A).
    /// Anyone with root on the host can use the agent's keys meanwhile.
    #[serde(default)]
    pub forward_agent: bool,
    /// Custom SSH keepalive interval in seconds (`None` = default 15 s, `Some(0)` = off).
    #[serde(default)]
    pub keepalive_secs: Option<u16>,
    /// Enable legacy SSH algorithms (e.g. `ssh-rsa`, `diffie-hellman-group14-sha1`,
    /// CBC ciphers, `hmac-sha1`) for older servers (CentOS 6) and network appliances.
    #[serde(default)]
    pub legacy_algorithms: bool,
}

/// A saved host to hop through, resolved by the caller together with its
/// secrets. Several make a chain (see [`connect_with`]); the caller keeps
/// chains short (Shellwick allows 3) and free of loops.
#[derive(Debug, Clone)]
pub struct Jump {
    pub cfg: HostConfig,
    pub secrets: Secrets,
}

#[derive(Debug, Clone, Copy)]
pub struct TermSize {
    pub cols: u32,
    pub rows: u32,
}

#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    pub enabled: bool,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    /// `None` = retry forever until the user closes the session.
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

/// Secrets resolved by the caller (from the OS keyring) just before connecting.
#[derive(Clone, Default)]
pub struct Secrets {
    pub password: Option<String>,
    pub key_passphrase: Option<String>,
    /// For signing in to the host's proxy.
    pub proxy_password: Option<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets{..}")
    }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Authenticated and shell is open. Carries the server key fingerprint so
    /// the caller can persist it (TOFU).
    Connected { fingerprint: String },
    Data(Bytes),
    Reconnecting { attempt: u32, delay: Duration, reason: String },
    /// Terminal state: session is over for good.
    Closed { reason: String },
    /// A server presented a key different from the recorded one. The session
    /// is NOT established; the user must explicitly accept the new key.
    /// `host_id` says whose key changed: the host itself or its jump host.
    HostKeyMismatch { host_id: String, expected: String, actual: String },
    /// No key is recorded and the host asks to confirm a new one: the
    /// session is NOT established; the user must explicitly trust `actual`.
    HostKeyUnknown { host_id: String, actual: String },
    /// A port-forwarding rule started or failed.
    Forward { id: String, status: forward::ForwardStatus },
    /// Signed in to the jump host (sent before `Connected`). Carries its key
    /// fingerprint so the caller can record it on the jump host's entry (TOFU).
    JumpConnected { host_id: String, fingerprint: String },
    /// A server asks questions while signing in (two-factor code, password
    /// through PAM…). The session waits for [`SessionHandle::answer_prompt`].
    AuthPrompt(prompt::Challenge),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("key: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("authentication failed ({0})")]
    AuthFailed(String),
    #[error("host key mismatch")]
    HostKeyMismatch { host_id: String, expected: String, actual: String },
    /// No key recorded and `confirm_new_key` set: the server's key was refused.
    #[error("host key not confirmed")]
    HostKeyUnknown { host_id: String, actual: String },
    /// Connecting to or signing in to the jump host failed.
    #[error("jump host {name}: {source}")]
    Jump { name: String, source: Box<Error> },
    /// The jump host couldn't open a connection to the target (user-facing).
    #[error("{0}")]
    Unreachable(String),
    #[error("missing secret: {0}")]
    MissingSecret(&'static str),
    /// The user cancelled a sign-in question. `partial`: another method (the
    /// key, the password) had already been accepted.
    #[error("Sign-in was cancelled.")]
    AuthCancelled { partial: bool },
    /// A security key file (YubiKey, `sk-` key) picked as a key file: those
    /// sign in the hardware, so they're used through an agent.
    #[error("This is a security key (like a YubiKey). Shellwick uses those through an SSH agent: add it to your agent (ssh-add) and choose Agent for this server.")]
    SecurityKeyFile,
    /// The server gave up while the user was answering its question.
    #[error("The server stopped waiting for an answer. Reconnect to try again.")]
    AuthPromptExpired,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sftp: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error("transfer cancelled")]
    Cancelled,
    /// The proxy couldn't be reached, refused the sign-in or the server
    /// (message is user-facing). `fatal`: retrying won't help (a setting or
    /// sign-in problem), so no reconnect loop.
    #[error("{message}")]
    Proxy { message: String, fatal: bool },
    /// A file operation refused before reaching the server (message is user-facing).
    #[error("{0}")]
    Remote(String),
    /// Uploading a folder whose name is already a folder there: the caller asks
    /// whether to merge, then tries again with `merge`.
    #[error("A folder named “{0}” is already here.")]
    FolderExists(String),
    /// Generating or installing a key failed (message is user-facing).
    #[error("{0}")]
    KeyGen(String),
    /// No agent, an empty agent, or one that couldn't sign (message is user-facing).
    #[error("{0}")]
    Agent(String),
    #[error("session closed")]
    Closed,
}

// ---------------------------------------------------------------------------
// Handle given to the UI
// ---------------------------------------------------------------------------

enum Cmd {
    Write(Bytes),
    Resize(TermSize),
    Exec {
        command: String,
        reply: tokio::sync::oneshot::Sender<Result<String, Error>>,
    },
    Close,
}

#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::Sender<Cmd>,
    prompt: prompt::PromptSlot,
}

impl SessionHandle {
    pub async fn write(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.tx.send(Cmd::Write(data.into())).await.map_err(|_| Error::Closed)
    }
    pub async fn resize(&self, size: TermSize) -> Result<(), Error> {
        self.tx.send(Cmd::Resize(size)).await.map_err(|_| Error::Closed)
    }
    /// Runs a short read-only command on a separate SSH exec channel over this
    /// session's existing connection (4 s timeout, 8 KiB output cap).
    pub async fn exec(&self, command: impl Into<String>) -> Result<String, Error> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Cmd::Exec { command: command.into(), reply: tx }).await.map_err(|_| Error::Closed)?;
        rx.await.map_err(|_| Error::Closed)?
    }
    pub async fn close(&self) {
        // A question may be waiting: closing cancels it, or the task would wait forever.
        self.prompt.answer(None);
        let _ = self.tx.send(Cmd::Close).await;
    }
    /// Answers the pending [`SessionEvent::AuthPrompt`] (one answer per
    /// question), or cancels it with `None`. False when nothing is waiting.
    pub fn answer_prompt(&self, answers: Option<Vec<String>>) -> bool {
        self.prompt.answer(answers)
    }
}

// ---------------------------------------------------------------------------
// Host key verification (trust on first use)
// ---------------------------------------------------------------------------

struct TofuHandler {
    expected: Option<String>,
    /// Refuse an unexpected key even when none is recorded.
    confirm_new: bool,
    observed: Arc<Mutex<Option<String>>>,
    /// Remote-forward targets; `None` for connections without forwards (SFTP).
    remote: Option<forward::RemoteTargets>,
    /// Agent forwarding is on for this host: the names to find its agent
    /// by (address and Shellwick name, for IdentityAgent). `None` refuses the
    /// server's agent channels.
    agent_names: Option<Vec<String>>,
}

fn fingerprint_of(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
        PublicKeyOrCertificate::Certificate(cert) => cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

impl Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = fingerprint_of(key);
        *self.observed.lock().unwrap() = Some(fp.clone());
        match &self.expected {
            None => Ok(!self.confirm_new),
            Some(expected) => Ok(expected == &fp),
        }
    }

    /// The server wants to use our agent (we asked, on the terminal's channel):
    /// relay the channel to the local agent. Refused when forwarding is off,
    /// so a server can't reach the agent uninvited.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let Some(names) = self.agent_names.clone() else {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            match agent::connect(&names).await {
                Ok((local, _, _)) => {
                    let mut local = local.into_inner();
                    let mut remote = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut remote, &mut local).await;
                }
                // No agent here: the remote side sees the channel close (like ssh).
                Err(_) => {
                    let _ = channel.close().await;
                }
            }
        });
        Ok(())
    }

    /// The server opened a channel for one of our remote forwards. Accept it
    /// right away and connect to the local destination in the background:
    /// awaiting a TCP connect here would stall the whole SSH session.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote.as_ref().and_then(|r| r.map.get(&connected_port).cloned().map(|t| (t, r.shutdown.clone())));
        match target {
            Some(((host, port), shutdown)) => {
                reply.accept().await;
                forward::serve_remote_channel(channel, host, port, shutdown);
            }
            // Never asked for this port: refuse.
            None => reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await,
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

fn client_config(cfg: &HostConfig) -> Arc<client::Config> {
    let keepalive_interval = match cfg.keepalive_secs {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(u64::from(secs))),
        None => Some(Duration::from_secs(15)),
    };
    let mut preferred = russh::Preferred::default();
    if cfg.legacy_algorithms {
        use std::borrow::Cow;
        preferred.kex = Cow::Owned(russh::kex::ALL_KEX_ALGORITHMS.iter().copied().copied().collect());
        preferred.cipher = Cow::Owned(russh::cipher::ALL_CIPHERS.iter().copied().copied().collect());
        preferred.mac = Cow::Owned(russh::mac::ALL_MAC_ALGORITHMS.iter().copied().copied().collect());
        let mut keys = preferred.key.to_vec();
        let legacy_rsa = russh::keys::Algorithm::Rsa { hash: None };
        if !keys.contains(&legacy_rsa) {
            keys.push(legacy_rsa);
        }
        preferred.key = Cow::Owned(keys);
    }
    Arc::new(client::Config {
        keepalive_interval,
        keepalive_max: 3,
        inactivity_timeout: None,
        nodelay: true,
        preferred,
        ..Default::default()
    })
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

fn timed_out() -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))
}

/// A signed-in connection, plus the jump-host connections it runs over (in
/// connection order). They must stay alive for as long as `handle` is used.
pub(crate) struct Conn {
    pub handle: Handle<TofuHandler>,
    pub fingerprint: String,
    pub jumps: Vec<JumpConn>,
}

pub(crate) struct JumpConn {
    pub host_id: String,
    pub handle: Handle<TofuHandler>,
    pub fingerprint: String,
}

impl JumpConn {
    pub async fn disconnect(&self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

/// Retrying won't help with these: report at once instead of reconnecting.
fn is_fatal(e: &Error) -> bool {
    match e {
        Error::AuthFailed(_)
        | Error::MissingSecret(_)
        | Error::Key(_)
        | Error::Agent(_)
        | Error::AuthCancelled { .. }
        | Error::AuthPromptExpired
        | Error::SecurityKeyFile
        | Error::Proxy { fatal: true, .. } => true,
        Error::Jump { source, .. } => is_fatal(source),
        _ => false,
    }
}

async fn connect_once(cfg: &HostConfig, secrets: &Secrets, jumps: &[Jump], ask: &prompt::Ask) -> Result<Conn, Error> {
    connect_with(cfg, secrets, None, jumps, ask).await
}

/// Signs in once and disconnects, through `jumps` (may be empty): checks that
/// `cfg`'s sign-in works (for example a key just added to the server).
/// Host keys are checked as usual. A server that accepts the key and then
/// wants a second factor counts as accepting the key (nothing is asked).
pub async fn check_sign_in(cfg: &HostConfig, secrets: &Secrets, jumps: &[Jump]) -> Result<(), Error> {
    let conn = match connect_once(cfg, secrets, jumps, &prompt::never_ask()).await {
        Ok(conn) => conn,
        Err(Error::AuthCancelled { partial: true }) => return Ok(()),
        Err(e) => return Err(e),
    };
    let _ = conn.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    disconnect_all(&conn.jumps).await;
    Ok(())
}

/// Connects to `cfg` through `jumps` (in order: the first is reached
/// directly, each next one through the one before): sign in to each jump
/// host, have it open a TCP connection to the next (`direct-tcpip`), and run
/// the next SSH session inside that channel. Every hop keeps its own sign-in
/// and host key; errors name the hop.
async fn connect_with(
    cfg: &HostConfig,
    secrets: &Secrets,
    remote: Option<forward::RemoteTargets>,
    jumps: &[Jump],
    ask: &prompt::Ask,
) -> Result<Conn, Error> {
    let Some(first) = jumps.first() else {
        let (handle, fingerprint) = connect_direct(cfg, secrets, remote, ask).await?;
        return Ok(Conn { handle, fingerprint, jumps: Vec::new() });
    };
    // A hop that failed: a changed key or the user's own cancel are reported as
    // such (`host_id` names the hop); anything else is prefixed with its name.
    let hop_error = |hop: &Jump, e: Error| match e {
        e @ (Error::HostKeyMismatch { .. } | Error::HostKeyUnknown { .. } | Error::AuthCancelled { .. } | Error::AuthPromptExpired) => e,
        e => Error::Jump { name: hop.cfg.name.clone(), source: Box::new(e) },
    };
    let (handle, fingerprint) = connect_direct(&first.cfg, &first.secrets, None, ask).await.map_err(|e| hop_error(first, e))?;
    let mut conns = vec![JumpConn { host_id: first.cfg.id.clone(), handle, fingerprint }];

    // Each further hop, then the server itself, through the last hop.
    for (i, hop) in jumps.iter().enumerate().skip(1) {
        let via = &jumps[i - 1];
        let channel = match open_through(&conns, via, &hop.cfg).await {
            Ok(c) => c,
            Err(e) => {
                disconnect_all(&conns).await;
                return Err(e);
            }
        };
        match sign_in(&hop.cfg, &hop.secrets, channel.into_stream(), None, ask).await {
            Ok((handle, fingerprint)) => conns.push(JumpConn { host_id: hop.cfg.id.clone(), handle, fingerprint }),
            Err(e) => {
                disconnect_all(&conns).await;
                return Err(match e {
                    Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => unreachable(via, &hop.cfg, "timed out".into()),
                    e if is_fatal(&e) || matches!(e, Error::HostKeyMismatch { .. } | Error::HostKeyUnknown { .. }) => hop_error(hop, e),
                    e => unreachable(via, &hop.cfg, e.to_string()),
                });
            }
        }
    }
    let last = jumps.last().expect("at least one hop");
    let channel = match open_through(&conns, last, cfg).await {
        Ok(c) => c,
        Err(e) => {
            disconnect_all(&conns).await;
            return Err(e);
        }
    };
    match sign_in(cfg, secrets, channel.into_stream(), remote, ask).await {
        Ok((handle, fingerprint)) => Ok(Conn { handle, fingerprint, jumps: conns }),
        Err(e) => {
            disconnect_all(&conns).await;
            Err(match e {
                // The target answered: its own verdict stands.
                e @ (Error::HostKeyMismatch { .. } | Error::HostKeyUnknown { .. }) => e,
                e if is_fatal(&e) => e,
                // Some servers (Windows OpenSSH) accept the channel before
                // connecting and then just close it when the target is down.
                Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => unreachable(last, cfg, "timed out".into()),
                e => unreachable(last, cfg, e.to_string()),
            })
        }
    }
}

fn unreachable(via: &Jump, to: &HostConfig, why: String) -> Error {
    Error::Unreachable(format!("The jump host {} couldn't reach {} ({why})", via.cfg.name, to.name))
}

/// Asks the last connected hop (`via`) for a TCP connection to `to`.
async fn open_through(conns: &[JumpConn], via: &Jump, to: &HostConfig) -> Result<russh::Channel<client::Msg>, Error> {
    let handle = &conns.last().expect("a connected hop").handle;
    let open = handle.channel_open_direct_tcpip(to.host.clone(), u32::from(to.port), "127.0.0.1", 0);
    match tokio::time::timeout(CONNECT_TIMEOUT, open).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(e)) => Err(unreachable(via, to, e.to_string())),
        Err(_) => Err(unreachable(via, to, "timed out".into())),
    }
}

/// Closes hop connections, the innermost first.
pub(crate) async fn disconnect_all(conns: &[JumpConn]) {
    for c in conns.iter().rev() {
        c.disconnect().await;
    }
}

async fn connect_direct(
    cfg: &HostConfig,
    secrets: &Secrets,
    remote: Option<forward::RemoteTargets>,
    ask: &prompt::Ask,
) -> Result<(Handle<TofuHandler>, String), Error> {
    let dial = async {
        match &cfg.proxy {
            Some(p) => proxy::connect(p, secrets.proxy_password.as_deref(), &cfg.host, cfg.port).await,
            None => {
                let host = cfg.host.trim().trim_start_matches('[').trim_end_matches(']');
                let tcp = tokio::net::TcpStream::connect((host, cfg.port)).await?;
                let _ = tcp.set_nodelay(true);
                Ok(tcp)
            }
        }
    };
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, dial).await {
        Ok(tcp) => tcp?,
        Err(_) => return Err(timed_out()),
    };
    sign_in(cfg, secrets, tcp, remote, ask).await
}

/// SSH handshake, host-key check and authentication over an open stream.
/// After the host's own method (password / key / agent), or instead of it
/// when no password is saved, the server may ask questions
/// (keyboard-interactive): see [`prompt`].
async fn sign_in<S>(
    cfg: &HostConfig,
    secrets: &Secrets,
    stream: S,
    remote: Option<forward::RemoteTargets>,
    ask: &prompt::Ask,
) -> Result<(Handle<TofuHandler>, String), Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let observed = Arc::new(Mutex::new(None));
    let handler = TofuHandler {
        expected: cfg.host_key_fingerprint.clone(),
        confirm_new: cfg.confirm_new_key,
        observed: observed.clone(),
        remote,
        agent_names: cfg.forward_agent.then(|| vec![cfg.host.clone(), cfg.name.clone()]),
    };

    let connect = client::connect_stream(client_config(cfg), stream, handler);
    let mut handle = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            // Distinguish a rejected host key from a network failure.
            let actual = observed.lock().unwrap().clone();
            match (&cfg.host_key_fingerprint, actual) {
                (Some(expected), Some(actual)) if expected != &actual => {
                    return Err(Error::HostKeyMismatch { host_id: cfg.id.clone(), expected: expected.clone(), actual });
                }
                (None, Some(actual)) if cfg.confirm_new_key => {
                    return Err(Error::HostKeyUnknown { host_id: cfg.id.clone(), actual });
                }
                _ => {}
            }
            return Err(e.into());
        }
        Err(_) => return Err(timed_out()),
    };

    // The host's own method first. A password host without a saved password
    // goes straight to the server's questions (the user types it there).
    let first = match &cfg.auth {
        AuthMethod::Password => match secrets.password.as_deref() {
            Some(pw) => Some(handle.authenticate_password(cfg.user.clone(), pw).await?),
            None => None,
        },
        AuthMethod::KeyFile { path } => {
            let path = expand_home(path, home_dir().as_deref());
            if is_security_key(&path) {
                return Err(Error::SecurityKeyFile);
            }
            let key = russh::keys::load_secret_key(&path, secrets.key_passphrase.as_deref())?;
            if is_sk(key.algorithm()) {
                return Err(Error::SecurityKeyFile);
            }
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            Some(
                handle
                    .authenticate_publickey(cfg.user.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await?,
            )
        }
        AuthMethod::Agent => Some(agent::authenticate(&mut handle, &cfg.user, &[cfg.host.as_str(), cfg.name.as_str()]).await?),
        AuthMethod::Auto => auto_keys(&mut handle, cfg, ask).await?,
    };

    // Keyboard-interactive: a second factor after an accepted key or password,
    // password-by-PAM servers, or the password question when none is saved.
    let outcome = match first {
        Some(russh::client::AuthResult::Success) => Ok(()),
        Some(russh::client::AuthResult::Failure { remaining_methods, partial_success }) => {
            if remaining_methods.contains(&russh::MethodKind::KeyboardInteractive) {
                match prompt::run(&mut handle, cfg, secrets.password.as_deref(), ask, partial_success).await {
                    Ok(prompt::Outcome::SignedIn) => Ok(()),
                    Ok(prompt::Outcome::Refused) => Err(Error::AuthFailed(format!("server accepts: {remaining_methods:?}"))),
                    Err(e) => Err(e),
                }
            } else {
                Err(Error::AuthFailed(format!("server accepts: {remaining_methods:?}")))
            }
        }
        None => questions(&mut handle, cfg, ask).await,
    };
    if let Err(e) = outcome {
        let _ = handle.disconnect(Disconnect::ByApplication, "auth failed", "en").await;
        return Err(e);
    }

    let fp = observed.lock().unwrap().clone().unwrap_or_default();
    Ok((handle, fp))
}

/// No saved password (or, for [`AuthMethod::Auto`], no key accepted): ask the
/// user. Servers that ask their own questions (keyboard-interactive) go
/// first, like OpenSSH; otherwise Shellwick asks for the password itself.
async fn questions(handle: &mut Handle<TofuHandler>, cfg: &HostConfig, ask: &prompt::Ask) -> Result<(), Error> {
    let methods = match handle.authenticate_none(cfg.user.clone()).await? {
        russh::client::AuthResult::Success => return Ok(()),
        russh::client::AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };
    if methods.contains(&russh::MethodKind::KeyboardInteractive) {
        match prompt::run(handle, cfg, None, ask, false).await? {
            prompt::Outcome::SignedIn => return Ok(()),
            prompt::Outcome::Refused if !methods.contains(&russh::MethodKind::Password) => return Err(Error::MissingSecret("password")),
            prompt::Outcome::Refused => {}
        }
    }
    if !methods.contains(&russh::MethodKind::Password) {
        return Err(match cfg.auth {
            AuthMethod::Auto => Error::AuthFailed("no key was accepted and the server doesn't take passwords".into()),
            _ => Error::MissingSecret("password"),
        });
    }
    match ask_password(handle, cfg, ask).await? {
        russh::client::AuthResult::Success => Ok(()),
        // The password was right and the server wants a second step (a code).
        russh::client::AuthResult::Failure { remaining_methods, partial_success: true }
            if remaining_methods.contains(&russh::MethodKind::KeyboardInteractive) =>
        {
            match prompt::run(handle, cfg, None, ask, true).await? {
                prompt::Outcome::SignedIn => Ok(()),
                prompt::Outcome::Refused => Err(Error::AuthFailed("the server didn't accept the answers".into())),
            }
        }
        russh::client::AuthResult::Failure { remaining_methods, .. } => Err(Error::AuthFailed(format!("server accepts: {remaining_methods:?}"))),
    }
}

/// How many times a wrong password or passphrase is asked again.
const ASK_TRIES: usize = 3;

/// One question, hidden input; `None` = the user cancelled.
async fn ask_hidden(cfg: &HostConfig, ask: &prompt::Ask, text: &str, retry: bool) -> Option<String> {
    let challenge = prompt::Challenge {
        host_id: cfg.id.clone(),
        host_name: cfg.name.clone(),
        name: String::new(),
        instructions: String::new(),
        questions: vec![prompt::Question { text: text.to_string(), echo: false }],
        retry,
    };
    ask(challenge).await.map(|a| a.into_iter().next().unwrap_or_default())
}

/// Asks for the password (never stored) until the server takes it or the
/// tries run out. A partial success (password right, code next) is returned
/// for the caller to continue.
async fn ask_password(handle: &mut Handle<TofuHandler>, cfg: &HostConfig, ask: &prompt::Ask) -> Result<russh::client::AuthResult, Error> {
    for attempt in 0..ASK_TRIES {
        let pw = ask_hidden(cfg, ask, "Password", attempt > 0).await.ok_or(Error::AuthCancelled { partial: false })?;
        // The server may have given up while the question was showing.
        match handle.authenticate_password(cfg.user.clone(), pw).await.map_err(|_| Error::AuthPromptExpired)? {
            russh::client::AuthResult::Success => return Ok(russh::client::AuthResult::Success),
            f @ russh::client::AuthResult::Failure { partial_success: true, .. } => return Ok(f),
            russh::client::AuthResult::Failure { .. } => continue,
        }
    }
    Err(Error::AuthFailed("the server didn't accept the password".into()))
}

fn is_sk(alg: russh::keys::ssh_key::Algorithm) -> bool {
    matches!(alg, russh::keys::ssh_key::Algorithm::SkEd25519 | russh::keys::ssh_key::Algorithm::SkEcdsaSha2NistP256)
}

/// A key file whose public half (`<file>.pub`) is a security key (`sk-…`).
/// Checked before loading, so no passphrase is asked for a file that can't be used.
fn is_security_key(private: &Path) -> bool {
    let mut pub_path = private.as_os_str().to_owned();
    pub_path.push(".pub");
    std::fs::read_to_string(pub_path).is_ok_and(|t| t.trim_start().starts_with("sk-"))
}

/// The default key files ssh tries, in its order.
const DEFAULT_KEYS: [&str; 3] = ["id_ed25519", "id_ecdsa", "id_rsa"];

/// [`AuthMethod::Auto`]: the agent's keys, then the default key files (an
/// encrypted one asks for its passphrase; an empty answer skips it).
/// `None` when no key got in, so the caller asks for the password.
async fn auto_keys(handle: &mut Handle<TofuHandler>, cfg: &HostConfig, ask: &prompt::Ask) -> Result<Option<russh::client::AuthResult>, Error> {
    use russh::client::AuthResult;
    match agent::authenticate(handle, &cfg.user, &[cfg.host.as_str(), cfg.name.as_str()]).await {
        Ok(AuthResult::Success) => return Ok(Some(AuthResult::Success)),
        Ok(f @ AuthResult::Failure { partial_success: true, .. }) => return Ok(Some(f)),
        // No agent, an empty one, or none of its keys accepted: next.
        Ok(_) | Err(Error::Agent(_)) | Err(Error::AuthFailed(_)) => {}
        Err(e) => return Err(e),
    }
    let Some(ssh_dir) = home_dir().map(|h| h.join(".ssh")) else { return Ok(None) };
    for name in DEFAULT_KEYS {
        let path = ssh_dir.join(name);
        if !path.is_file() || is_security_key(&path) {
            continue;
        }
        let key = match russh::keys::load_secret_key(&path, None) {
            Ok(k) => Some(k),
            Err(russh::keys::Error::KeyIsEncrypted) => {
                let mut key = None;
                for attempt in 0..ASK_TRIES {
                    let text = format!("Passphrase for ~/.ssh/{name} (leave empty to skip it)");
                    let pass = ask_hidden(cfg, ask, &text, attempt > 0).await.ok_or(Error::AuthCancelled { partial: false })?;
                    if pass.is_empty() {
                        break;
                    }
                    if let Ok(k) = russh::keys::load_secret_key(&path, Some(&pass)) {
                        key = Some(k);
                        break;
                    }
                }
                key
            }
            Err(_) => None, // not a key ssh would use either
        };
        let Some(key) = key else { continue };
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        match handle.authenticate_publickey(cfg.user.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await? {
            AuthResult::Success => return Ok(Some(AuthResult::Success)),
            f @ AuthResult::Failure { partial_success: true, .. } => return Ok(Some(f)),
            AuthResult::Failure { .. } => continue,
        }
    }
    Ok(None)
}

/// Reads a SHA-256 host key fingerprint the user pasted (to pin it before the
/// first connection). Accepts `SHA256:…`, the bare base64, or a whole
/// `ssh-keygen -lf` line (`256 SHA256:… root@host (ED25519)`). Returns it in
/// the form Shellwick records: `SHA256:<43 base64 chars>`.
pub fn parse_fingerprint(input: &str) -> Result<String, &'static str> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Paste the server's SHA256 fingerprint.");
    }
    let token = input
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .or_else(|| input.split_whitespace().next())
        .unwrap_or(input);
    if token.starts_with("MD5:") || (token.len() == 47 && token.matches(':').count() == 15) {
        return Err("That's an old MD5 fingerprint. Shellwick needs the SHA256 one: run ssh-keygen -lf on the server's public host key.");
    }
    let b64 = token.strip_prefix("SHA256:").unwrap_or(token).trim_end_matches('=');
    if b64.len() != 43 || !b64.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
        return Err("That doesn't look like a SHA256 fingerprint (SHA256: followed by 43 letters, digits, + or /).");
    }
    Ok(format!("SHA256:{b64}"))
}

fn home_dir() -> Option<PathBuf> {
    let vars: &[&str] = if cfg!(windows) { &["USERPROFILE", "HOME"] } else { &["HOME"] };
    vars.iter()
        .filter_map(std::env::var_os)
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Expands a leading `~` (`~`, `~/…`, `~\…`) to the home directory, the way
/// users write key paths in OpenSSH configs. Other paths are returned as-is.
fn expand_home(path: &str, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else { return PathBuf::from(path) };
    if path == "~" {
        return home.to_path_buf();
    }
    match path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        Some(rest) => home.join(rest),
        None => PathBuf::from(path),
    }
}

/// Runs one shell until it ends. Returns `Ok(true)` if the user asked to close,
/// `Ok(false)` if the remote side went away (candidate for reconnect).
async fn run_shell(
    handle: &Handle<TofuHandler>,
    cfg: &HostConfig,
    size: &mut TermSize,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    events: &mpsc::Sender<SessionEvent>,
) -> Result<bool, Error> {
    let mut channel = handle.channel_open_session().await?;
    channel
        .request_pty(true, "xterm-256color", size.cols, size.rows, 0, 0, &[])
        .await?;
    // Only the terminal asks for the agent (never the file panel or jump hosts).
    if cfg.forward_agent {
        channel.agent_forward(false).await?;
    }
    channel.request_shell(true).await?;

    if let Some(cmd) = &cfg.startup_command {
        channel.data_bytes(Bytes::from(format!("{cmd}\n"))).await?;
    }

    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if events.send(SessionEvent::Data(data)).await.is_err() { return Ok(true); }
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if events.send(SessionEvent::Data(data)).await.is_err() { return Ok(true); }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return Ok(false),
                Some(ChannelMsg::ExitStatus { .. }) => return Ok(false),
                Some(_) => {}
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Write(b)) => channel.data_bytes(b).await?,
                Some(Cmd::Resize(s)) => {
                    *size = s;
                    channel.window_change(s.cols, s.rows, 0, 0).await?;
                }
                Some(Cmd::Exec { command, reply }) => {
                    match handle.channel_open_session().await {
                        Ok(mut exec_ch) => {
                            tokio::spawn(async move {
                                let res = tokio::time::timeout(Duration::from_secs(4), async {
                                    exec_ch.exec(true, command.as_bytes()).await?;
                                    let mut out = Vec::new();
                                    const MAX_BYTES: usize = 8 * 1024;
                                    while let Some(msg) = exec_ch.wait().await {
                                        match msg {
                                            ChannelMsg::Data { data } => {
                                                let room = MAX_BYTES.saturating_sub(out.len());
                                                if room > 0 {
                                                    out.extend_from_slice(&data[..data.len().min(room)]);
                                                }
                                            }
                                            ChannelMsg::Eof | ChannelMsg::Close => break,
                                            _ => {}
                                        }
                                    }
                                    Ok::<String, Error>(String::from_utf8_lossy(&out).into_owned())
                                })
                                .await
                                .unwrap_or(Err(Error::Closed));
                                let _ = reply.send(res);
                            });
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e.into()));
                        }
                    }
                }
                Some(Cmd::Close) | None => {
                    let _ = channel.eof().await;
                    let _ = channel.close().await;
                    return Ok(true);
                }
            }
        }
    }
}

/// Spawns a session task. Events arrive on `events`; control via the handle.
pub fn spawn_session(
    cfg: HostConfig,
    secrets: Secrets,
    size: TermSize,
    policy: ReconnectPolicy,
    events: mpsc::Sender<SessionEvent>,
) -> SessionHandle {
    spawn_session_with(cfg, secrets, size, policy, Vec::new(), Vec::new(), events)
}

/// Like [`spawn_session`], also running the given port forwards (enabled
/// rules only) for as long as the session lives, and connecting through
/// `jumps` (in connection order; empty = directly). Pass the host's rules to at most one session per host,
/// or the second one's listeners fail with "port already in use".
pub fn spawn_session_with(
    cfg: HostConfig,
    secrets: Secrets,
    size: TermSize,
    policy: ReconnectPolicy,
    forwards: Vec<forward::ForwardRule>,
    jumps: Vec<Jump>,
    events: mpsc::Sender<SessionEvent>,
) -> SessionHandle {
    let (tx, mut rx) = mpsc::channel::<Cmd>(256);
    // Sign-in questions go out as events and wait for `answer_prompt` (also on reconnects).
    let prompt = prompt::PromptSlot::default();
    let ask = {
        let events = events.clone();
        prompt.ask(move |challenge| {
            let events = events.clone();
            Box::pin(async move {
                let _ = events.send(SessionEvent::AuthPrompt(challenge)).await;
            })
        })
    };

    tokio::spawn(async move {
        let mut cfg = cfg;
        let mut jumps = jumps;
        let mut size = size;
        let mut attempt: u32 = 0;
        let mut delay = policy.initial_delay;

        // Forwarding state lives as long as this task: dropping `_shutdown_tx`
        // on any return stops listeners and open tunnels.
        let forwards: Vec<_> = forwards.into_iter().filter(|r| r.enabled).collect();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let current: forward::SharedHandle = Arc::new(tokio::sync::RwLock::new(None));
        let remote = forwards.iter().any(|r| r.kind == forward::ForwardKind::Remote).then(|| forward::RemoteTargets {
            map: forwards
                .iter()
                .filter(|r| r.kind == forward::ForwardKind::Remote)
                .map(|r| (u32::from(r.listen_port), (r.dest_host.clone(), r.dest_port)))
                .collect(),
            shutdown: shutdown_rx.clone(),
        });
        let mut listeners_started = false;

        loop {
            // Drain commands sent while we were disconnected; keep the latest size.
            while let Ok(c) = rx.try_recv() {
                match c {
                    Cmd::Resize(s) => size = s,
                    Cmd::Close => {
                        let _ = events.send(SessionEvent::Closed { reason: "closed by user".into() }).await;
                        return;
                    }
                    Cmd::Write(_) => {}
                    Cmd::Exec { reply, .. } => {
                        let _ = reply.send(Err(Error::Closed));
                    }
                }
            }

            match connect_with(&cfg, &secrets, remote.clone(), &jumps, &ask).await {
                Ok(Conn { handle, fingerprint: fp, jumps: jump_conns }) => {
                    attempt = 0;
                    delay = policy.initial_delay;
                    // Keys seen first in this session stay pinned for its
                    // reconnects too, not only once the caller has saved them.
                    for (j, jc) in jumps.iter_mut().zip(&jump_conns) {
                        j.cfg.host_key_fingerprint.get_or_insert_with(|| jc.fingerprint.clone());
                        let _ = events
                            .send(SessionEvent::JumpConnected { host_id: jc.host_id.clone(), fingerprint: jc.fingerprint.clone() })
                            .await;
                    }
                    cfg.host_key_fingerprint.get_or_insert_with(|| fp.clone());
                    let handle = Arc::new(handle);
                    *current.write().await = Some(handle.clone());
                    let _ = events.send(SessionEvent::Connected { fingerprint: fp }).await;

                    // Local / SOCKS listeners once; they outlive reconnects.
                    if !listeners_started {
                        listeners_started = true;
                        for rule in forwards.iter().filter(|r| r.kind != forward::ForwardKind::Remote) {
                            forward::start_listener(rule.clone(), current.clone(), shutdown_rx.clone(), events.clone()).await;
                        }
                    }
                    // Remote forwards belong to the connection: ask again every time.
                    forward::request_remote(&handle, &forwards, &events).await;

                    let outcome = run_shell(&handle, &cfg, &mut size, &mut rx, &events).await;
                    *current.write().await = None;
                    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                    disconnect_all(&jump_conns).await;

                    match outcome {
                        Ok(true) => {
                            let _ = events.send(SessionEvent::Closed { reason: "closed by user".into() }).await;
                            return;
                        }
                        Ok(false) => { /* remote closed: fall through to reconnect */ }
                        Err(e) => {
                            tracing::warn!("shell error: {e}");
                        }
                    }
                }
                Err(Error::HostKeyMismatch { host_id, expected, actual }) => {
                    let _ = events.send(SessionEvent::HostKeyMismatch { host_id, expected, actual }).await;
                    return;
                }
                Err(Error::HostKeyUnknown { host_id, actual }) => {
                    let _ = events.send(SessionEvent::HostKeyUnknown { host_id, actual }).await;
                    return;
                }
                Err(e) if is_fatal(&e) => {
                    // Retrying will not help; surface immediately.
                    let _ = events.send(SessionEvent::Closed { reason: e.to_string() }).await;
                    return;
                }
                Err(e) => {
                    tracing::warn!("connect error: {e}");
                }
            }

            if !policy.enabled {
                let _ = events.send(SessionEvent::Closed { reason: "connection lost".into() }).await;
                return;
            }
            attempt += 1;
            if let Some(max) = policy.max_attempts {
                if attempt > max {
                    let _ = events.send(SessionEvent::Closed { reason: "reconnect attempts exhausted".into() }).await;
                    return;
                }
            }
            let _ = events
                .send(SessionEvent::Reconnecting { attempt, delay, reason: "connection lost".into() })
                .await;

            // Sleep, but wake early if the user closes the tab.
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                cmd = rx.recv() => {
                    if matches!(cmd, Some(Cmd::Close) | None) {
                        let _ = events.send(SessionEvent::Closed { reason: "closed by user".into() }).await;
                        return;
                    }
                }
            }
            delay = (delay * 2).min(policy.max_delay);
        }
    });

    SessionHandle { tx, prompt }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_key_files_are_recognized_by_their_public_half() {
        let dir = std::env::current_exe().unwrap().parent().unwrap().join("test-scratch").join(format!("sk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("id_ed25519_sk.pub"), "sk-ssh-ed25519@openssh.com AAAAGnNr... me@laptop\n").unwrap();
        std::fs::write(dir.join("id_ed25519.pub"), "ssh-ed25519 AAAAC3Nz... me@laptop\n").unwrap();
        assert!(is_security_key(&dir.join("id_ed25519_sk")));
        assert!(!is_security_key(&dir.join("id_ed25519")));
        assert!(!is_security_key(&dir.join("missing")), "no .pub: decided after loading");
        assert!(is_fatal(&Error::SecurityKeyFile), "never retried");
    }

    #[test]
    fn host_config_roundtrip_does_not_contain_secrets() {
        let cfg = HostConfig {
            id: "h1".into(),
            name: "prod".into(),
            host: "example.com".into(),
            port: 22,
            user: "root".into(),
            auth: AuthMethod::Password,
            host_key_fingerprint: None,
            startup_command: Some("tmux new -A -s shellwick".into()),
            tags: vec![],
            environment: Some("production".into()),
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
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("password\":"));
        let back: HostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port, 22);
    }

    #[test]
    fn hosts_saved_before_forwarding_still_load() {
        let old = r#"{"id":"h","name":"n","host":"x","port":22,"user":"u","auth":{"kind":"password"},
                      "host_key_fingerprint":null,"startup_command":null}"#;
        let cfg: HostConfig = serde_json::from_str(old).unwrap();
        assert!(cfg.forwards.is_empty());
        assert!(cfg.tags.is_empty());
        assert!(cfg.jump_host.is_none());
        assert!(!cfg.confirm_new_key, "old hosts keep trust-on-first-use");
    }

    #[test]
    fn pasted_fingerprints_are_normalized() {
        let b64 = "YgdZWTpv4WZUa1uEA7Syjuv2VTOTPRLxWzXUybNS7Ys";
        let want = format!("SHA256:{b64}");
        assert_eq!(parse_fingerprint(&want).unwrap(), want);
        assert_eq!(parse_fingerprint(&format!("  {b64}  ")).unwrap(), want);
        assert_eq!(parse_fingerprint(&format!("{b64}=")).unwrap(), want, "trailing base64 padding is dropped");
        assert_eq!(parse_fingerprint(&format!("256 SHA256:{b64} root@web-1 (ED25519)")).unwrap(), want, "a whole ssh-keygen -lf line");
    }

    #[test]
    fn bad_fingerprints_are_explained() {
        assert_eq!(parse_fingerprint("  "), Err("Paste the server's SHA256 fingerprint."));
        assert!(parse_fingerprint("MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48").unwrap_err().contains("MD5"));
        assert!(parse_fingerprint("16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48").unwrap_err().contains("MD5"));
        assert!(parse_fingerprint("SHA256:tooshort").unwrap_err().starts_with("That doesn't look like"));
        assert!(parse_fingerprint("SHA256:YgdZWTpv4WZUa1uEA7Syjuv2VTOTPRLxWzXUybNS7Y!").is_err());
    }

    #[test]
    fn jump_host_failures_name_the_jump_host_and_keep_their_kind() {
        let auth = Error::Jump { name: "bastion".into(), source: Box::new(Error::MissingSecret("password")) };
        assert_eq!(auth.to_string(), "jump host bastion: missing secret: password");
        assert!(is_fatal(&auth), "a jump host that can't sign in won't fix itself");

        let network = Error::Jump { name: "bastion".into(), source: Box::new(timed_out()) };
        assert!(!is_fatal(&network), "a jump host that is down may come back: keep retrying");
        assert!(!is_fatal(&Error::Unreachable("The jump host bastion couldn't reach api-1 (Connect failed)".into())));
    }

    #[test]
    fn key_path_tilde_expands_to_home() {
        let home = Path::new("/home/me");
        assert_eq!(expand_home("~/.ssh/id_ed25519", Some(home)), home.join(".ssh/id_ed25519"));
        assert_eq!(expand_home("~\\.ssh\\id", Some(home)), home.join(".ssh\\id"));
        assert_eq!(expand_home("~", Some(home)), home.to_path_buf());
    }

    #[test]
    fn key_path_without_tilde_is_untouched() {
        let home = Path::new("/home/me");
        assert_eq!(expand_home("/etc/key", Some(home)), PathBuf::from("/etc/key"));
        assert_eq!(expand_home("~other/key", Some(home)), PathBuf::from("~other/key"));
        assert_eq!(expand_home("~/.ssh/id", None), PathBuf::from("~/.ssh/id"));
    }

    #[test]
    fn backoff_is_capped() {
        let p = ReconnectPolicy::default();
        let mut d = p.initial_delay;
        for _ in 0..10 {
            d = (d * 2).min(p.max_delay);
        }
        assert_eq!(d, p.max_delay);
    }
}
