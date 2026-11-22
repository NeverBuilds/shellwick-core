//! Port forwarding: local (`-L`), remote (`-R`) and dynamic SOCKS5 (`-D`).
//!
//! Rules belong to a host and run inside its shell session: local and SOCKS
//! listeners are opened after the first successful connection and survive
//! reconnects (connections arriving while disconnected are dropped); remote
//! forwards are requested again after every connection. Everything stops when
//! the session ends.
//!
//! Local listeners bind loopback only: a tunnel into the remote network must
//! not be reachable from the LAN.

use crate::{SessionEvent, TofuHandler};
use russh::client::Handle;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock};

/// Address local and SOCKS listeners bind to.
pub const LOCAL_BIND: &str = "127.0.0.1";
/// Address remote forwards ask the server to listen on (its loopback).
pub const REMOTE_BIND: &str = "localhost";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    /// `-L`: listen locally, connect to `dest` from the server.
    Local,
    /// `-R`: the server listens, connections come back to `dest` on this machine.
    Remote,
    /// `-D`: local SOCKS5 proxy; each client picks its own destination.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRule {
    pub id: String,
    pub kind: ForwardKind,
    /// Local / Dynamic: port on this machine. Remote: port on the server.
    pub listen_port: u16,
    /// Local: resolved by the server. Remote: resolved here. Unused for Dynamic.
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

impl ForwardRule {
    /// Short human description, e.g. `localhost:8080 → db.internal:5432`.
    pub fn describe(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!("localhost:{} → {}:{}", self.listen_port, self.dest_host, self.dest_port),
            ForwardKind::Remote => format!("server localhost:{} → {}:{}", self.listen_port, self.dest_host, self.dest_port),
            ForwardKind::Dynamic => format!("SOCKS5 proxy on localhost:{}", self.listen_port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ForwardStatus {
    /// Listening (local / SOCKS) or accepted by the server (remote).
    Active,
    Failed { reason: String },
}

/// Problems with a set of rules, as `(rule id, message)`. Disabled rules are
/// checked for shape but never clash with others.
pub fn validate_rules(rules: &[ForwardRule]) -> Vec<(String, String)> {
    let mut problems = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        let mut say = |m: &str| problems.push((r.id.clone(), m.to_string()));
        if r.listen_port == 0 {
            say("Pick a listen port between 1 and 65535.");
        }
        if r.kind != ForwardKind::Dynamic {
            let host = r.dest_host.trim();
            if host.is_empty() {
                say("Destination host is required.");
            } else if host.chars().any(|c| c.is_whitespace() || c == '/') {
                say("Destination host looks wrong (no spaces or slashes).");
            }
            if r.dest_port == 0 {
                say("Pick a destination port between 1 and 65535.");
            }
        }
        // Local and SOCKS share this machine's ports; remote ones are on the server.
        let local_side = |k: ForwardKind| k != ForwardKind::Remote;
        let clash = r.enabled
            && r.listen_port != 0
            && rules[..i].iter().any(|o| {
                o.enabled && o.listen_port == r.listen_port && local_side(o.kind) == local_side(r.kind)
            });
        if clash {
            say(&format!("Port {} is already used by another rule.", r.listen_port));
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928): no authentication, CONNECT only
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SocksError {
    #[error("not a SOCKS5 client")]
    Version,
    #[error("client insists on authentication")]
    NoAcceptableAuth,
    #[error("only CONNECT is supported")]
    Command,
    #[error("unsupported address type")]
    AddressType,
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        SocksError::Io(e.to_string())
    }
}

const SOCKS_OK: u8 = 0x00;
const SOCKS_FAILURE: u8 = 0x01;
const SOCKS_CMD_UNSUPPORTED: u8 = 0x07;
const SOCKS_ATYP_UNSUPPORTED: u8 = 0x08;

/// Runs the SOCKS5 greeting and request; returns the requested destination.
/// On a protocol error the matching error reply has already been sent.
pub async fn socks5_accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(String, u16), SocksError> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(SocksError::Version);
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        s.write_all(&[5, 0xFF]).await?;
        return Err(SocksError::NoAcceptableAuth);
    }
    s.write_all(&[5, 0x00]).await?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(SocksError::Version);
    }
    if req[1] != 0x01 {
        socks5_reply(s, SOCKS_CMD_UNSUPPORTED).await?;
        return Err(SocksError::Command);
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| SocksError::AddressType)?
        }
        0x04 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            socks5_reply(s, SOCKS_ATYP_UNSUPPORTED).await?;
            return Err(SocksError::AddressType);
        }
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Sends a SOCKS5 reply with an all-zero bound address.
pub async fn socks5_reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> std::io::Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

// ---------------------------------------------------------------------------
// Running forwards inside a session
// ---------------------------------------------------------------------------

/// The live SSH connection of a session, `None` while (re)connecting.
pub(crate) type SharedHandle = Arc<RwLock<Option<Arc<Handle<TofuHandler>>>>>;

/// Remote-forward targets the SSH handler needs when the server opens a
/// `forwarded-tcpip` channel: server port → local destination.
#[derive(Debug, Clone)]
pub(crate) struct RemoteTargets {
    pub map: std::collections::HashMap<u32, (String, u16)>,
    pub shutdown: watch::Receiver<bool>,
}

/// Copies both ways until either side closes or the session shuts down.
pub(crate) async fn pipe<A, B>(mut a: A, mut b: B, mut shutdown: watch::Receiver<bool>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut a, &mut b) => {}
        _ = shutdown.changed() => {}
    }
    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
}

/// Connects to a remote-forward destination on this machine and pipes it to
/// the channel the server opened.
pub(crate) fn serve_remote_channel(channel: russh::Channel<russh::client::Msg>, host: String, port: u16, shutdown: watch::Receiver<bool>) {
    tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(tcp)) => pipe(tcp, channel.into_stream(), shutdown).await,
            _ => {
                let _ = channel.close().await;
            }
        }
    });
}

fn bind_error(port: u16, e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::AddrInUse => format!("Port {port} is already in use on this computer."),
        std::io::ErrorKind::PermissionDenied => format!("Not allowed to listen on port {port}."),
        _ => format!("Couldn't listen on port {port}: {e}"),
    }
}

/// Opens a local or SOCKS listener for `rule` and serves it in the
/// background until `shutdown` fires. Reports the outcome as a Forward event.
pub(crate) async fn start_listener(
    rule: ForwardRule,
    current: SharedHandle,
    shutdown: watch::Receiver<bool>,
    events: mpsc::Sender<SessionEvent>,
) {
    let listener = match TcpListener::bind((LOCAL_BIND, rule.listen_port)).await {
        Ok(l) => l,
        Err(e) => {
            let reason = bind_error(rule.listen_port, &e);
            let _ = events.send(SessionEvent::Forward { id: rule.id, status: ForwardStatus::Failed { reason } }).await;
            return;
        }
    };
    let _ = events.send(SessionEvent::Forward { id: rule.id.clone(), status: ForwardStatus::Active }).await;

    let mut stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = stop.changed() => return,
            };
            let Ok((mut tcp, peer)) = accepted else { continue };
            let current = current.clone();
            let rule = rule.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let target = match rule.kind {
                    ForwardKind::Dynamic => match socks5_accept(&mut tcp).await {
                        Ok(t) => t,
                        Err(_) => return,
                    },
                    _ => (rule.dest_host.clone(), rule.dest_port),
                };
                // Disconnected right now: drop the client rather than queue it.
                let handle = current.read().await.clone();
                let Some(handle) = handle else {
                    if rule.kind == ForwardKind::Dynamic {
                        let _ = socks5_reply(&mut tcp, SOCKS_FAILURE).await;
                    }
                    return;
                };
                let opened = handle
                    .channel_open_direct_tcpip(target.0, u32::from(target.1), peer.ip().to_string(), u32::from(peer.port()))
                    .await;
                drop(handle);
                match opened {
                    Ok(channel) => {
                        if rule.kind == ForwardKind::Dynamic && socks5_reply(&mut tcp, SOCKS_OK).await.is_err() {
                            return;
                        }
                        pipe(tcp, channel.into_stream(), shutdown).await;
                    }
                    Err(_) => {
                        if rule.kind == ForwardKind::Dynamic {
                            let _ = socks5_reply(&mut tcp, SOCKS_FAILURE).await;
                        }
                    }
                }
            });
        }
    });
}

/// Asks the server to listen for every enabled remote rule; reports each.
pub(crate) async fn request_remote(handle: &Handle<TofuHandler>, rules: &[ForwardRule], events: &mpsc::Sender<SessionEvent>) {
    for r in rules.iter().filter(|r| r.enabled && r.kind == ForwardKind::Remote) {
        let status = match handle.tcpip_forward(REMOTE_BIND, u32::from(r.listen_port)).await {
            Ok(_) => ForwardStatus::Active,
            Err(e) => ForwardStatus::Failed {
                reason: format!("The server refused to listen on port {} ({e}).", r.listen_port),
            },
        };
        let _ = events.send(SessionEvent::Forward { id: r.id.clone(), status }).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, kind: ForwardKind, listen: u16, host: &str, port: u16) -> ForwardRule {
        ForwardRule { id: id.into(), kind, listen_port: listen, dest_host: host.into(), dest_port: port, enabled: true }
    }

    #[test]
    fn valid_rules_pass() {
        let rules = [
            rule("a", ForwardKind::Local, 8080, "db.internal", 5432),
            rule("b", ForwardKind::Remote, 8080, "localhost", 3000), // remote port space is separate
            rule("c", ForwardKind::Dynamic, 1080, "", 0),
        ];
        assert_eq!(validate_rules(&rules), vec![]);
    }

    #[test]
    fn shape_problems_are_reported_per_rule() {
        let problems = validate_rules(&[
            rule("a", ForwardKind::Local, 0, "", 0),
            rule("b", ForwardKind::Remote, 9000, "bad host", 80),
        ]);
        let ids: Vec<_> = problems.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["a", "a", "a", "b"], "{problems:?}");
    }

    #[test]
    fn clashing_ports_are_caught_but_disabled_rules_do_not_clash() {
        let mut off = rule("c", ForwardKind::Local, 8080, "x", 1);
        off.enabled = false;
        let problems = validate_rules(&[
            rule("a", ForwardKind::Local, 8080, "x", 1),
            rule("b", ForwardKind::Dynamic, 8080, "", 0), // same local port as "a"
            off,
        ]);
        assert_eq!(problems, vec![("b".into(), "Port 8080 is already used by another rule.".into())]);
    }

    #[test]
    fn rules_load_from_older_json_shapes() {
        let r: ForwardRule = serde_json::from_str(r#"{"id":"s","kind":"dynamic","listen_port":1080}"#).unwrap();
        assert!(r.enabled, "enabled defaults to true");
        assert_eq!(r.dest_host, "");
        assert_eq!(r.describe(), "SOCKS5 proxy on localhost:1080");
    }

    /// Feeds `client` bytes to the server side and returns the outcome plus what the server wrote back.
    async fn socks(client: &[u8]) -> (Result<(String, u16), SocksError>, Vec<u8>) {
        let (mut server_side, mut client_side) = tokio::io::duplex(1024);
        client_side.write_all(client).await.unwrap();
        let result = socks5_accept(&mut server_side).await;
        drop(server_side);
        let mut written = Vec::new();
        client_side.read_to_end(&mut written).await.unwrap();
        (result, written)
    }

    #[tokio::test]
    async fn socks5_connect_by_domain_ipv4_and_ipv6() {
        let (r, w) = socks(&[5, 1, 0, 5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g', 0x01, 0xBB]).await;
        assert_eq!(r, Ok(("example.org".into(), 443)));
        assert_eq!(w, [5, 0], "only the method choice is sent; the caller sends the final reply");

        let (r, _) = socks(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 4, 12, 0x15, 0x38]).await;
        assert_eq!(r, Ok(("10.0.4.12".into(), 5432)));

        let mut v6 = vec![5, 2, 2, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&22u16.to_be_bytes());
        let (r, _) = socks(&v6).await;
        assert_eq!(r, Ok(("::1".into(), 22)));
    }

    #[tokio::test]
    async fn socks5_rejects_what_it_does_not_support() {
        let (r, _) = socks(&[4, 1, 0, 80]).await;
        assert_eq!(r, Err(SocksError::Version));

        let (r, w) = socks(&[5, 1, 2]).await; // username/password only
        assert_eq!(r, Err(SocksError::NoAcceptableAuth));
        assert_eq!(w, [5, 0xFF]);

        let (r, w) = socks(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await; // BIND
        assert_eq!(r, Err(SocksError::Command));
        assert_eq!(&w[2..4], &[5, SOCKS_CMD_UNSUPPORTED]);

        let (r, w) = socks(&[5, 1, 0, 5, 1, 0, 9]).await; // unknown address type
        assert_eq!(r, Err(SocksError::AddressType));
        assert_eq!(&w[2..4], &[5, SOCKS_ATYP_UNSUPPORTED]);
    }

    #[tokio::test]
    async fn pipe_copies_both_ways_and_stops_on_shutdown() {
        let (a_near, mut a_far) = tokio::io::duplex(64);
        let (b_near, mut b_far) = tokio::io::duplex(64);
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(pipe(a_near, b_near, rx));

        a_far.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        b_far.write_all(b"pong").await.unwrap();
        a_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task).await.expect("pipe stops on shutdown").unwrap();
    }
}
