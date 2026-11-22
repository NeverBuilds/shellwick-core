//! Connecting through a proxy: SOCKS5 (RFC 1928, with the RFC 1929 user /
//! password sign-in) or HTTP CONNECT (with Basic sign-in). The proxy resolves
//! the server's name (SOCKS5 sends it as a domain name), so names that only
//! the proxy's network knows work too.
//!
//! The proxy password is a secret like the server password: it comes from the
//! caller (the OS keyring) in [`crate::Secrets`] and is never logged.

use crate::Error;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    Socks5,
    Http,
}

/// A server's proxy (its password is in the keyring, see [`crate::Secrets`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Sign in to the proxy with this user (and the saved proxy password).
    #[serde(default)]
    pub user: Option<String>,
}

pub const PROXY_NO_HOST: &str = "Type the proxy's address.";
pub const PROXY_BAD_HOST: &str = "The proxy address can't contain spaces or control characters.";
pub const PROXY_BAD_PORT: &str = "The proxy port must be between 1 and 65535.";
pub const PROXY_BAD_USER: &str = "The proxy user name can be at most 255 characters, on one line.";
pub const PROXY_WANTS_SIGN_IN: &str = "The proxy wants a user name and password. Add them in this server's proxy settings.";
pub const PROXY_SIGN_IN_REFUSED: &str = "The proxy didn't accept the user name or password.";
pub const PROXY_NO_METHOD: &str = "The proxy doesn't offer a way to sign in that Shellwick supports.";
pub const PROXY_NOT_SOCKS: &str = "That proxy didn't answer like a SOCKS5 proxy. Check the type and port.";
pub const PROXY_NOT_HTTP: &str = "That proxy didn't answer like an HTTP proxy. Check the type and port.";

/// Checks a proxy setting (the same rules and words as the server form).
pub fn check(p: &ProxyConfig) -> Result<(), &'static str> {
    let host = p.host.trim();
    if host.is_empty() {
        return Err(PROXY_NO_HOST);
    }
    if host.chars().count() > 255 || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PROXY_BAD_HOST);
    }
    if p.port == 0 {
        return Err(PROXY_BAD_PORT);
    }
    if p.user.as_deref().is_some_and(|u| u.len() > 255 || u.chars().any(char::is_control)) {
        return Err(PROXY_BAD_USER);
    }
    Ok(())
}

/// "host:port", with brackets around an IPv6 address.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn fatal(message: impl Into<String>) -> Error {
    Error::Proxy { message: message.into(), fatal: true }
}

fn retry(message: impl Into<String>) -> Error {
    Error::Proxy { message: message.into(), fatal: false }
}

/// Opens a TCP connection to `host:port` through the proxy. Errors say what
/// went wrong in plain words; sign-in and setting problems are fatal (no
/// reconnect loop), an unreachable proxy or target is retried.
pub async fn connect(p: &ProxyConfig, password: Option<&str>, host: &str, port: u16) -> Result<TcpStream, Error> {
    let bare_proxy = p.host.trim().trim_start_matches('[').trim_end_matches(']');
    let at = host_port(bare_proxy, p.port);
    let mut tcp = TcpStream::connect((bare_proxy, p.port)).await.map_err(|e| retry(format!("Couldn't reach the proxy {at} ({e})")))?;
    let _ = tcp.set_nodelay(true);
    let user = p.user.as_deref().filter(|u| !u.is_empty());
    match p.kind {
        ProxyKind::Socks5 => socks5(&mut tcp, user, password, host, port).await?,
        ProxyKind::Http => {
            tcp = http_connect(tcp, user, password, host, port).await?;
        }
    }
    Ok(tcp)
}

async fn socks5(tcp: &mut TcpStream, user: Option<&str>, password: Option<&str>, host: &str, port: u16) -> Result<(), Error> {
    let lost = |e: std::io::Error| retry(format!("The proxy closed the connection ({e})"));
    // Offer "no sign-in", and user / password when there is a user.
    let hello: &[u8] = if user.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    tcp.write_all(hello).await.map_err(lost)?;
    let mut choice = [0u8; 2];
    tcp.read_exact(&mut choice).await.map_err(lost)?;
    if choice[0] != 5 {
        return Err(fatal(PROXY_NOT_SOCKS));
    }
    match (choice[1], user) {
        (0, _) => {}
        (2, Some(u)) => {
            let pw = password.unwrap_or("");
            if u.len() > 255 || pw.len() > 255 {
                return Err(fatal(PROXY_BAD_USER));
            }
            let mut msg = vec![1, u.len() as u8];
            msg.extend_from_slice(u.as_bytes());
            msg.push(pw.len() as u8);
            msg.extend_from_slice(pw.as_bytes());
            tcp.write_all(&msg).await.map_err(lost)?;
            let mut status = [0u8; 2];
            tcp.read_exact(&mut status).await.map_err(lost)?;
            if status[1] != 0 {
                return Err(fatal(PROXY_SIGN_IN_REFUSED));
            }
        }
        (2, None) | (0xFF, None) => return Err(fatal(PROXY_WANTS_SIGN_IN)),
        _ => return Err(fatal(PROXY_NO_METHOD)),
    }
    // CONNECT to the server by name (the proxy resolves it) or by address.
    let mut req = vec![5, 1, 0];
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(fatal(PROXY_BAD_HOST));
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await.map_err(lost)?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await.map_err(lost)?;
    if head[0] != 5 {
        return Err(fatal(PROXY_NOT_SOCKS));
    }
    if head[1] != 0 {
        let why = match head[1] {
            1 => "general failure",
            2 => "not allowed by the proxy's rules",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "timed out",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        };
        let message = format!("The proxy couldn't connect to {} ({why})", host_port(bare, port));
        // The proxy's rules or abilities won't change by trying again.
        return Err(if matches!(head[1], 2 | 7 | 8) { fatal(message) } else { retry(message) });
    }
    // Skip the bound address the proxy reports.
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(lost)?;
            len[0] as usize
        }
        _ => return Err(fatal(PROXY_NOT_SOCKS)),
    };
    let mut rest = vec![0u8; skip + 2];
    tcp.read_exact(&mut rest).await.map_err(lost)?;
    Ok(())
}

async fn http_connect(mut tcp: TcpStream, user: Option<&str>, password: Option<&str>, host: &str, port: u16) -> Result<TcpStream, Error> {
    let lost = |e: std::io::Error| retry(format!("The proxy closed the connection ({e})"));
    let target = host_port(host.trim_start_matches('[').trim_end_matches(']'), port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(u) = user {
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64(format!("{u}:{}", password.unwrap_or("")).as_bytes())));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await.map_err(lost)?;
    // The reply's headers, one byte at a time: the SSH server's own greeting
    // may follow right behind them and must stay in the stream.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(fatal(PROXY_NOT_HTTP));
        }
        let mut byte = [0u8; 1];
        if tcp.read(&mut byte).await.map_err(lost)? == 0 {
            return Err(if head.is_empty() { retry("The proxy closed the connection") } else { fatal(PROXY_NOT_HTTP) });
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.split_whitespace();
    let code = match (parts.next(), parts.next().and_then(|c| c.parse::<u16>().ok())) {
        (Some(v), Some(code)) if v.starts_with("HTTP/1.") => code,
        _ => return Err(fatal(PROXY_NOT_HTTP)),
    };
    match code {
        200..=299 => Ok(tcp),
        407 => Err(fatal(if user.is_some() { PROXY_SIGN_IN_REFUSED } else { PROXY_WANTS_SIGN_IN })),
        // The proxy couldn't reach the server: may work later.
        502..=504 => Err(retry(format!("The proxy couldn't connect to {target} (HTTP {code})"))),
        _ => Err(fatal(format!("The proxy refused to connect to {target} (HTTP {code})"))),
    }
}

fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(host: &str, port: u16, user: Option<&str>) -> ProxyConfig {
        ProxyConfig { kind: ProxyKind::Socks5, host: host.into(), port, user: user.map(Into::into) }
    }

    #[test]
    fn settings_are_checked() {
        assert_eq!(check(&proxy("proxy.corp", 1080, None)), Ok(()));
        assert_eq!(check(&proxy("  ", 1080, None)), Err(PROXY_NO_HOST));
        assert_eq!(check(&proxy("a b", 1080, None)), Err(PROXY_BAD_HOST));
        assert_eq!(check(&proxy("p", 0, None)), Err(PROXY_BAD_PORT));
        assert_eq!(check(&proxy("p", 8080, Some("me\nyou"))), Err(PROXY_BAD_USER));
        assert_eq!(check(&proxy("::1", 8080, Some("me"))), Ok(()));
    }

    #[test]
    fn addresses_and_basic_auth() {
        assert_eq!(host_port("::1", 22), "[::1]:22");
        assert_eq!(host_port("example.com", 2222), "example.com:2222");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        let json = serde_json::to_string(&ProxyConfig { kind: ProxyKind::Http, host: "p".into(), port: 3128, user: None }).unwrap();
        assert_eq!(json, r#"{"kind":"http","host":"p","port":3128,"user":null}"#);
    }
}
