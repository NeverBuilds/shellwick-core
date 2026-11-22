//! Connecting through a proxy, end to end: an SSH server and SOCKS5 / HTTP
//! CONNECT proxies all run inside the test. The server is addressed by a name
//! only the proxy knows ("files.test"), so a connection that skipped the proxy
//! would fail. Runs by default (no external server needed).

#[path = "support/dir_sftp.rs"]
mod dir_sftp;
#[path = "support/files_server.rs"]
mod files_server;

use sshcore::proxy::{ProxyConfig, ProxyKind, PROXY_SIGN_IN_REFUSED, PROXY_WANTS_SIGN_IN};
use sshcore::sftp::SftpClient;
use sshcore::{Error, Secrets};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "files.test";

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("proxy-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What a test proxy saw: the target it was asked for.
type Seen = Arc<Mutex<Vec<String>>>;

/// A SOCKS5 proxy that sends every name to 127.0.0.1; `creds` = required user / password.
async fn socks5(creds: Option<(&'static str, &'static str)>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                c.read_exact(&mut head).await?;
                let mut methods = vec![0u8; head[1] as usize];
                c.read_exact(&mut methods).await?;
                match creds {
                    None => c.write_all(&[5, 0]).await?,
                    Some(_) if !methods.contains(&2) => {
                        c.write_all(&[5, 0xFF]).await?;
                        return Ok::<_, std::io::Error>(());
                    }
                    Some((user, pass)) => {
                        c.write_all(&[5, 2]).await?;
                        let mut v = [0u8; 2];
                        c.read_exact(&mut v).await?;
                        let mut u = vec![0u8; v[1] as usize];
                        c.read_exact(&mut u).await?;
                        let mut pl = [0u8; 1];
                        c.read_exact(&mut pl).await?;
                        let mut p = vec![0u8; pl[0] as usize];
                        c.read_exact(&mut p).await?;
                        let ok = u == user.as_bytes() && p == pass.as_bytes();
                        c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
                        if !ok {
                            return Ok(());
                        }
                    }
                }
                let mut req = [0u8; 4];
                c.read_exact(&mut req).await?;
                let target = match req[3] {
                    3 => {
                        let mut len = [0u8; 1];
                        c.read_exact(&mut len).await?;
                        let mut name = vec![0u8; len[0] as usize];
                        c.read_exact(&mut name).await?;
                        String::from_utf8_lossy(&name).into_owned()
                    }
                    _ => {
                        let mut ip = [0u8; 4];
                        c.read_exact(&mut ip).await?;
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                };
                let mut port = [0u8; 2];
                c.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                log.lock().unwrap().push(format!("{target}:{port}"));
                match TcpStream::connect(("127.0.0.1", port)).await {
                    Ok(mut up) => {
                        c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    }
                    Err(_) => c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
                }
                Ok(())
            });
        }
    });
    (port, seen)
}

/// An HTTP CONNECT proxy (names go to 127.0.0.1); `auth` = the required Basic credentials, encoded.
async fn http(auth: Option<&'static str>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if c.read(&mut b).await? == 0 {
                        return Ok::<_, std::io::Error>(());
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let target = text.split_whitespace().nth(1).unwrap_or_default().to_string();
                log.lock().unwrap().push(target.clone());
                if let Some(want) = auth {
                    if !text.contains(&format!("Proxy-Authorization: Basic {want}\r\n")) {
                        c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n").await?;
                        return Ok(());
                    }
                }
                let port: u16 = target.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let mut up = TcpStream::connect(("127.0.0.1", port)).await?;
                c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                Ok(())
            });
        }
    });
    (port, seen)
}

fn proxy(kind: ProxyKind, port: u16, user: Option<&str>) -> ProxyConfig {
    ProxyConfig { kind, host: "127.0.0.1".into(), port, user: user.map(Into::into) }
}

async fn try_connect(ssh_port: u16, p: ProxyConfig, proxy_password: Option<&str>) -> Result<SftpClient, Error> {
    let mut cfg = files_server::host(NAME, ssh_port);
    cfg.proxy = Some(p);
    let secrets = Secrets { proxy_password: proxy_password.map(Into::into), ..files_server::secrets() };
    SftpClient::connect(&cfg, &secrets).await
}

fn proxy_error(r: Result<SftpClient, Error>) -> (String, bool) {
    match r {
        Err(Error::Proxy { message, fatal }) => (message, fatal),
        Err(e) => panic!("not a proxy error: {e}"),
        Ok(_) => panic!("connected"),
    }
}

#[tokio::test]
async fn socks5_with_and_without_sign_in() {
    let root = scratch("socks");
    let ssh = files_server::start(root.clone()).await;

    let (open, seen) = socks5(None).await;
    let c = try_connect(ssh, proxy(ProxyKind::Socks5, open, None), None).await.expect("through the proxy");
    assert_eq!(c.home(), files_server::HOME);
    c.close().await;
    assert_eq!(seen.lock().unwrap().as_slice(), [format!("{NAME}:{ssh}")], "the name goes to the proxy, which resolves it");

    let (guarded, _) = socks5(Some(("alice", "s3cret"))).await;
    let c = try_connect(ssh, proxy(ProxyKind::Socks5, guarded, Some("alice")), Some("s3cret")).await.expect("signed in to the proxy");
    c.close().await;
    assert_eq!(proxy_error(try_connect(ssh, proxy(ProxyKind::Socks5, guarded, Some("alice")), Some("wrong")).await), (PROXY_SIGN_IN_REFUSED.to_string(), true));
    assert_eq!(proxy_error(try_connect(ssh, proxy(ProxyKind::Socks5, guarded, None), None).await), (PROXY_WANTS_SIGN_IN.to_string(), true));

    // The proxy can't reach the server: worth retrying.
    let (msg, fatal) = proxy_error(try_connect(1, proxy(ProxyKind::Socks5, open, None), None).await);
    assert_eq!((msg.as_str(), fatal), ("The proxy couldn't connect to files.test:1 (connection refused)", false));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn http_connect_with_and_without_sign_in() {
    let root = scratch("http");
    let ssh = files_server::start(root.clone()).await;

    let (open, seen) = http(None).await;
    let c = try_connect(ssh, proxy(ProxyKind::Http, open, None), None).await.expect("through the proxy");
    assert_eq!(c.list(files_server::HOME).await.unwrap().len(), 0, "the SSH greeting right after the 200 isn't lost");
    c.close().await;
    assert_eq!(seen.lock().unwrap().as_slice(), [format!("{NAME}:{ssh}")]);

    // "bob:pw" in Basic.
    let (guarded, _) = http(Some("Ym9iOnB3")).await;
    let c = try_connect(ssh, proxy(ProxyKind::Http, guarded, Some("bob")), Some("pw")).await.expect("signed in to the proxy");
    c.close().await;
    assert_eq!(proxy_error(try_connect(ssh, proxy(ProxyKind::Http, guarded, Some("bob")), Some("nope")).await), (PROXY_SIGN_IN_REFUSED.to_string(), true));
    assert_eq!(proxy_error(try_connect(ssh, proxy(ProxyKind::Http, guarded, None), None).await), (PROXY_WANTS_SIGN_IN.to_string(), true));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn unreachable_proxy_is_retried() {
    // A port nothing listens on.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (msg, fatal) = proxy_error(try_connect(22, proxy(ProxyKind::Socks5, free, None), None).await);
    assert!(msg.starts_with(&format!("Couldn't reach the proxy 127.0.0.1:{free} (")), "{msg}");
    assert!(!fatal);
}
