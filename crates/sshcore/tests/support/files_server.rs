//! An SSH server inside the test (russh's server side): password sign-in,
//! SFTP over a local folder (see `dir_sftp`). Test files include it with
//! `#[path = "support/files_server.rs"] mod files_server;` next to `dir_sftp`.

use crate::dir_sftp;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use sshcore::{AuthMethod, HostConfig, Secrets};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const PASSWORD: &str = "files-test";
pub const HOME: &str = "/home/deploy";

struct Srv {
    root: PathBuf,
    modes: dir_sftp::Modes,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == PASSWORD { Auth::Accept } else { Auth::Reject { proceed_with_methods: None, partial_success: false } })
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: ChannelOpenHandle, _: &mut Session) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    /// Acts as a jump host: any name means this machine (so chains of test
    /// servers work); a port nobody listens on is refused like a real server.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _host: &str,
        port: u32,
        _from: &str,
        _from_port: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        match tokio::net::TcpStream::connect(("127.0.0.1", port as u16)).await {
            Ok(mut tcp) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                });
            }
            Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&channel)) {
            ("sftp", Some(ch)) => {
                session.channel_success(channel)?;
                let files = dir_sftp::DirSftp::new(self.root.clone(), HOME, self.modes.clone());
                tokio::spawn(russh_sftp::server::run(ch.into_stream(), files));
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

/// Starts a server over `root` on a free local port; returns the port.
pub async fn start(root: PathBuf) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)), "shellwick-files-test").unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    let modes = dir_sftp::Modes::default();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let srv = Srv { root: root.clone(), modes: modes.clone(), channels: HashMap::new() };
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

/// A saved host for the server at `host:port`.
pub fn host(host: &str, port: u16) -> HostConfig {
    HostConfig {
        id: "files-id".into(),
        name: "files-box".into(),
        host: host.into(),
        port,
        user: "deploy".into(),
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
        forward_agent: false,
        keepalive_secs: None,
        legacy_algorithms: false,
    }
}

pub fn secrets() -> Secrets {
    Secrets { password: Some(PASSWORD.into()), ..Default::default() }
}
