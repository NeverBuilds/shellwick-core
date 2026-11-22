//! Development-only SSH server that asks sign-in questions, for trying the
//! app's two-factor flow without a real PAM / TOTP server:
//!   cargo run -p sshcore --example otp_server
//! Listens on 127.0.0.1:47222 (SHELLWICK_OTP_PORT to change). Any user name.
//!
//! - Password sign-in is refused, like `PasswordAuthentication no`: the
//!   password is asked as a question ("Password: ", hidden), then a code.
//! - Any key is accepted as the first factor; the code is still asked.
//!
//! Password `shellwick-dev`, verification code `123456`; a wrong code is asked
//! again. The shell echoes what you type. The Files panel serves a real local
//! folder, read-write: `SHELLWICK_OTP_FILES` (default: <temp>/shellwick-otp-files),
//! with the home at /home/shellwick inside it. The host key is fixed, so the
//! fingerprint is the same on every run. Answers are never printed.

#[path = "../tests/support/dir_sftp.rs"]
mod dir_sftp;

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const PASSWORD: &str = "shellwick-dev";
const CODE: &str = "123456";
const HOME: &str = "/home/shellwick";

fn ki_only() -> MethodSet {
    MethodSet::from(&[MethodKind::KeyboardInteractive][..])
}

/// Like most servers, a refused answer just brings the same question back
/// (`_retry`: no note; Shellwick's banner says the answer wasn't accepted).
fn ask(text: &'static str, echo: bool, _retry: bool) -> Auth {
    Auth::Partial { name: Cow::Borrowed("Shellwick dev server"), instructions: Cow::Borrowed(""), prompts: Cow::Owned(vec![(Cow::Borrowed(text), echo)]) }
}

#[derive(Default)]
struct Srv {
    /// 1 = asking the password, 2 = asking the code.
    stage: u8,
    key_accepted: bool,
    channels: HashMap<ChannelId, Channel<Msg>>,
    /// Only shell channels echo (SFTP bytes go to the SFTP handler).
    shells: Vec<ChannelId>,
    files: PathBuf,
    modes: dir_sftp::Modes,
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, _: &str) -> Result<Auth, Self::Error> {
        println!("{user}: password sign-in refused (questions only)");
        Ok(Auth::Reject { proceed_with_methods: Some(ki_only()), partial_success: false })
    }

    async fn auth_publickey(&mut self, user: &str, _: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        println!("{user}: key accepted, a code is still needed");
        self.key_accepted = true;
        Ok(Auth::Reject { proceed_with_methods: Some(ki_only()), partial_success: true })
    }

    async fn auth_keyboard_interactive<'a>(&'a mut self, user: &str, _: &str, response: Option<Response<'a>>) -> Result<Auth, Self::Error> {
        let answer: Option<String> = match response {
            None => {
                self.stage = if self.key_accepted { 2 } else { 1 };
                None
            }
            Some(mut r) => r.next().map(|b| String::from_utf8_lossy(&b).into_owned()),
        };
        Ok(match (self.stage, answer.as_deref()) {
            (1, None) => ask("Password: ", false, false),
            (1, Some(PASSWORD)) => {
                self.stage = 2;
                ask("Verification code: ", true, false)
            }
            (1, Some(_)) => ask("Password: ", false, true),
            (2, None) => ask("Verification code: ", true, false),
            (2, Some(CODE)) => {
                println!("{user}: signed in");
                Auth::Accept
            }
            (2, Some(_)) => ask("Verification code: ", true, true),
            _ => Auth::reject(),
        })
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: ChannelOpenHandle, _: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        self.channels.insert(channel.id(), channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(&mut self, channel: ChannelId, _: &str, _: u32, _: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.shells.push(channel);
        session.channel_success(channel)?;
        session.data(channel, "Signed in to the Shellwick dev server. What you type is echoed.\r\n$ ")
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if !self.shells.contains(&channel) {
            return Ok(());
        }
        let echoed = String::from_utf8_lossy(data).replace('\r', "\r\n$ ");
        session.data(channel, echoed)
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&channel)) {
            ("sftp", Some(ch)) => {
                session.channel_success(channel)?;
                let files = dir_sftp::DirSftp::new(self.files.clone(), HOME, self.modes.clone());
                russh_sftp::server::run(ch.into_stream(), files).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("SHELLWICK_OTP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(47222);
    // A fixed, public seed: this key only identifies a throwaway local server.
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[42u8; 32])), "shellwick-otp-dev").unwrap();
    println!("host key {}", key.public_key().fingerprint(Default::default()));
    let config = Arc::new(server::Config {
        keys: vec![key],
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey, MethodKind::KeyboardInteractive][..]),
        auth_rejection_time: Duration::from_millis(300),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    let files = std::env::var_os("SHELLWICK_OTP_FILES").map(PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("shellwick-otp-files"));
    let _ = std::fs::create_dir_all(files.join("home/shellwick/logs"));
    println!("files panel serves {}", files.display());
    let modes = dir_sftp::Modes::default();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("port free");
    println!("listening on 127.0.0.1:{port}; password {PASSWORD}, code {CODE}; Ctrl+C to stop");
    while let Ok((socket, _)) = listener.accept().await {
        let config = config.clone();
        let (files, modes) = (files.clone(), modes.clone());
        tokio::spawn(async move {
            let srv = Srv { files, modes, ..Default::default() };
            if let Ok(running) = server::run_stream(config, socket, srv).await {
                let _ = running.await;
            }
        });
    }
}
