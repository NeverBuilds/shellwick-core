//! Smoke test without any UI:
//!   SSH_PASSWORD=xxx cargo run -p sshcore --example smoke -- user@host[:port]
//!   SSH_KEY=~/.ssh/id_ed25519 cargo run -p sshcore --example smoke -- user@host
//! Type into the terminal; Ctrl-] exits. Kill the network to watch reconnects.

use sshcore::*;
use std::io::{Read, Write};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let target = std::env::args().nth(1).expect("user@host[:port]");
    let (user, hostport) = target.split_once('@').expect("user@host");
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap()),
        None => (hostport.to_string(), 22),
    };

    let auth = match std::env::var("SSH_KEY") {
        Ok(p) => AuthMethod::KeyFile { path: shellexpand(&p) },
        Err(_) => AuthMethod::Password,
    };
    let secrets = Secrets {
        password: std::env::var("SSH_PASSWORD").ok(),
        key_passphrase: std::env::var("SSH_PASSPHRASE").ok(),
        proxy_password: None,
    };
    let cfg = HostConfig {
        id: "smoke".into(),
        name: "smoke".into(),
        host,
        port,
        user: user.into(),
        auth,
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
    };

    let (tx, mut rx) = mpsc::channel(256);
    let handle = spawn_session(cfg, secrets, TermSize { cols: 120, rows: 36 }, ReconnectPolicy::default(), tx);

    // stdin -> session (raw bytes, line-buffered by your terminal; good enough for a smoke test)
    let h2 = handle.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut buf = [0u8; 1024];
        let mut stdin = std::io::stdin();
        loop {
            let n = stdin.read(&mut buf).unwrap_or(0);
            if n == 0 || buf[..n].contains(&0x1d) {
                rt.block_on(h2.close());
                return;
            }
            rt.block_on(h2.write(Bytes::copy_from_slice(&buf[..n]))).ok();
        }
    });

    let mut out = std::io::stdout();
    while let Some(ev) = rx.recv().await {
        match ev {
            SessionEvent::Connected { fingerprint } => eprintln!("\n[connected] host key {fingerprint}"),
            SessionEvent::Data(b) => { out.write_all(&b).ok(); out.flush().ok(); }
            SessionEvent::Reconnecting { attempt, delay, reason } => eprintln!("\n[reconnecting #{attempt} in {delay:?}: {reason}]"),
            SessionEvent::HostKeyMismatch { expected, actual, .. } => { eprintln!("\n[HOST KEY CHANGED] {expected} -> {actual}"); break; }
            SessionEvent::Closed { reason } => { eprintln!("\n[closed: {reason}]"); break; }
            SessionEvent::Forward { id, status } => eprintln!("\n[forward {id}: {status:?}]"),
            SessionEvent::JumpConnected { fingerprint, .. } => eprintln!("\n[jump host key {fingerprint}]"),
            SessionEvent::HostKeyUnknown { actual, .. } => { eprintln!("\n[HOST KEY NOT CONFIRMED] {actual}"); break; }
            // Sign-in questions (2FA codes…): answers come from SSH_ANSWERS=a,b,… (stdin is the terminal here).
            SessionEvent::AuthPrompt(c) => {
                let questions: Vec<&str> = c.questions.iter().map(|q| q.text.as_str()).collect();
                eprintln!("\n[{} asks: {}]", c.host_name, questions.join(" | "));
                let answers = std::env::var("SSH_ANSWERS").ok().map(|a| a.split(',').map(String::from).collect::<Vec<_>>());
                if answers.is_none() {
                    eprintln!("[set SSH_ANSWERS=answer1,answer2 to answer; cancelling]");
                }
                handle.answer_prompt(answers);
            }
        }
    }
}

fn shellexpand(p: &str) -> String {
    match (p.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => p.to_string(),
    }
}
