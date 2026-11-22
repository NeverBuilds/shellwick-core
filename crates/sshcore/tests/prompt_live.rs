//! Sign-in questions end to end, against an SSH server running inside the
//! test (russh's server side): a PAM-style server that asks for the password
//! and then a verification code, and one that accepts any key but still wants
//! a code. Runs by default (no external server needed).

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Response, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};
use sshcore::{AuthMethod, HostConfig, ReconnectPolicy, Secrets, SessionEvent, SessionHandle, TermSize};
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const PASSWORD: &str = "correct-password";
const CODE: &str = "123456";

#[derive(Clone, Copy)]
struct Behaviour {
    /// Ask for the password in keyboard-interactive (PAM style) before the code.
    ask_password: bool,
    /// Drop the first connection right after the shell starts (to test reconnects).
    drop_first: bool,
    /// Like a stock Ubuntu sshd: passwords only (no questions), every key refused.
    password_only: bool,
}

struct Srv {
    b: Behaviour,
    connections: Arc<AtomicUsize>,
    stage: u8,
    channels: Vec<Channel<Msg>>,
}

fn ki_only() -> MethodSet {
    MethodSet::from(&[MethodKind::KeyboardInteractive][..])
}

fn ask(text: &'static str, echo: bool) -> Auth {
    Auth::Partial { name: Cow::Borrowed("Shellwick test"), instructions: Cow::Borrowed(""), prompts: Cow::Owned(vec![(Cow::Borrowed(text), echo)]) }
}

impl server::Handler for Srv {
    type Error = russh::Error;

    // Like PasswordAuthentication off with KbdInteractiveAuthentication on.
    async fn auth_password(&mut self, _: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.b.password_only {
            return Ok(if password == PASSWORD { Auth::Accept } else { Auth::Reject { proceed_with_methods: None, partial_success: false } });
        }
        Ok(Auth::Reject { proceed_with_methods: Some(ki_only()), partial_success: false })
    }

    // Any key is accepted as the first factor; a code is still required.
    async fn auth_publickey(&mut self, _: &str, _: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        if self.b.password_only {
            return Ok(Auth::Reject { proceed_with_methods: None, partial_success: false });
        }
        Ok(Auth::Reject { proceed_with_methods: Some(ki_only()), partial_success: true })
    }

    async fn auth_keyboard_interactive<'a>(&'a mut self, _user: &str, _sub: &str, response: Option<Response<'a>>) -> Result<Auth, Self::Error> {
        let answers: Vec<String> = match response {
            None => {
                self.stage = if self.b.ask_password { 1 } else { 2 };
                Vec::new()
            }
            Some(r) => r.map(|b| String::from_utf8_lossy(&b).into_owned()).collect(),
        };
        let first = answers.first().map(String::as_str);
        Ok(match (self.stage, first) {
            (1, None) => ask("Password: ", false),
            (1, Some(PASSWORD)) => {
                self.stage = 2;
                ask("Verification code: ", true)
            }
            (1, Some(_)) => ask("Password: ", false),
            (2, None) => ask("Verification code: ", true),
            (2, Some(CODE)) => Auth::Accept,
            // A wrong code: ask again (the client marks it as a retry).
            (2, Some(_)) => ask("Verification code: ", true),
            _ => Auth::reject(),
        })
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: ChannelOpenHandle, _: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        self.channels.push(channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(&mut self, channel: ChannelId, _: &str, _: u32, _: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, "welcome\r\n")?;
        if self.b.drop_first && self.connections.fetch_add(1, Ordering::SeqCst) == 0 {
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = handle.disconnect(Disconnect::ByApplication, "bye".into(), "en".into()).await;
            });
        }
        Ok(())
    }
}

async fn start_server(b: Behaviour) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)), "shellwick-test-server").unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        methods: if b.password_only {
            MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..])
        } else {
            MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey, MethodKind::KeyboardInteractive][..])
        },
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    let connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let srv = Srv { b, connections: connections.clone(), stage: 0, channels: Vec::new() };
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

fn host(port: u16, auth: AuthMethod) -> HostConfig {
    HostConfig {
        id: "target-id".into(),
        name: "otp-box".into(),
        host: "127.0.0.1".into(),
        port,
        user: "deploy".into(),
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
    }
}

fn quick_reconnect() -> ReconnectPolicy {
    ReconnectPolicy { enabled: true, initial_delay: Duration::from_millis(100), max_delay: Duration::from_millis(200), max_attempts: Some(5) }
}

fn spawn(cfg: HostConfig, secrets: Secrets) -> (SessionHandle, mpsc::Receiver<SessionEvent>) {
    let (tx, rx) = mpsc::channel(256);
    let handle = sshcore::spawn_session_with(cfg, secrets, TermSize { cols: 80, rows: 24 }, quick_reconnect(), Vec::new(), Vec::new(), tx);
    (handle, rx)
}

/// The next event that isn't terminal output.
async fn next(rx: &mut mpsc::Receiver<SessionEvent>) -> SessionEvent {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("an event within 10 s").expect("session alive") {
            SessionEvent::Data(_) => continue,
            other => return other,
        }
    }
}

fn prompt(ev: SessionEvent) -> sshcore::prompt::Challenge {
    match ev {
        SessionEvent::AuthPrompt(c) => c,
        other => panic!("expected a sign-in question, got {other:?}"),
    }
}

#[tokio::test]
async fn saved_password_answers_pam_and_the_code_is_asked() {
    let port = start_server(Behaviour { ask_password: true, drop_first: false, password_only: false }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Password), Secrets { password: Some(PASSWORD.into()), key_passphrase: None, proxy_password: None });
    let c = prompt(next(&mut rx).await);
    assert_eq!(c.questions.len(), 1, "the password question was answered from the saved password");
    assert_eq!((c.questions[0].text.as_str(), c.questions[0].echo), ("Verification code: ", true));
    assert_eq!((c.host_id.as_str(), c.host_name.as_str(), c.name.as_str(), c.retry), ("target-id", "otp-box", "Shellwick test", false));
    assert!(handle.answer_prompt(Some(vec![CODE.into()])));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}

#[tokio::test]
async fn without_a_saved_password_both_are_asked() {
    let port = start_server(Behaviour { ask_password: true, drop_first: false, password_only: false }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Password), Secrets::default());
    let c = prompt(next(&mut rx).await);
    assert_eq!((c.questions[0].text.as_str(), c.questions[0].echo), ("Password: ", false));
    handle.answer_prompt(Some(vec![PASSWORD.into()]));
    let c = prompt(next(&mut rx).await);
    assert_eq!(c.questions[0].text, "Verification code: ");
    handle.answer_prompt(Some(vec![CODE.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}

#[tokio::test]
async fn wrong_code_is_asked_again_and_cancel_ends_without_retrying() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: false }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Password), Secrets { password: Some(PASSWORD.into()), key_passphrase: None, proxy_password: None });
    let c = prompt(next(&mut rx).await);
    assert!(!c.retry);
    handle.answer_prompt(Some(vec!["000000".into()]));
    let c = prompt(next(&mut rx).await);
    assert!(c.retry, "the same question came back: the code was refused");
    handle.answer_prompt(None);
    match next(&mut rx).await {
        SessionEvent::Closed { reason } => assert_eq!(reason, "Sign-in was cancelled."),
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[tokio::test]
async fn closing_the_tab_while_a_question_waits_ends_the_session() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: false }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Password), Secrets { password: Some(PASSWORD.into()), key_passphrase: None, proxy_password: None });
    prompt(next(&mut rx).await);
    handle.close().await;
    assert!(matches!(next(&mut rx).await, SessionEvent::Closed { .. }), "no stuck task, no reconnect loop");
}

fn test_key() -> (std::path::PathBuf, String) {
    // Tests run in parallel and the clock can read the same for two of them.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let base = std::env::current_exe().unwrap().parent().unwrap().join("test-scratch");
    let dir = base.join(format!("prompt-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let k = sshcore::keygen::generate_ed25519(&dir, "id_test", "test", None).unwrap();
    (dir, k.private_path.to_string_lossy().into_owned())
}

#[tokio::test]
async fn key_then_code_and_reconnects_ask_again() {
    let port = start_server(Behaviour { ask_password: false, drop_first: true, password_only: false }).await;
    let (_dir, key) = test_key();
    let (handle, mut rx) = spawn(host(port, AuthMethod::KeyFile { path: key }), Secrets::default());
    let c = prompt(next(&mut rx).await);
    assert_eq!(c.questions[0].text, "Verification code: ");
    handle.answer_prompt(Some(vec![CODE.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    // The server drops the connection; the reconnect needs a fresh code and waits for it.
    assert!(matches!(next(&mut rx).await, SessionEvent::Reconnecting { .. }));
    let c = prompt(next(&mut rx).await);
    assert_eq!(c.questions[0].text, "Verification code: ");
    handle.answer_prompt(Some(vec![CODE.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}

#[tokio::test]
async fn key_check_counts_key_plus_code_as_accepted() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: false }).await;
    let (_dir, key) = test_key();
    // Used after "Add to server": the key was accepted, the code isn't asked.
    sshcore::check_sign_in(&host(port, AuthMethod::KeyFile { path: key }), &Secrets::default(), &[]).await.unwrap();
}

/// The next question that isn't a default key's passphrase (this computer's
/// own ~/.ssh keys may be tried by Auto; their passphrase questions are skipped).
async fn next_question(handle: &SessionHandle, rx: &mut mpsc::Receiver<SessionEvent>) -> sshcore::prompt::Challenge {
    loop {
        let c = prompt(next(rx).await);
        if c.questions[0].text.starts_with("Passphrase for ") {
            handle.answer_prompt(Some(vec![String::new()]));
            continue;
        }
        return c;
    }
}

#[tokio::test]
async fn the_password_is_asked_when_none_is_saved() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: true }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Password), Secrets::default());
    let c = prompt(next(&mut rx).await);
    assert_eq!((c.questions[0].text.as_str(), c.questions[0].echo, c.retry), ("Password", false, false));
    handle.answer_prompt(Some(vec!["wrong".into()]));
    let c = prompt(next(&mut rx).await);
    assert!(c.retry, "a wrong password is asked again");
    handle.answer_prompt(Some(vec![PASSWORD.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}

#[tokio::test]
async fn like_ssh_falls_back_to_the_password() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: true }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Auto), Secrets::default());
    // The agent and default keys (if this computer has any) are refused; then the password.
    let c = next_question(&handle, &mut rx).await;
    assert_eq!(c.questions[0].text, "Password");
    handle.answer_prompt(Some(vec![PASSWORD.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}

#[tokio::test]
async fn cancelling_the_password_ends_without_retrying() {
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: true }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Auto), Secrets::default());
    next_question(&handle, &mut rx).await;
    handle.answer_prompt(None);
    match next(&mut rx).await {
        SessionEvent::Closed { reason } => assert_eq!(reason, "Sign-in was cancelled."),
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[tokio::test]
async fn like_ssh_with_a_key_and_a_code() {
    // A server that takes any key and then wants a code: Auto's default keys
    // aren't available here, so it goes through the questions instead.
    let port = start_server(Behaviour { ask_password: false, drop_first: false, password_only: false }).await;
    let (handle, mut rx) = spawn(host(port, AuthMethod::Auto), Secrets::default());
    let c = next_question(&handle, &mut rx).await;
    assert_eq!(c.questions[0].text, "Verification code: ");
    handle.answer_prompt(Some(vec![CODE.into()]));
    assert!(matches!(next(&mut rx).await, SessionEvent::Connected { .. }));
    handle.close().await;
}
