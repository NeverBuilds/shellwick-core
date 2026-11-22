//! Authentication through an SSH agent: the agent signs, the private key
//! never enters Shellwick (and nothing is stored in the keyring for such hosts).
//!
//! Agent discovery, in order (the first that answers is used):
//!   1. the path set in Shellwick's settings ([`set_agent_path`])
//!   2. `IdentityAgent` in ~/.ssh/config for this server (`none` = no agent)
//!   3. `SSH_AUTH_SOCK` when set (a Unix socket; on Windows a named-pipe path,
//!      which Windows OpenSSH also honors)
//!   4. Windows: the OpenSSH agent service's pipe (1Password and Bitwarden use it too)
//!   5. Windows: Pageant
//!   6. macOS / Linux: where 1Password and Bitwarden put their agents
//!
//! Security keys (YubiKey, `sk-` keys) work through any of these: the agent
//! talks to the hardware and signs; Shellwick never reads them directly.
//!
//! Agent forwarding (`ssh -A`) is deliberately not offered.

use crate::{Error, TofuHandler};
use russh::client::{AuthResult, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::PublicKey;
use std::path::Path;
use std::sync::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};

/// The agent path from Shellwick's settings (tried first); `None` = find one.
static AGENT_PATH: RwLock<Option<String>> = RwLock::new(None);

/// Sets the agent path from settings (`None` or blank = automatic).
pub fn set_agent_path(path: Option<String>) {
    *AGENT_PATH.write().unwrap() = path.filter(|p| !p.trim().is_empty());
}

/// One place an agent may be listening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    /// A Unix socket, or on Windows a named pipe.
    Path { name: &'static str, path: String },
    #[cfg(windows)]
    Pageant,
}

/// Where password managers put their agents on macOS / Linux (tried when the file exists).
#[cfg(unix)]
const KNOWN_SOCKETS: &[(&str, &str)] = &[
    ("1Password", ".1password/agent.sock"),
    ("1Password", "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
    ("Bitwarden", ".bitwarden-ssh-agent.sock"),
];

/// Expands an agent path the way ssh does for IdentityAgent: `~`, `%d` (home),
/// `%u` (local user), `${VAR}`, and the word `SSH_AUTH_SOCK`.
pub(crate) fn expand_agent_path(raw: &str, home: Option<&Path>, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let raw = raw.trim();
    if raw == "SSH_AUTH_SOCK" || raw == "$SSH_AUTH_SOCK" {
        return env("SSH_AUTH_SOCK").filter(|s| !s.is_empty());
    }
    let home_str = home.map(|h| h.to_string_lossy().into_owned());
    let mut out = match (raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")), &home_str) {
        (Some(rest), Some(h)) => Path::new(h).join(rest).to_string_lossy().into_owned(),
        _ => raw.to_string(),
    };
    if let Some(h) = &home_str {
        out = out.replace("%d", h);
    }
    if let Some(u) = env("USER").or_else(|| env("USERNAME")) {
        out = out.replace("%u", &u);
    }
    while let Some(start) = out.find("${") {
        let Some(len) = out[start..].find('}') else { break };
        let name = out[start + 2..start + len].to_string();
        out.replace_range(start..start + len + 1, &env(&name).unwrap_or_default());
    }
    Some(out)
}

/// The places to try for one server, in order (see the module docs).
/// `Err` when its ssh config says `IdentityAgent none`.
pub(crate) fn places(
    custom: Option<&str>,
    identity_agent: Option<&str>,
    home: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
    exists: &dyn Fn(&Path) -> bool,
) -> Result<Vec<Place>, Error> {
    let mut out: Vec<Place> = Vec::new();
    let mut push = |name: &'static str, path: Option<String>| {
        if let Some(path) = path.filter(|p| !p.is_empty()) {
            if !out.iter().any(|p| matches!(p, Place::Path { path: q, .. } if q == &path)) {
                out.push(Place::Path { name, path });
            }
        }
    };
    if let Some(c) = custom {
        push("the agent set in Settings", expand_agent_path(c, home, env));
    }
    if let Some(ia) = identity_agent {
        if ia.trim().eq_ignore_ascii_case("none") {
            return Err(Error::Agent("Your ~/.ssh/config turns the SSH agent off for this server (IdentityAgent none).".into()));
        }
        push("IdentityAgent in ~/.ssh/config", expand_agent_path(ia, home, env));
    }
    push("SSH_AUTH_SOCK", env("SSH_AUTH_SOCK"));
    #[cfg(windows)]
    {
        let _ = exists;
        push("the Windows OpenSSH agent", Some(OPENSSH_AGENT_PIPE.to_string()));
        out.push(Place::Pageant);
    }
    #[cfg(unix)]
    if let Some(h) = home {
        for &(name, rel) in KNOWN_SOCKETS {
            let path: std::path::PathBuf = h.join(rel);
            if exists(&path) {
                push(name, Some(path.to_string_lossy().into_owned()));
            }
        }
    }
    Ok(out)
}

/// At most this many agent keys are offered. OpenSSH servers allow six
/// attempts by default (MaxAuthTries); stay under it so a full agent does not
/// lock the user out.
pub const MAX_AGENT_KEYS: usize = 5;

#[cfg(windows)]
pub const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Which agent answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSource {
    AuthSock,
    #[cfg(windows)]
    OpenSsh,
    #[cfg(windows)]
    Pageant,
}

pub(crate) trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

/// An agent client over whichever transport was found.
pub(crate) type Agent = AgentClient<Box<dyn Duplex>>;

/// Opens a named pipe, waiting briefly while the server is busy.
#[cfg(windows)]
async fn open_pipe(path: &str) -> std::io::Result<Box<dyn Duplex>> {
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..40 {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
            Ok(client) => return Ok(Box::new(client)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "agent pipe stayed busy"))
}

async fn open_auth_sock(path: &str) -> std::io::Result<Box<dyn Duplex>> {
    #[cfg(unix)]
    {
        Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
    }
    #[cfg(windows)]
    {
        open_pipe(path).await
    }
}

/// How long an opened agent may take to list its keys.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

enum Probe {
    Ready(Agent, Vec<AgentIdentity>),
    /// Nothing there after all (some transports, like Pageant's window
    /// messages, "open" even when nothing is running).
    Gone,
    /// Something is listening but didn't answer, e.g. Pageant stuck behind a dialog.
    Silent,
}

/// Asks a freshly opened agent for its keys; this is also the liveness check.
async fn probe(stream: Box<dyn Duplex>) -> Probe {
    let mut agent = AgentClient::connect(stream);
    match tokio::time::timeout(PROBE_TIMEOUT, agent.request_identities()).await {
        Ok(Ok(ids)) => Probe::Ready(agent, ids),
        Ok(Err(_)) => Probe::Gone,
        Err(_) => Probe::Silent,
    }
}

/// Finds a running agent for a server known by `names` (its address and
/// Shellwick name, for IdentityAgent) and returns it with the keys it holds.
pub(crate) async fn connect(names: &[&str]) -> Result<(Agent, Vec<AgentIdentity>, AgentSource), Error> {
    let home = crate::home_dir();
    let identity_agent = home.as_deref().and_then(|h| crate::import::read_identity_agent(h, names));
    let custom = AGENT_PATH.read().unwrap().clone();
    let env = |k: &str| std::env::var(k).ok();
    let list = places(custom.as_deref(), identity_agent.as_deref(), home.as_deref(), &env, &|p| p.exists())?;

    let mut tried: Vec<&str> = Vec::new();
    // The first agent that was there but never answered, reported if none works.
    let mut silent: Option<&str> = None;
    for place in list {
        let (name, source, p) = match place {
            Place::Path { name, path } => {
                let p = match open_auth_sock(&path).await {
                    Ok(s) => probe(s).await,
                    Err(_) => Probe::Gone,
                };
                (name, AgentSource::AuthSock, p)
            }
            #[cfg(windows)]
            Place::Pageant => {
                let p = match pageant::PageantStream::new().await {
                    Ok(s) => probe(Box::new(s)).await,
                    Err(_) => Probe::Gone,
                };
                ("Pageant", AgentSource::Pageant, p)
            }
        };
        match p {
            Probe::Ready(agent, ids) => return Ok((agent, ids, source)),
            Probe::Gone => tried.push(name),
            Probe::Silent => {
                tried.push(name);
                silent.get_or_insert(name);
            }
        }
    }
    Err(Error::Agent(match silent {
        Some(name) => silent_agent_message(name),
        None => no_agent_message(&tried),
    }))
}

fn no_agent_message(tried: &[&str]) -> String {
    if tried.is_empty() {
        "No SSH agent is running. Start one and add your key.".into()
    } else {
        format!("No SSH agent is running (tried {}). Start one and add your key.", tried.join(", "))
    }
}

fn silent_agent_message(name: &str) -> String {
    let name = match name {
        "SSH_AUTH_SOCK" => "The SSH agent at SSH_AUTH_SOCK",
        "the Windows OpenSSH agent" => "The Windows OpenSSH agent",
        "the agent set in Settings" => "The agent set in Settings",
        "IdentityAgent in ~/.ssh/config" => "The agent named by IdentityAgent in ~/.ssh/config",
        other => other,
    };
    format!("{name} is running but didn't answer within 5 seconds. Check it isn't waiting on a dialog, then reconnect.")
}

/// Plain keys to offer, in the agent's order, capped at [`MAX_AGENT_KEYS`].
/// Certificates are skipped for now.
fn usable_keys(ids: Vec<AgentIdentity>) -> Vec<PublicKey> {
    ids.into_iter()
        .filter_map(|id| match id {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            _ => None,
        })
        .take(MAX_AGENT_KEYS)
        .collect()
}

/// Offers the agent's keys one by one until the server accepts one.
pub(crate) async fn authenticate(handle: &mut Handle<TofuHandler>, user: &str, names: &[&str]) -> Result<AuthResult, Error> {
    let (mut agent, ids, _source) = connect(names).await?;
    let keys = usable_keys(ids);
    if keys.is_empty() {
        return Err(Error::Agent("The SSH agent has no keys. Add one (ssh-add, or load it in Pageant) and reconnect.".into()));
    }
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let tried = keys.len();
    for key in keys {
        match handle.authenticate_publickey_with(user.to_string(), key, hash, &mut agent).await {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
            // Key accepted, the server wants a second step (a code): pass it on.
            Ok(f @ AuthResult::Failure { partial_success: true, .. }) => return Ok(f),
            Ok(AuthResult::Failure { .. }) => continue,
            Err(e) => return Err(Error::Agent(format!("The SSH agent couldn't sign: {e}"))),
        }
    }
    Err(Error::AuthFailed(if tried == 1 {
        "the server didn't accept the SSH agent's key".into()
    } else {
        format!("the server didn't accept any of the SSH agent's {tried} keys")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    fn names(list: &[Place]) -> Vec<String> {
        list.iter()
            .map(|p| match p {
                Place::Path { name, path } => format!("{name}={path}"),
                #[cfg(windows)]
                Place::Pageant => "Pageant".to_string(),
            })
            .collect()
    }

    #[test]
    fn agent_paths_expand_like_ssh() {
        let home = PathBuf::from(if cfg!(windows) { "C:\\Users\\me" } else { "/home/me" });
        let env = env_of(&[("SSH_AUTH_SOCK", "/tmp/agent.1"), ("USER", "me"), ("XDG_RUNTIME_DIR", "/run/user/1000")]);
        assert_eq!(expand_agent_path("SSH_AUTH_SOCK", Some(&home), &env).as_deref(), Some("/tmp/agent.1"));
        assert_eq!(expand_agent_path("${XDG_RUNTIME_DIR}/ssh-agent.socket", Some(&home), &env).as_deref(), Some("/run/user/1000/ssh-agent.socket"));
        assert_eq!(expand_agent_path("~/.1password/agent.sock", Some(&home), &env), Some(home.join(".1password/agent.sock").to_string_lossy().into_owned()));
        assert_eq!(expand_agent_path(r"\\.\pipe\openssh-ssh-agent", Some(&home), &env).as_deref(), Some(r"\\.\pipe\openssh-ssh-agent"));
        assert_eq!(expand_agent_path("SSH_AUTH_SOCK", None, &env_of(&[])), None, "unset: nothing to try");
    }

    #[test]
    fn places_in_order_without_repeats() {
        let home = PathBuf::from("/home/me");
        let env = env_of(&[("SSH_AUTH_SOCK", "/tmp/agent.1")]);
        let list = places(Some("/custom.sock"), Some("SSH_AUTH_SOCK"), Some(&home), &env, &|_| false).unwrap();
        let got = names(&list);
        assert_eq!(got[0], "the agent set in Settings=/custom.sock");
        // IdentityAgent SSH_AUTH_SOCK is the same place as SSH_AUTH_SOCK: tried once, under the first name.
        assert_eq!(got[1], "IdentityAgent in ~/.ssh/config=/tmp/agent.1");
        assert!(!got.iter().any(|g| g.starts_with("SSH_AUTH_SOCK=")));
        let err = places(None, Some("none"), Some(&home), &env, &|_| true).unwrap_err();
        assert!(err.to_string().contains("IdentityAgent none"), "{err}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_tries_the_openssh_pipe_and_pageant_last() {
        let got = names(&places(None, None, None, &env_of(&[]), &|_| false).unwrap());
        assert_eq!(got, [r"the Windows OpenSSH agent=\\.\pipe\openssh-ssh-agent", "Pageant"]);
    }

    #[cfg(unix)]
    #[test]
    fn password_manager_sockets_when_present() {
        let home = PathBuf::from("/home/me");
        let got = names(&places(None, None, Some(&home), &env_of(&[]), &|p| p.ends_with(".1password/agent.sock")).unwrap());
        assert_eq!(got, ["1Password=/home/me/.1password/agent.sock"]);
    }
    use russh::keys::ssh_key::private::Ed25519Keypair;

    fn key(seed: u8) -> PublicKey {
        PublicKey::from(Ed25519Keypair::from_seed(&[seed; 32]).public)
    }

    #[test]
    fn offers_at_most_five_plain_keys_in_agent_order() {
        let ids: Vec<_> = (1..=7).map(|i| AgentIdentity::PublicKey { key: key(i), comment: format!("k{i}") }).collect();
        let picked = usable_keys(ids);
        assert_eq!(picked.len(), MAX_AGENT_KEYS);
        assert_eq!(picked[0], key(1));
        assert_eq!(picked[4], key(5));
    }

    #[test]
    fn empty_agent_gives_no_keys() {
        assert!(usable_keys(vec![]).is_empty());
    }

    #[test]
    fn message_lists_what_was_tried() {
        assert_eq!(
            no_agent_message(&["the Windows OpenSSH agent", "Pageant"]),
            "No SSH agent is running (tried the Windows OpenSSH agent, Pageant). Start one and add your key."
        );
        assert_eq!(no_agent_message(&[]), "No SSH agent is running. Start one and add your key.");
    }

    #[test]
    fn silent_agent_is_named() {
        assert_eq!(
            silent_agent_message("Pageant"),
            "Pageant is running but didn't answer within 5 seconds. Check it isn't waiting on a dialog, then reconnect."
        );
        assert!(silent_agent_message("SSH_AUTH_SOCK").starts_with("The SSH agent at SSH_AUTH_SOCK is running"));
    }
}
