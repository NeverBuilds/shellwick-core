//! Import hosts from other clients: OpenSSH `~/.ssh/config` and PuTTY saved
//! sessions.
//!
//! Only connection parameters are imported — never passwords (PuTTY does not
//! store them and ssh config cannot hold them). PuTTY `.ppk` keys need no
//! conversion: russh reads them directly.
//!
//! Parsing is pure (text / plain data in, candidates out); reading files and
//! the registry is kept in thin functions at the bottom so everything else is
//! unit-testable.

use crate::HostConfig;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    SshConfig,
    Putty,
    #[serde(rename = "securecrt")]
    SecureCrt,
    #[serde(rename = "mobaxterm")]
    MobaXterm,
}

/// A host found in another client's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportCandidate {
    pub source: ImportSource,
    /// ssh config alias or PuTTY session name.
    pub name: String,
    pub host: String,
    pub port: u16,
    /// `None` when the source does not say (PuTTY then asks "login as:").
    pub user: Option<String>,
    /// Private key path as written in the source (may start with `~`).
    pub key_file: Option<String>,
    /// Settings that will not carry over, in plain words.
    pub notes: Vec<String>,
    /// The (top) folder it was in, as a Shellwick folder name.
    pub folder: Option<String>,
    /// Host key fingerprint from ~/.ssh/known_hosts (pinned when imported).
    pub fingerprint: Option<String>,
    /// ssh config `ForwardAgent yes`.
    #[serde(default)]
    pub forward_agent: bool,
    /// ssh config `ProxyJump`: the jump host nearest the server, as written
    /// (an alias or user@host:port). [`plan_import`] matches it to a server.
    #[serde(default)]
    pub jump: Option<String>,
}

/// Something the scan could not use at all (not tied to one candidate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportSkip {
    pub source: ImportSource,
    pub name: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// OpenSSH config
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum BlockKind {
    Host(Vec<String>),
    Match,
}

#[derive(Debug)]
struct Block {
    kind: BlockKind,
    settings: Vec<(String, String)>,
}

/// Splits a config line into a lower-cased keyword and its argument.
/// Accepts `Key value`, `Key=value` and `Key = value`; strips one pair of
/// surrounding double quotes from the argument.
fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let key = line[..end].to_ascii_lowercase();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    let value = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(rest);
    Some((key, value.to_string()))
}

/// Splits a `Host` argument into patterns (space separated, quotes allowed).
fn split_patterns(arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in arg.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `*` and `?` glob, case-insensitive (host names are).
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b) && go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

/// A `Host` line applies when some positive pattern matches and no negated
/// (`!pattern`) one does — OpenSSH semantics.
fn host_applies(patterns: &[String], alias: &str) -> bool {
    let mut positive = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob_match(neg, alias) {
                return false;
            }
        } else if glob_match(p, alias) {
            positive = true;
        }
    }
    positive
}

fn is_concrete(pattern: &str) -> bool {
    !pattern.starts_with('!') && !pattern.contains(['*', '?'])
}

/// The `IdentityAgent` ssh would use for a server known by any of `names`
/// (its address, its Shellwick name): the first value from a global line or a
/// matching `Host` block. `Match` blocks are skipped (not evaluated).
pub fn identity_agent(text: &str, names: &[&str]) -> Option<String> {
    let mut applies = true; // lines before the first Host apply to every server
    for line in text.lines() {
        let Some((key, value)) = split_line(line) else { continue };
        match key.as_str() {
            "host" => {
                let patterns = split_patterns(&value);
                applies = names.iter().any(|n| host_applies(&patterns, n));
            }
            "match" => applies = false,
            "identityagent" if applies && !value.is_empty() => return Some(value),
            _ => {}
        }
    }
    None
}

/// [`identity_agent`] for the user's own ~/.ssh/config (Includes followed).
pub fn read_identity_agent(home: &Path, names: &[&str]) -> Option<String> {
    let ssh_dir = home.join(".ssh");
    let text = std::fs::read_to_string(ssh_dir.join("config")).ok()?;
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let list = |dir: &Path| {
        std::fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_file()).collect())
            .unwrap_or_default()
    };
    identity_agent(&inline_includes(&text, &ssh_dir, home, &read, &list), names)
}

/// Parses ssh config text (with `Include`s already inlined, see
/// [`inline_includes`]) into one candidate per concrete `Host` alias.
pub fn parse_ssh_config(text: &str) -> Vec<ImportCandidate> {
    // Lines before the first Host/Match apply to every host.
    let mut blocks = vec![Block { kind: BlockKind::Host(vec!["*".into()]), settings: vec![] }];
    let mut aliases: Vec<String> = Vec::new();
    for (key, value) in text.lines().filter_map(split_line) {
        match key.as_str() {
            "host" => {
                let patterns = split_patterns(&value);
                for p in patterns.iter().filter(|p| is_concrete(p)) {
                    if !aliases.contains(p) {
                        aliases.push(p.clone());
                    }
                }
                blocks.push(Block { kind: BlockKind::Host(patterns), settings: vec![] });
            }
            "match" => blocks.push(Block { kind: BlockKind::Match, settings: vec![] }),
            _ => blocks.last_mut().expect("global block").settings.push((key, value)),
        }
    }

    aliases
        .into_iter()
        .map(|alias| {
            // First obtained value wins, in file order (OpenSSH semantics).
            let mut values: HashMap<&str, &str> = HashMap::new();
            let mut notes = Vec::new();
            for block in &blocks {
                let BlockKind::Host(patterns) = &block.kind else { continue };
                if !host_applies(patterns, &alias) {
                    continue;
                }
                for (key, value) in &block.settings {
                    let note = match key.as_str() {
                        "proxycommand" => Some("ProxyCommand isn't imported"),
                        "localforward" | "remoteforward" | "dynamicforward" => Some("Port forwarding isn't imported yet"),
                        _ => None,
                    };
                    if let Some(n) = note {
                        if !notes.iter().any(|x| x == n) {
                            notes.push(n.to_string());
                        }
                    }
                    values.entry(key.as_str()).or_insert(value.as_str());
                }
            }

            let host = values.get("hostname").map(|h| h.replace("%h", &alias)).unwrap_or_else(|| alias.clone());
            let port = match values.get("port") {
                None => 22,
                Some(p) => p.parse().unwrap_or_else(|_| {
                    notes.push(format!("Port “{p}” isn't a number; using 22"));
                    22
                }),
            };
            let user = values.get("user").map(|u| u.to_string());
            // "a,b": b is the hop next to the server; b's own setting decides how b is reached.
            let jump = values.get("proxyjump").map(|j| j.trim()).filter(|j| !j.is_empty() && !j.eq_ignore_ascii_case("none")).map(|j| {
                let hops: Vec<&str> = j.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
                if hops.len() > 1 {
                    notes.push(format!("ProxyJump lists several hosts; Shellwick uses {}, which is reached its own way", hops[hops.len() - 1]));
                }
                hops.last().copied().unwrap_or(j).to_string()
            });
            let key_file = values.get("identityfile").map(|k| {
                let k = k.replace("%d", "~");
                if k.contains('%') {
                    notes.push("Key path uses % tokens; check it after importing".into());
                }
                k
            });
            // "yes" (or a socket path, which Shellwick treats as yes: it finds the agent its own way).
            let forward_agent = values.get("forwardagent").is_some_and(|v| !matches!(v.to_ascii_lowercase().as_str(), "no" | "false"));
            ImportCandidate { source: ImportSource::SshConfig, name: alias, host, port, user, key_file, notes, folder: None, fingerprint: None, jump, forward_agent }
        })
        .collect()
}

/// Maximum `Include` nesting, like OpenSSH's own limit.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Replaces `Include` lines with the contents of the files they name.
///
/// Relative paths are relative to `ssh_dir` (`~/.ssh`), `~` is the home
/// directory, and `*` / `?` are allowed in the file-name part. Unreadable or
/// missing files are skipped (OpenSSH ignores them too). `read` and `list`
/// abstract the filesystem for tests.
pub fn inline_includes(
    text: &str,
    ssh_dir: &Path,
    home: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
    list: &dyn Fn(&Path) -> Vec<PathBuf>,
) -> String {
    fn go(
        text: &str,
        depth: usize,
        ssh_dir: &Path,
        home: &Path,
        read: &dyn Fn(&Path) -> Option<String>,
        list: &dyn Fn(&Path) -> Vec<PathBuf>,
    ) -> String {
        let mut out = String::new();
        for line in text.lines() {
            match split_line(line) {
                Some((key, value)) if key == "include" && depth < MAX_INCLUDE_DEPTH => {
                    for pattern in split_patterns(&value) {
                        let path = match pattern.strip_prefix("~/") {
                            Some(rest) => home.join(rest),
                            None if Path::new(&pattern).is_absolute() => PathBuf::from(&pattern),
                            None => ssh_dir.join(&pattern),
                        };
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        let files: Vec<PathBuf> = if name.contains(['*', '?']) {
                            let mut matched: Vec<PathBuf> = path
                                .parent()
                                .map(list)
                                .unwrap_or_default()
                                .into_iter()
                                .filter(|f| f.file_name().and_then(|n| n.to_str()).is_some_and(|n| glob_match(name, n)))
                                .collect();
                            matched.sort();
                            matched
                        } else {
                            vec![path]
                        };
                        for f in files {
                            if let Some(inner) = read(&f) {
                                out.push_str(&go(&inner, depth + 1, ssh_dir, home, read, list));
                                out.push('\n');
                            }
                        }
                    }
                }
                _ => {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        out
    }
    go(text, 0, ssh_dir, home, read, list)
}

// ---------------------------------------------------------------------------
// PuTTY
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PuttyValue {
    Str(String),
    Dword(u32),
}

/// One saved session as stored under
/// `HKCU\Software\SimonTatham\PuTTY\Sessions\<name>`.
#[derive(Debug, Clone, Default)]
pub struct PuttySession {
    /// Registry key name (PuTTY escapes special characters as `%XX`).
    pub key_name: String,
    pub values: HashMap<String, PuttyValue>,
}

impl PuttySession {
    fn str(&self, k: &str) -> Option<&str> {
        match self.values.get(k) {
            Some(PuttyValue::Str(s)) if !s.trim().is_empty() => Some(s.trim()),
            _ => None,
        }
    }
    fn dword(&self, k: &str) -> Option<u32> {
        match self.values.get(k) {
            Some(PuttyValue::Dword(d)) => Some(*d),
            _ => None,
        }
    }
}

/// Decodes PuTTY's `%XX` escaping of session names.
fn decode_session_name(raw: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Turns PuTTY sessions into candidates; sessions that cannot become an SSH
/// host (telnet, serial, no host name) are reported as skipped.
pub fn putty_candidates(sessions: &[PuttySession]) -> (Vec<ImportCandidate>, Vec<ImportSkip>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for s in sessions {
        let name = decode_session_name(&s.key_name);
        if name == "Default Settings" {
            continue;
        }
        let skip = |reason: String| ImportSkip { source: ImportSource::Putty, name: name.clone(), reason };
        let protocol = s.str("Protocol").unwrap_or("ssh");
        if !protocol.eq_ignore_ascii_case("ssh") {
            skipped.push(skip(format!("{protocol} sessions aren't supported, only SSH")));
            continue;
        }
        let Some(raw_host) = s.str("HostName") else {
            skipped.push(skip("No host name saved".into()));
            continue;
        };
        // PuTTY accepts "user@host" in the host field.
        let (user_in_host, host) = match raw_host.rsplit_once('@') {
            Some((u, h)) if !u.is_empty() && !h.is_empty() => (Some(u.to_string()), h.to_string()),
            _ => (None, raw_host.to_string()),
        };
        let port = s.dword("PortNumber").and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0).unwrap_or(22);
        let user = s.str("UserName").map(str::to_string).or(user_in_host);

        let mut notes = Vec::new();
        if s.dword("ProxyMethod").unwrap_or(0) != 0 {
            notes.push("Proxy settings aren't imported".to_string());
        }
        if s.str("PortForwardings").is_some() {
            notes.push("Port forwarding isn't imported yet".to_string());
        }
        found.push(ImportCandidate {
            source: ImportSource::Putty,
            name,
            host,
            port,
            user,
            key_file: s.str("PublicKeyFile").map(str::to_string),
            notes,
            folder: None,
            fingerprint: None,
            jump: None,
            forward_agent: false,
        });
    }
    (found, skipped)
}

// ---------------------------------------------------------------------------
// De-duplication against hosts that already exist
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Duplicate {
    /// Same address, port and user as a saved host.
    Existing { id: String, name: String },
    /// Same as an earlier candidate in this scan (e.g. in both PuTTY and ssh config).
    Earlier { index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JumpPlan {
    /// A saved server.
    Existing { id: String, name: String },
    /// Another server in this scan (import it too, before this one).
    Planned { index: usize },
    /// Nothing saved or found matches: imported without a jump host.
    Unknown { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedImport {
    pub candidate: ImportCandidate,
    /// Name to save under: unique among saved hosts and earlier candidates.
    pub name: String,
    pub duplicate: Option<Duplicate>,
    /// Where the candidate's ProxyJump points, when it has one.
    pub jump: Option<JumpPlan>,
}

/// "user@host:port" / "host" / "[v6]:port" → (user, host, port).
fn jump_target(s: &str) -> (Option<&str>, &str, Option<u16>) {
    let (user, rest) = match s.rsplit_once('@') {
        Some((u, r)) => (Some(u), r),
        None => (None, s),
    };
    if let Some(v6) = rest.strip_prefix('[') {
        if let Some((h, p)) = v6.split_once("]:") {
            return (user, h, p.parse().ok());
        }
        return (user, v6.trim_end_matches(']'), None);
    }
    match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (user, h, p.parse().ok()),
        _ => (user, rest, None),
    }
}

/// Matches a ProxyJump to a server: by name (a saved server's name or another
/// alias in the scan), then by address. A scanned server that is already saved
/// points at the saved one.
fn plan_jump(jump: &str, me: usize, planned: &[PlannedImport], existing: &[HostConfig]) -> JumpPlan {
    let resolve_planned = |i: usize| match &planned[i].duplicate {
        Some(Duplicate::Existing { id, name }) => JumpPlan::Existing { id: id.clone(), name: name.clone() },
        _ => JumpPlan::Planned { index: i },
    };
    if let Some(i) = planned.iter().enumerate().position(|(i, p)| i != me && p.candidate.name.eq_ignore_ascii_case(jump)) {
        return resolve_planned(i);
    }
    if let Some(h) = existing.iter().find(|h| h.name.eq_ignore_ascii_case(jump)) {
        return JumpPlan::Existing { id: h.id.clone(), name: h.name.clone() };
    }
    let (user, host, port) = jump_target(jump);
    let fits = |h: &str, p: u16, u: Option<&str>| h.eq_ignore_ascii_case(host) && port.is_none_or(|x| x == p) && match (user, u) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    if let Some(h) = existing.iter().find(|h| fits(&h.host, h.port, Some(&h.user))) {
        return JumpPlan::Existing { id: h.id.clone(), name: h.name.clone() };
    }
    if let Some(i) = planned.iter().enumerate().position(|(i, p)| i != me && fits(&p.candidate.host, p.candidate.port, p.candidate.user.as_deref())) {
        return resolve_planned(i);
    }
    JumpPlan::Unknown { name: jump.to_string() }
}

fn same_target(host: &str, port: u16, user: Option<&str>, other_host: &str, other_port: u16, other_user: Option<&str>) -> bool {
    host.eq_ignore_ascii_case(other_host)
        && port == other_port
        // An unknown user matches any user: it would most likely be the same login.
        && match (user, other_user) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
}

/// Marks duplicates and picks unique names (`name (2)`, `name (3)`…).
pub fn plan_import(candidates: Vec<ImportCandidate>, existing: &[HostConfig]) -> Vec<PlannedImport> {
    let mut planned: Vec<PlannedImport> = Vec::with_capacity(candidates.len());
    for c in candidates {
        let duplicate = existing
            .iter()
            .find(|h| same_target(&c.host, c.port, c.user.as_deref(), &h.host, h.port, Some(&h.user)))
            .map(|h| Duplicate::Existing { id: h.id.clone(), name: h.name.clone() })
            .or_else(|| {
                planned
                    .iter()
                    .position(|p| {
                        let o = &p.candidate;
                        same_target(&c.host, c.port, c.user.as_deref(), &o.host, o.port, o.user.as_deref())
                    })
                    .map(|index| Duplicate::Earlier { index })
            });
        let taken = |n: &str| {
            existing.iter().any(|h| h.name.eq_ignore_ascii_case(n)) || planned.iter().any(|p| p.name.eq_ignore_ascii_case(n))
        };
        let name = if taken(&c.name) {
            (2..).map(|i| format!("{} ({i})", c.name)).find(|n| !taken(n)).expect("a free name")
        } else {
            c.name.clone()
        };
        planned.push(PlannedImport { candidate: c, name, duplicate, jump: None });
    }
    // Jump hosts once every candidate is known (one may point at a later one).
    for i in 0..planned.len() {
        if let Some(j) = planned[i].candidate.jump.clone() {
            planned[i].jump = Some(plan_jump(&j, i, &planned, existing));
        }
    }
    planned
}

// ---------------------------------------------------------------------------
// Reading the real sources
// ---------------------------------------------------------------------------

/// Reads `<home>/.ssh/config` (following `Include`s). `Ok(None)` when the
/// file does not exist.
pub fn read_ssh_config(home: &Path) -> std::io::Result<Option<Vec<ImportCandidate>>> {
    let ssh_dir = home.join(".ssh");
    let text = match std::fs::read_to_string(ssh_dir.join("config")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let list = |dir: &Path| {
        std::fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_file()).collect())
            .unwrap_or_default()
    };
    Ok(Some(parse_ssh_config(&inline_includes(&text, &ssh_dir, home, &read, &list))))
}

/// Reads PuTTY's saved sessions from the current user's registry. Empty when
/// PuTTY was never used, and always empty off Windows.
#[cfg(windows)]
pub fn read_putty_sessions() -> std::io::Result<Vec<PuttySession>> {
    use winreg::enums::{RegType, HKEY_CURRENT_USER};
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    let root = match RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\SimonTatham\PuTTY\Sessions") {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut sessions = Vec::new();
    for key_name in root.enum_keys().filter_map(Result::ok) {
        let Ok(key) = root.open_subkey(&key_name) else { continue };
        let mut values = HashMap::new();
        for (name, value) in key.enum_values().filter_map(Result::ok) {
            let parsed = match value.vtype {
                RegType::REG_SZ | RegType::REG_EXPAND_SZ => String::from_reg_value(&value).ok().map(PuttyValue::Str),
                RegType::REG_DWORD => u32::from_reg_value(&value).ok().map(PuttyValue::Dword),
                _ => None,
            };
            if let Some(v) = parsed {
                values.insert(name, v);
            }
        }
        sessions.push(PuttySession { key_name, values });
    }
    Ok(sessions)
}

#[cfg(not(windows))]
pub fn read_putty_sessions() -> std::io::Result<Vec<PuttySession>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_agent_like_ssh() {
        let cfg = "IdentityAgent ~/.global.sock\nHost work-*\n  IdentityAgent \"~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock\"\n";
        // The global line comes first, so it wins (first value wins).
        assert_eq!(identity_agent(cfg, &["work-db"]).as_deref(), Some("~/.global.sock"));
        let cfg = "Host *.corp.example\n  IdentityAgent ~/.1password/agent.sock\nHost !old.corp.example *\n  IdentityAgent SSH_AUTH_SOCK\nMatch exec true\n  IdentityAgent ~/never\n";
        assert_eq!(identity_agent(cfg, &["api.corp.example"]).as_deref(), Some("~/.1password/agent.sock"));
        assert_eq!(identity_agent(cfg, &["10.0.0.5", "lab box"]).as_deref(), Some("SSH_AUTH_SOCK"));
        assert_eq!(identity_agent("Host other\n IdentityAgent x\n", &["mine"]), None);
        assert_eq!(identity_agent("Host mine\n IdentityAgent=none\n", &["MINE"]).as_deref(), Some("none"), "host names match without case");
    }
    use crate::AuthMethod;

    fn by_name<'a>(c: &'a [ImportCandidate], name: &str) -> &'a ImportCandidate {
        c.iter().find(|x| x.name == name).unwrap_or_else(|| panic!("no candidate {name}: {c:?}"))
    }

    #[test]
    fn line_forms_and_quotes() {
        assert_eq!(split_line("  HostName example.com"), Some(("hostname".into(), "example.com".into())));
        assert_eq!(split_line("Port=2222"), Some(("port".into(), "2222".into())));
        assert_eq!(split_line("User = deploy"), Some(("user".into(), "deploy".into())));
        assert_eq!(split_line(r#"IdentityFile "C:\Users\Me\My Keys\id""#), Some(("identityfile".into(), r"C:\Users\Me\My Keys\id".into())));
        assert_eq!(split_line("# comment"), None);
        assert_eq!(split_line("   "), None);
    }

    #[test]
    fn glob_and_negation() {
        assert!(glob_match("*.prod", "api.PROD"));
        assert!(glob_match("web?", "web1"));
        assert!(!glob_match("web?", "web10"));
        assert!(host_applies(&["*".into(), "!bastion".into()], "api"));
        assert!(!host_applies(&["*".into(), "!bastion".into()], "bastion"));
        assert!(!host_applies(&["!bastion".into()], "api"), "negation alone matches nothing");
    }

    #[test]
    fn concrete_hosts_with_first_value_winning_and_wildcard_defaults() {
        let cfg = r#"
            # global default before any Host
            ServerAliveInterval 30

            Host api api-alias
              HostName 10.0.4.12
              User deploy
              IdentityFile ~/.ssh/id_api

            Host db
              HostName db.internal
              Port 2222

            Host *.prod web?
              User ignored-for-concrete-hosts

            Host *
              User root
              IdentityFile ~/.ssh/id_default
              Port 22
        "#;
        let c = parse_ssh_config(cfg);
        let names: Vec<_> = c.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["api", "api-alias", "db"], "wildcard-only Host lines produce no candidates");

        let api = by_name(&c, "api");
        assert_eq!((api.host.as_str(), api.port, api.user.as_deref()), ("10.0.4.12", 22, Some("deploy")));
        assert_eq!(api.key_file.as_deref(), Some("~/.ssh/id_api"), "specific block comes first, so it wins");
        assert_eq!(by_name(&c, "api-alias").host, "10.0.4.12");

        let db = by_name(&c, "db");
        assert_eq!((db.host.as_str(), db.port), ("db.internal", 2222));
        assert_eq!(db.user.as_deref(), Some("root"), "falls back to Host * default");
        assert_eq!(db.key_file.as_deref(), Some("~/.ssh/id_default"));
    }

    #[test]
    fn alias_without_hostname_connects_to_itself() {
        let c = parse_ssh_config("Host example.org\n  User me\n");
        assert_eq!(c[0].host, "example.org");
        assert_eq!(c[0].port, 22);
    }

    #[test]
    fn match_blocks_are_ignored_and_unsupported_options_are_noted() {
        let cfg = "Host jumpy\n  HostName 10.1.1.1\n  ProxyJump bastion\n  LocalForward 8080 localhost:80\n  Port nope\n\
                   Match host jumpy\n  User from-match\n";
        let c = parse_ssh_config(cfg);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].user, None, "Match blocks are not evaluated");
        assert_eq!(c[0].port, 22);
        assert_eq!(c[0].jump.as_deref(), Some("bastion"));
        let fwd = parse_ssh_config("Host a\n  ForwardAgent yes\nHost b\n  ForwardAgent no\nHost c\n");
        assert_eq!(fwd.iter().map(|c| c.forward_agent).collect::<Vec<_>>(), [true, false, false]);
        assert!(c[0].notes.iter().any(|n| n.contains("Port forwarding")));
        assert!(c[0].notes.iter().any(|n| n.contains("isn't a number")));
    }

    #[test]
    fn hostname_and_identity_tokens() {
        let c = parse_ssh_config("Host box\n  HostName %h.example.com\n  IdentityFile %d/.ssh/id_box\n");
        assert_eq!(c[0].host, "box.example.com");
        assert_eq!(c[0].key_file.as_deref(), Some("~/.ssh/id_box"));
        assert!(c[0].notes.is_empty());
    }

    #[test]
    fn includes_are_inlined_with_globs_relative_to_ssh_dir() {
        let home = Path::new("/home/me");
        let ssh = home.join(".ssh");
        let files: HashMap<PathBuf, &str> = [
            (ssh.join("conf.d/a.conf"), "Host a\n  HostName 1.1.1.1\n"),
            (ssh.join("conf.d/b.conf"), "Host b\n  HostName 2.2.2.2\nInclude ~/.ssh/deeper\n"),
            (ssh.join("conf.d/notes.txt"), "Host never\n"),
            (ssh.join("deeper"), "Host c\n  HostName 3.3.3.3\n"),
            (ssh.join("loop"), "Include loop\nHost l\n"),
        ]
        .into_iter()
        .collect();
        let read = |p: &Path| files.get(p).map(|s| s.to_string());
        let list = |dir: &Path| files.keys().filter(|p| p.parent() == Some(dir)).cloned().collect();

        let text = inline_includes("Include conf.d/*.conf\nInclude missing\nInclude loop\n", &ssh, home, &read, &list);
        let names: Vec<_> = parse_ssh_config(&text).into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["a", "b", "c", "l"], "globbed, nested, missing ignored, loops stop");
    }

    fn putty(name: &str, values: &[(&str, PuttyValue)]) -> PuttySession {
        PuttySession { key_name: name.into(), values: values.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
    }
    fn s(v: &str) -> PuttyValue {
        PuttyValue::Str(v.into())
    }

    #[test]
    fn putty_sessions_map_to_candidates() {
        let (found, skipped) = putty_candidates(&[
            putty("Default%20Settings", &[("HostName", s("")), ("Protocol", s("ssh"))]),
            putty(
                "My%20Server",
                &[("HostName", s("10.0.0.5")), ("PortNumber", PuttyValue::Dword(2200)), ("Protocol", s("ssh")),
                  ("UserName", s("ops")), ("PublicKeyFile", s(r"C:\keys\ops.ppk"))],
            ),
            putty("inline-user", &[("HostName", s("admin@box.lan")), ("Protocol", s("ssh"))]),
            putty("no-user", &[("HostName", s("box2.lan")), ("Protocol", s("ssh")), ("PortNumber", PuttyValue::Dword(22))]),
            putty("old-router", &[("HostName", s("192.168.1.1")), ("Protocol", s("telnet"))]),
            putty("empty", &[("Protocol", s("ssh"))]),
            putty(
                "proxied",
                &[("HostName", s("inner")), ("ProxyMethod", PuttyValue::Dword(1)), ("PortForwardings", s("L8080=localhost:80"))],
            ),
        ]);

        let my = by_name(&found, "My Server");
        assert_eq!((my.host.as_str(), my.port, my.user.as_deref()), ("10.0.0.5", 2200, Some("ops")));
        assert_eq!(my.key_file.as_deref(), Some(r"C:\keys\ops.ppk"), ".ppk is kept as is; russh reads it");

        let inline = by_name(&found, "inline-user");
        assert_eq!((inline.host.as_str(), inline.user.as_deref()), ("box.lan", Some("admin")));
        assert_eq!(by_name(&found, "no-user").user, None);
        assert_eq!(by_name(&found, "proxied").notes.len(), 2);
        assert!(found.iter().all(|c| c.name != "Default Settings"));

        let reasons: Vec<_> = skipped.iter().map(|k| (k.name.as_str(), k.reason.as_str())).collect();
        assert_eq!(reasons, [("old-router", "telnet sessions aren't supported, only SSH"), ("empty", "No host name saved")]);
    }

    #[test]
    fn session_name_decoding() {
        assert_eq!(decode_session_name("My%20Server"), "My Server");
        assert_eq!(decode_session_name("100%25%20done"), "100% done");
        assert_eq!(decode_session_name("plain"), "plain");
        assert_eq!(decode_session_name("bad%zz"), "bad%zz");
        assert_eq!(decode_session_name("tail%2"), "tail%2");
        assert_eq!(decode_session_name("%E6%9C%8D%E5%8A%A1%E5%99%A8"), "服务器");
        assert_eq!(decode_session_name("中%文"), "中%文", "multibyte after % must not panic");
    }

    fn saved(id: &str, name: &str, host: &str, port: u16, user: &str) -> HostConfig {
        HostConfig {
            id: id.into(),
            name: name.into(),
            host: host.into(),
            port,
            user: user.into(),
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
    fn cand(source: ImportSource, name: &str, host: &str, port: u16, user: Option<&str>) -> ImportCandidate {
        ImportCandidate { source, name: name.into(), host: host.into(), port, user: user.map(Into::into), key_file: None, notes: vec![], folder: None, fingerprint: None, jump: None, forward_agent: false }
    }

    #[test]
    fn proxy_jump_is_matched_to_a_server() {
        let cfg = "Host edge
  HostName edge.example
  User ops
Host api
  HostName 10.0.0.9
  ProxyJump edge
Host db
  ProxyJump ops@bastion.corp:2222
Host web
  ProxyJump first,EDGE
Host lab
  ProxyJump nowhere
Host plain
  ProxyJump none
Host side
  ProxyJump old-api
";
        let existing = [saved("h1", "bastion", "bastion.corp", 2222, "ops"), saved("h2", "old-api", "10.0.0.9", 22, "x")];
        let plan = plan_import(parse_ssh_config(cfg), &existing);
        let jump = |n: &str| plan.iter().find(|p| p.candidate.name == n).unwrap().jump.clone();
        assert_eq!(jump("edge"), None);
        assert_eq!(jump("api"), Some(JumpPlan::Planned { index: 0 }), "another alias in the scan");
        assert_eq!(jump("db"), Some(JumpPlan::Existing { id: "h1".into(), name: "bastion".into() }), "by address");
        assert_eq!(jump("web"), Some(JumpPlan::Planned { index: 0 }), "the last of several, any case");
        assert!(plan.iter().find(|p| p.candidate.name == "web").unwrap().candidate.notes.iter().any(|n| n.contains("several hosts")));
        assert_eq!(jump("lab"), Some(JumpPlan::Unknown { name: "nowhere".into() }));
        assert_eq!(jump("plain"), None, "ProxyJump none");
        assert_eq!(jump("side"), Some(JumpPlan::Existing { id: "h2".into(), name: "old-api".into() }), "a saved server's name");
        assert_eq!(jump_target("me@[::1]:2200"), (Some("me"), "::1", Some(2200)));
        assert_eq!(jump_target("host"), (None, "host", None));
    }

    #[test]
    fn plan_marks_duplicates_and_renames_clashes() {
        let existing = [saved("h1", "api", "10.0.0.1", 22, "deploy")];
        let plan = plan_import(
            vec![
                cand(ImportSource::SshConfig, "api", "10.0.0.1", 22, Some("deploy")), // same as saved
                cand(ImportSource::SshConfig, "api", "10.0.0.2", 22, Some("deploy")), // name clash only
                cand(ImportSource::SshConfig, "db", "DB.lan", 22, Some("pg")),
                cand(ImportSource::Putty, "db", "db.lan", 22, None),                   // same as earlier, user unknown
                cand(ImportSource::Putty, "api", "10.0.0.1", 2222, Some("deploy")),    // other port: not a duplicate
            ],
            &existing,
        );
        let rows: Vec<_> = plan.iter().map(|p| (p.name.as_str(), p.duplicate.clone())).collect();
        assert_eq!(
            rows,
            [
                ("api (2)", Some(Duplicate::Existing { id: "h1".into(), name: "api".into() })),
                ("api (3)", None),
                ("db", None),
                ("db (2)", Some(Duplicate::Earlier { index: 2 })),
                ("api (4)", None),
            ]
        );
    }

    #[test]
    fn candidate_serializes_for_the_webview() {
        let json = serde_json::to_string(&cand(ImportSource::Putty, "x", "h", 22, None)).unwrap();
        assert!(json.contains("\"source\":\"putty\""), "{json}");
        assert!(json.contains("\"user\":null"), "{json}");
    }
}
