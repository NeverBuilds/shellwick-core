//! Quick connect: reads what the user typed into the search box as a server
//! address: `user@host`, `user@host:port`, `[2001:db8::1]:2222`, `ssh://…`,
//! or a pasted `ssh -p 2222 -l user host` command.
//!
//! Plain words ("homelab") are a search, not an address: an address has an
//! `@`, a `:` or a `.`, or starts with `ssh`. Same rules and messages as
//! src/quickRules.ts.

use serde::Serialize;

/// A server to connect to without saving it first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
    /// Parts of a pasted ssh command quick connect doesn't use ("-i", "-L"…).
    pub ignored: Vec<String>,
}

impl Target {
    /// "user@host", or "user@host:2222" (brackets around IPv6 when a port follows).
    pub fn label(&self) -> String {
        let host = if self.host.contains(':') && self.port != 22 { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == 22 {
            format!("{}@{host}", self.user)
        } else {
            format!("{}@{host}:{}", self.user, self.port)
        }
    }
}

pub const BAD_PORT: &str = "The port must be a number from 1 to 65535.";
pub const BAD_HOST: &str = "That doesn't look like a server address.";
pub const BAD_USER: &str = "That user name has characters a user name can't have.";
pub const NO_DESTINATION: &str = "Add the server to connect to, like ssh user@host.";

/// ssh options that take a value (the value is skipped along with them).
const WITH_VALUE: &[char] = &['b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'p', 'Q', 'R', 'S', 'W', 'w'];

/// `None`: not an address (keep searching). `Some(Err)`: looks like one but
/// can't be used, with the reason.
pub fn parse_target(input: &str, local_user: &str) -> Option<Result<Target, String>> {
    let text = input.trim();
    if let Some(rest) = text.strip_prefix("ssh://") {
        return Some(destination(rest.trim_end_matches('/'), None, None, local_user, Vec::new()));
    }
    if text == "ssh" || text.starts_with("ssh ") || text.starts_with("ssh\t") {
        return Some(command(&text[3..], local_user));
    }
    if text.is_empty() || text.chars().any(char::is_whitespace) || !text.contains(['@', ':', '.']) {
        return None;
    }
    Some(destination(text, None, None, local_user, Vec::new()))
}

/// A pasted `ssh …` command: -p and -l are used, other options noted, a remote command ignored.
fn command(args: &str, local_user: &str) -> Result<Target, String> {
    let mut tokens = args.split_whitespace().map(|t| t.trim_matches(['"', '\'']));
    let (mut port, mut user, mut ignored, mut dest) = (None, None, Vec::new(), None);
    while let Some(t) = tokens.next() {
        if dest.is_some() {
            if !ignored.iter().any(|i| i == "the remote command") {
                ignored.push("the remote command".to_string());
            }
            continue;
        }
        let Some(opts) = t.strip_prefix('-').filter(|o| !o.is_empty()) else {
            dest = Some(t.to_string());
            continue;
        };
        // Flags can be grouped (-4v); the first one taking a value ends the group.
        for (i, c) in opts.char_indices() {
            if WITH_VALUE.contains(&c) {
                let inline = &opts[i + c.len_utf8()..];
                let value = if inline.is_empty() { tokens.next().unwrap_or("").to_string() } else { inline.to_string() };
                match c {
                    'p' => port = Some(value),
                    'l' => user = Some(value),
                    _ => ignored.push(format!("-{c}")),
                }
                break;
            }
            ignored.push(format!("-{c}"));
        }
    }
    let dest = dest.ok_or_else(|| NO_DESTINATION.to_string())?;
    destination(&dest, port.as_deref(), user.as_deref(), local_user, ignored)
}

/// `[user@]host[:port]` (IPv6 in brackets when a port follows). An explicit
/// -p / -l from a command wins over the ones in the address, like ssh.
fn destination(text: &str, port_opt: Option<&str>, user_opt: Option<&str>, local_user: &str, ignored: Vec<String>) -> Result<Target, String> {
    let (user_part, host_part) = match text.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, text),
    };
    let (host, port_part) = if let Some(rest) = host_part.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| BAD_HOST.to_string())?;
        match after {
            "" => (h, None),
            a => (h, Some(a.strip_prefix(':').ok_or_else(|| BAD_HOST.to_string())?)),
        }
    } else {
        match host_part.matches(':').count() {
            0 => (host_part, None),
            1 => {
                let (h, p) = host_part.split_once(':').unwrap_or((host_part, ""));
                (h, Some(p))
            }
            _ => (host_part, None), // a bare IPv6 address
        }
    };
    let host = host.trim();
    if host.is_empty() || host.len() > 255 || host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '[' | ']')) {
        return Err(BAD_HOST.to_string());
    }
    let port = match port_opt.or(port_part) {
        None => 22,
        Some(p) => p.parse::<u16>().ok().filter(|&n| n > 0).ok_or_else(|| BAD_PORT.to_string())?,
    };
    let user = user_opt.or(user_part).unwrap_or(local_user).trim();
    if user.is_empty() || user.chars().count() > 64 || user.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '/' | '\\')) {
        return Err(BAD_USER.to_string());
    }
    Ok(Target { user: user.to_string(), host: host.to_string(), port, ignored })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Target {
        parse_target(s, "me").expect("an address").expect("valid")
    }
    fn t(user: &str, host: &str, port: u16) -> Target {
        Target { user: user.into(), host: host.into(), port, ignored: vec![] }
    }

    #[test]
    fn plain_words_are_a_search() {
        assert_eq!(parse_target("homelab", "me"), None);
        assert_eq!(parse_target("", "me"), None);
        assert_eq!(parse_target("two words", "me"), None);
    }

    #[test]
    fn addresses() {
        assert_eq!(ok("deploy@10.0.4.12"), t("deploy", "10.0.4.12", 22));
        assert_eq!(ok(" deploy@api.example.com:2222 "), t("deploy", "api.example.com", 2222));
        assert_eq!(ok("api.example.com"), t("me", "api.example.com", 22), "no user: this computer's");
        assert_eq!(ok("box:2200"), t("me", "box", 2200));
        assert_eq!(ok("root@[2001:db8::1]:2222"), t("root", "2001:db8::1", 2222));
        assert_eq!(ok("2001:db8::1"), t("me", "2001:db8::1", 22));
        assert_eq!(ok("ssh://ops@bastion.example.net:22/"), t("ops", "bastion.example.net", 22));
        // Windows domain accounts: split on the last @, like ssh.
        assert_eq!(ok("first.last@corp@gw.example.com"), t("first.last@corp", "gw.example.com", 22));
    }

    #[test]
    fn bad_addresses_say_why() {
        assert_eq!(parse_target("me@host:99999", "me"), Some(Err(BAD_PORT.into())));
        assert_eq!(parse_target("me@host:", "me"), Some(Err(BAD_PORT.into())));
        assert_eq!(parse_target("me@:22", "me"), Some(Err(BAD_HOST.into())));
        assert_eq!(parse_target("me@[::1", "me"), Some(Err(BAD_HOST.into())));
        assert_eq!(parse_target("ssh -p 22", "me"), Some(Err(NO_DESTINATION.into())));
        assert_eq!(parse_target("api.example.com", "bad user"), Some(Err(BAD_USER.into())));
    }

    #[test]
    fn pasted_ssh_commands() {
        assert_eq!(ok("ssh deploy@api.example.com"), t("deploy", "api.example.com", 22));
        assert_eq!(ok("ssh -p 2222 -l ops box.example.com"), t("ops", "box.example.com", 2222));
        assert_eq!(ok("ssh -p2222 ops@box"), t("ops", "box", 2222));
        let x = ok("ssh -i ~/.ssh/work -L 8080:localhost:80 -4v deploy@api.example.com uptime");
        assert_eq!((x.user.as_str(), x.host.as_str(), x.port), ("deploy", "api.example.com", 22));
        assert_eq!(x.ignored, ["-i", "-L", "-4", "-v", "the remote command"]);
        // -p / -l win over the address, like ssh.
        assert_eq!(ok("ssh -p 2200 -l root admin@host:22"), t("root", "host", 2200));
        assert_eq!(ok("ssh -J bastion internal").ignored, ["-J"]);
    }

    /// Prints results for a file of inputs (one per line), to compare with src/quickRules.ts:
    /// SHELLWICK_QUICK_CASES=cases.txt cargo test -p sshcore --lib quick::tests::print_cases -- --ignored --nocapture
    #[test]
    #[ignore]
    fn print_cases() {
        let path = std::env::var("SHELLWICK_QUICK_CASES").expect("SHELLWICK_QUICK_CASES");
        let text = std::fs::read_to_string(path).unwrap().replace('\r', "");
        let mut lines: Vec<&str> = text.split('\n').collect();
        lines.pop();
        for c in lines {
            let out = match parse_target(c, "me") {
                None => "none".to_string(),
                Some(Err(e)) => format!("err:{e}"),
                Some(Ok(t)) => format!("ok:{}|{}|{}|{}|{}", t.user, t.host, t.port, t.ignored.join(","), t.label()),
            };
            println!("CASE {} => {out}", serde_json::to_string(c).unwrap());
        }
    }

    #[test]
    fn labels() {
        assert_eq!(t("a", "h", 22).label(), "a@h");
        assert_eq!(t("a", "h", 2222).label(), "a@h:2222");
        assert_eq!(t("a", "2001:db8::1", 2222).label(), "a@[2001:db8::1]:2222");
        assert_eq!(t("a", "2001:db8::1", 22).label(), "a@2001:db8::1");
    }
}
