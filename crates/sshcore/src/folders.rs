//! Host folders: one level, derived from the hosts themselves.
//!
//! A folder exists while at least one host names it in
//! [`HostConfig::folder`]; there is no separate folder list. Names compare
//! without regard to case, so "Prod" and "prod" are the same folder and the
//! spelling already in use wins. `src/folderRules.ts` has the same rules and
//! messages.

use crate::HostConfig;

pub const MAX_FOLDER: usize = 100;

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// True when `path` is `prefix` itself or a nested subfolder under `prefix/` (case-insensitive).
fn in_subtree<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if same(path, prefix) {
        return Some("");
    }
    let plen = prefix.len();
    if path.len() > plen && path.is_char_boundary(plen) && same(&path[..plen], prefix) && path[plen..].starts_with('/') {
        return Some(&path[plen..]);
    }
    None
}

/// Trimmed folder name, `None` for blank (no folder), or the rule it breaks.
pub fn check_folder(name: &str) -> Result<Option<String>, String> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > MAX_FOLDER {
        return Err(format!("Keep the folder name under {MAX_FOLDER} characters."));
    }
    if name.chars().any(char::is_control) {
        return Err("The folder name can't contain control characters.".into());
    }
    Ok(Some(name.to_string()))
}

/// The folder to store for a host being saved: checked, and spelled like an
/// existing folder that differs only in case. `except` is the host being
/// edited, so a folder's only member can change the folder's spelling.
pub fn canonical_folder(name: Option<&str>, hosts: &[HostConfig], except: Option<&str>) -> Result<Option<String>, String> {
    let Some(name) = check_folder(name.unwrap_or(""))? else { return Ok(None) };
    let existing = hosts
        .iter()
        .filter(|h| Some(h.id.as_str()) != except)
        .filter_map(|h| h.folder.as_deref())
        .find(|f| same(f, &name));
    Ok(Some(existing.map_or(name, str::to_string)))
}

/// Every folder in use, A–Z (ignoring case), each once.
pub fn folders(hosts: &[HostConfig]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in hosts.iter().filter_map(|h| h.folder.as_deref()) {
        if !out.iter().any(|o| same(o, f)) {
            out.push(f.to_string());
        }
    }
    out.sort_by_key(|f| (f.to_lowercase(), f.clone()));
    out
}

/// Moves every host in `from` into `to` and returns how many moved. When `to`
/// is another existing folder the two merge under that folder's spelling.
pub fn rename_folder(hosts: &mut [HostConfig], from: &str, to: &str) -> Result<usize, String> {
    let Some(to) = check_folder(to)? else { return Err("Give the folder a name.".into()) };
    let to = hosts
        .iter()
        .filter_map(|h| h.folder.as_deref())
        .find(|f| same(f, &to) && !same(f, from))
        .map_or(to, str::to_string);
    let mut moved = 0;
    for h in hosts.iter_mut() {
        if let Some(rest) = h.folder.as_deref().and_then(|f| in_subtree(f, from)) {
            h.folder = Some(if rest.is_empty() { to.clone() } else { format!("{to}{rest}") });
            moved += 1;
        }
    }
    if moved == 0 {
        return Err("That folder no longer exists.".into());
    }
    Ok(moved)
}

/// Takes every host out of `name` (and any nested subfolders under `name/`).
/// Nothing is deleted. Returns how many hosts changed.
pub fn ungroup_folder(hosts: &mut [HostConfig], name: &str) -> usize {
    let mut n = 0;
    for h in hosts.iter_mut() {
        if h.folder.as_deref().and_then(|f| in_subtree(f, name)).is_some() {
            h.folder = None;
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthMethod;

    fn host(id: &str, folder: Option<&str>) -> HostConfig {
        HostConfig {
            id: id.into(),
            name: id.into(),
            host: "h".into(),
            port: 22,
            user: "u".into(),
            auth: AuthMethod::Agent,
            host_key_fingerprint: None,
            startup_command: None,
            tags: vec![],
            environment: None,
            folder: folder.map(Into::into),
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

    fn folder_of<'a>(hosts: &'a [HostConfig], id: &str) -> Option<&'a str> {
        hosts.iter().find(|h| h.id == id).unwrap().folder.as_deref()
    }

    #[test]
    fn names_are_trimmed_and_checked() {
        assert_eq!(check_folder("  Clients  "), Ok(Some("Clients".into())));
        assert_eq!(check_folder("   "), Ok(None));
        assert_eq!(check_folder(""), Ok(None));
        assert_eq!(check_folder("客户 / Acme"), Ok(Some("客户 / Acme".into())));
        assert_eq!(check_folder(&"x".repeat(100)).unwrap().unwrap().len(), 100);
        assert_eq!(check_folder(&"x".repeat(101)).unwrap_err(), "Keep the folder name under 100 characters.");
        assert_eq!(check_folder("a\tb").unwrap_err(), "The folder name can't contain control characters.");
    }

    #[test]
    fn existing_spelling_wins_except_for_the_host_itself() {
        let hosts = vec![host("a", Some("Prod")), host("b", Some("Prod")), host("c", Some("lab"))];
        assert_eq!(canonical_folder(Some("prod "), &hosts, None), Ok(Some("Prod".into())));
        assert_eq!(canonical_folder(Some("Home"), &hosts, None), Ok(Some("Home".into())));
        assert_eq!(canonical_folder(Some(" "), &hosts, None), Ok(None));
        assert_eq!(canonical_folder(None, &hosts, None), Ok(None));
        // c is lab's only member, so it may respell it.
        assert_eq!(canonical_folder(Some("Lab"), &hosts, Some("c")), Ok(Some("Lab".into())));
        // a shares Prod with b: it joins the existing spelling.
        assert_eq!(canonical_folder(Some("PROD"), &hosts, Some("a")), Ok(Some("Prod".into())));
        assert!(canonical_folder(Some(&"x".repeat(101)), &hosts, None).is_err());
    }

    #[test]
    fn folder_list_is_sorted_and_unique() {
        let hosts = vec![host("a", Some("zeta")), host("b", None), host("c", Some("Alpha")), host("d", Some("zeta")), host("e", Some("beta"))];
        assert_eq!(folders(&hosts), ["Alpha", "beta", "zeta"]);
        assert!(folders(&[host("x", None)]).is_empty());
    }

    #[test]
    fn rename_moves_and_merges() {
        let mut hosts = vec![host("a", Some("Old")), host("b", Some("old")), host("c", Some("Keep")), host("d", None)];
        assert_eq!(rename_folder(&mut hosts, "Old", "  New "), Ok(2));
        assert_eq!((folder_of(&hosts, "a"), folder_of(&hosts, "b")), (Some("New"), Some("New")));
        assert_eq!(folder_of(&hosts, "c"), Some("Keep"));
        assert_eq!(folder_of(&hosts, "d"), None);
        // Into an existing folder: merged under its spelling.
        assert_eq!(rename_folder(&mut hosts, "New", "keep"), Ok(2));
        assert_eq!(folders(&hosts), ["Keep"]);
        // Case-only rename of a folder.
        assert_eq!(rename_folder(&mut hosts, "Keep", "KEEP"), Ok(3));
        assert_eq!(folders(&hosts), ["KEEP"]);
        assert_eq!(rename_folder(&mut hosts, "gone", "x").unwrap_err(), "That folder no longer exists.");
        assert_eq!(rename_folder(&mut hosts, "KEEP", " ").unwrap_err(), "Give the folder a name.");
        assert!(rename_folder(&mut hosts, "KEEP", &"x".repeat(101)).is_err());
        assert_eq!(folders(&hosts), ["KEEP"], "refused renames change nothing");
        // Nested folder rename updates descendants too.
        let mut nested = vec![host("a", Some("Clients/Acme/Prod")), host("b", Some("Clients/Acme")), host("c", Some("Other"))];
        assert_eq!(rename_folder(&mut nested, "Clients/Acme", "Customers/Acme"), Ok(2));
        assert_eq!(folder_of(&nested, "a"), Some("Customers/Acme/Prod"));
        assert_eq!(folder_of(&nested, "b"), Some("Customers/Acme"));
        assert_eq!(folder_of(&nested, "c"), Some("Other"));
    }

    #[test]
    fn ungroup_only_clears_the_folder() {
        let mut hosts = vec![host("a", Some("Lab")), host("b", Some("lab")), host("c", Some("Prod"))];
        assert_eq!(ungroup_folder(&mut hosts, "LAB"), 2);
        assert_eq!(hosts.len(), 3, "no host is deleted");
        assert_eq!(folders(&hosts), ["Prod"]);
        assert_eq!(ungroup_folder(&mut hosts, "Lab"), 0);
    }

    #[test]
    fn old_hosts_json_has_no_folder() {
        let json = r#"{"id":"1","name":"n","host":"h","port":22,"user":"u","auth":{"kind":"agent"},"host_key_fingerprint":null,"startup_command":null}"#;
        let cfg: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.folder, None);
    }
}
