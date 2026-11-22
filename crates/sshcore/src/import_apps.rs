//! Import from other SSH apps: SecureCRT session files, MobaXterm bookmarks
//! (MobaXterm.ini or the registry), and host keys from OpenSSH's known_hosts.
//!
//! Like `import`: only connection parameters, never passwords (both apps keep
//! encrypted passwords; they are ignored). Nested folders map to their top
//! folder (Shellwick folders are one level). Parsing is pure; reading files and
//! the registry is in thin functions at the bottom.

use crate::folders::MAX_FOLDER;
use crate::import::{ImportCandidate, ImportSkip, ImportSource};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The top folder of a nested path, made a valid Shellwick folder (cut to the limit).
fn top_folder<'a>(parts: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let top = parts.into_iter().map(str::trim).find(|p| !p.is_empty())?;
    let clean: String = top.chars().filter(|c| !c.is_control()).take(MAX_FOLDER).collect();
    let clean = clean.trim().to_string();
    (!clean.is_empty()).then_some(clean)
}

/// Text from a file that may be UTF-8 (with or without BOM) or a Windows code page.
pub fn decode_text(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        // Latin-1 keeps every byte: names may look odd, addresses stay right.
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

// ---------------------------------------------------------------------------
// SecureCRT
// ---------------------------------------------------------------------------

/// One SecureCRT session file: its folders under `Sessions` and its text.
#[derive(Debug, Clone)]
pub struct SecureCrtFile {
    pub folders: Vec<String>,
    /// File name without `.ini`.
    pub name: String,
    pub text: String,
}

/// `S:"Hostname"=web1` → ("Hostname", "web1"); `D:"[SSH2] Port"=00000016` → hex.
fn crt_values(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let Some((kind, rest)) = line.split_once(':') else { continue };
        if !matches!(kind, "S" | "D" | "Z" | "B") {
            continue;
        }
        let Some(rest) = rest.strip_prefix('"') else { continue };
        let Some((key, value)) = rest.split_once("\"=") else { continue };
        out.insert(key.to_string(), value.trim_end_matches('\r').to_string());
    }
    out
}

fn crt_dword(v: &HashMap<String, String>, key: &str) -> Option<u32> {
    v.get(key).and_then(|s| u32::from_str_radix(s.trim(), 16).ok())
}

/// SecureCRT points at the public key (`id_rsa.pub`) and may add `::rawkey`;
/// the private key is the same path without `.pub`.
fn crt_key_path(raw: &str) -> Option<String> {
    let path = raw.split("::").next().unwrap_or(raw).trim();
    if path.is_empty() {
        return None;
    }
    Some(path.strip_suffix(".pub").unwrap_or(path).to_string())
}

pub fn securecrt_candidates(files: &[SecureCrtFile]) -> (Vec<ImportCandidate>, Vec<ImportSkip>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for f in files {
        if f.name.eq_ignore_ascii_case("__FolderData__") || (f.folders.is_empty() && f.name.eq_ignore_ascii_case("Default")) {
            continue;
        }
        let skip = |reason: String| ImportSkip { source: ImportSource::SecureCrt, name: f.name.clone(), reason };
        let v = crt_values(&f.text);
        let protocol = v.get("Protocol Name").map(String::as_str).unwrap_or("SSH2");
        if !protocol.eq_ignore_ascii_case("SSH2") {
            skipped.push(skip(format!("{protocol} sessions aren't supported, only SSH")));
            continue;
        }
        let Some(host) = v.get("Hostname").map(|h| h.trim()).filter(|h| !h.is_empty()) else {
            skipped.push(skip("No host name saved".into()));
            continue;
        };
        let port = crt_dword(&v, "[SSH2] Port").and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0).unwrap_or(22);
        let user = v.get("Username").map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
        let key_file = v.get("Identity Filename V2").or_else(|| v.get("Identity Filename")).and_then(|k| crt_key_path(k));
        let mut notes = Vec::new();
        match v.get("Firewall Name").map(|s| s.trim()) {
            Some(fw) if fw.starts_with("Session:") => notes.push("Jump host settings aren't imported".to_string()),
            Some(fw) if !fw.is_empty() && !fw.eq_ignore_ascii_case("None") => notes.push("Proxy / firewall settings aren't imported".to_string()),
            _ => {}
        }
        if v.get("Port Forward Table V2").is_some_and(|t| !t.trim().starts_with("00000000")) {
            notes.push("Port forwarding isn't imported yet".to_string());
        }
        found.push(ImportCandidate {
            source: ImportSource::SecureCrt,
            name: f.name.clone(),
            host: host.to_string(),
            port,
            user,
            key_file,
            notes,
            folder: top_folder(f.folders.iter().map(String::as_str)),
            fingerprint: None,
            jump: None,
            forward_agent: false,
        });
    }
    (found, skipped)
}

// ---------------------------------------------------------------------------
// MobaXterm
// ---------------------------------------------------------------------------

const MOBA_TYPES: &[&str] = &["SSH", "Telnet", "Rsh", "XDMCP", "RDP", "VNC", "FTP", "SFTP", "Serial", "File", "Shell", "Browser", "Mosh", "S3", "WSL"];

/// Expands MobaXterm's folder placeholders it shares with Shellwick (`_ProfileDir_` = home).
fn moba_key_path(raw: &str) -> Result<Option<String>, ()> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if let Some(rest) = raw.strip_prefix("_ProfileDir_") {
        return Ok(Some(format!("~/{}", rest.trim_start_matches(['\\', '/']).replace('\\', "/"))));
    }
    // Other placeholders (_CurrentDrive_, _MyDocuments_…) depend on that MobaXterm install.
    if raw.starts_with('_') && raw[1..].contains('_') {
        return Err(());
    }
    Ok(Some(raw.to_string()))
}

/// Bookmarks from MobaXterm.ini text: `[Bookmarks]`, `[Bookmarks_1]`… with
/// `SubRep=Folder\Sub` and one `name=#icon#0%host%port%user%…` line per session.
pub fn mobaxterm_candidates(text: &str) -> (Vec<ImportCandidate>, Vec<ImportSkip>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    let mut in_bookmarks = false;
    let mut folder: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let s = section.to_ascii_lowercase();
            in_bookmarks = s == "bookmarks" || s.starts_with("bookmarks_");
            folder = None;
            continue;
        }
        if !in_bookmarks {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else { continue };
        match name {
            "SubRep" => {
                folder = top_folder(value.split('\\'));
                continue;
            }
            "ImgNum" | "" => continue,
            _ => {}
        }
        let name = name.trim().to_string();
        let skip = |reason: String| ImportSkip { source: ImportSource::MobaXterm, name: name.clone(), reason };
        // "#109#0%host%22%user%…#MobaFont%…": the third '#' part holds the connection.
        let Some(conn) = value.trim().split('#').nth(2) else {
            skipped.push(skip("Not a session MobaXterm format Shellwick knows".into()));
            continue;
        };
        let f: Vec<&str> = conn.split('%').collect();
        let kind: usize = f.first().and_then(|k| k.parse().ok()).unwrap_or(usize::MAX);
        if kind != 0 {
            let what = MOBA_TYPES.get(kind).copied().unwrap_or("These");
            skipped.push(skip(format!("{what} sessions aren't supported, only SSH")));
            continue;
        }
        let Some(host) = f.get(1).map(|h| h.trim()).filter(|h| !h.is_empty()) else {
            skipped.push(skip("No host name saved".into()));
            continue;
        };
        let port = f.get(2).and_then(|p| p.trim().parse::<u16>().ok()).filter(|p| *p != 0).unwrap_or(22);
        let user = f.get(3).map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
        let mut notes = Vec::new();
        let key_file = match moba_key_path(f.get(14).copied().unwrap_or("")) {
            Ok(k) => k,
            Err(()) => {
                notes.push("The key file path depends on MobaXterm's folders; pick it after importing".to_string());
                None
            }
        };
        if f.get(8).is_some_and(|g| !g.trim().is_empty()) {
            notes.push("SSH gateway (jump host) isn't imported".to_string());
        }
        found.push(ImportCandidate {
            source: ImportSource::MobaXterm,
            name,
            host: host.to_string(),
            port,
            user,
            key_file,
            notes,
            folder: folder.clone(),
            fingerprint: None,
            jump: None,
            forward_agent: false,
        });
    }
    (found, skipped)
}

// ---------------------------------------------------------------------------
// known_hosts
// ---------------------------------------------------------------------------

/// The SHA-256 fingerprint of the Ed25519 key `known_hosts` lists for
/// host:port (hashed entries included). Only Ed25519: it's what Shellwick is shown
/// whenever a server has one, so taking an older RSA / ECDSA entry could look
/// like a changed key. Unreadable files and entries count as nothing known.
pub fn known_ed25519(known_hosts: &Path, host: &str, port: u16) -> Option<String> {
    use russh::keys::ssh_key::{Algorithm, HashAlg};
    russh::keys::known_hosts::known_host_keys_path(host, port, known_hosts)
        .ok()?
        .into_iter()
        .find(|(_, k)| k.algorithm() == Algorithm::Ed25519)
        .map(|(_, k)| k.fingerprint(HashAlg::Sha256).to_string())
}

/// `<home>/.ssh/known_hosts`.
pub fn known_hosts_path(home: &Path) -> PathBuf {
    home.join(".ssh").join("known_hosts")
}

// ---------------------------------------------------------------------------
// Reading the real sources
// ---------------------------------------------------------------------------

/// Session files under a SecureCRT `Sessions` folder (sub-folders = folders).
pub fn read_securecrt_dir(sessions: &Path) -> std::io::Result<Vec<SecureCrtFile>> {
    fn walk(dir: &Path, folders: &[String], out: &mut Vec<SecureCrtFile>) -> std::io::Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let Ok(kind) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                let mut next = folders.to_vec();
                next.push(name);
                walk(&e.path(), &next, out)?;
            } else if let Some(stem) = name.strip_suffix(".ini").or_else(|| name.strip_suffix(".INI")) {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    out.push(SecureCrtFile { folders: folders.to_vec(), name: stem.to_string(), text: decode_text(&bytes) });
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(sessions, &[], &mut out)?;
    Ok(out)
}

/// A SecureCRT folder as pasted: the `Sessions` folder, the `Config` folder, or the folder holding `Config`.
pub fn securecrt_sessions_in(dir: &Path) -> Option<PathBuf> {
    [dir.join("Config").join("Sessions"), dir.join("Sessions"), dir.to_path_buf()]
        .into_iter()
        .find(|d| d.is_dir() && (d.file_name().is_some_and(|n| n.eq_ignore_ascii_case("Sessions"))))
}

/// Where SecureCRT keeps sessions on this computer (its own "Config Path" setting first).
pub fn securecrt_dirs(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\VanDyke\SecureCRT") {
            if let Ok(p) = key.get_value::<String, _>("Config Path") {
                dirs.push(PathBuf::from(p).join("Sessions"));
            }
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            dirs.push(PathBuf::from(appdata).join("VanDyke").join("Config").join("Sessions"));
        }
    }
    dirs.push(home.join("Library/Application Support/VanDyke/SecureCRT/Config/Sessions"));
    dirs.push(home.join(".vandyke/SecureCRT/Config/Sessions"));
    let mut seen = Vec::new();
    dirs.retain(|d| {
        let new = !seen.contains(d);
        seen.push(d.clone());
        new && d.is_dir()
    });
    dirs
}

/// MobaXterm.ini files of an installed MobaXterm (portable copies keep theirs
/// next to the program: paste that path).
pub fn mobaxterm_files(home: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        files.push(PathBuf::from(appdata).join("MobaXterm").join("MobaXterm.ini"));
    }
    files.push(home.join("Documents").join("MobaXterm").join("MobaXterm.ini"));
    files.retain(|f| f.is_file());
    files
}

/// MobaXterm's bookmarks kept in the registry (the "store in registry"
/// setting), as MobaXterm.ini text. Empty off Windows or when there are none.
#[cfg(windows)]
pub fn read_mobaxterm_registry() -> String {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let Ok(root) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Mobatek\MobaXterm") else { return String::new() };
    let mut text = String::new();
    for name in root.enum_keys().filter_map(Result::ok).filter(|k| k.to_ascii_lowercase().starts_with("bookmarks")) {
        let Ok(key) = root.open_subkey(&name) else { continue };
        text.push_str(&format!("[{name}]\n"));
        for (value_name, _) in key.enum_values().filter_map(Result::ok) {
            if let Ok(v) = key.get_value::<String, _>(&value_name) {
                text.push_str(&format!("{value_name}={v}\n"));
            }
        }
    }
    text
}

#[cfg(not(windows))]
pub fn read_mobaxterm_registry() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crt(folders: &[&str], name: &str, text: &str) -> SecureCrtFile {
        SecureCrtFile { folders: folders.iter().map(|s| s.to_string()).collect(), name: name.into(), text: text.into() }
    }

    #[test]
    fn securecrt_sessions() {
        let web = "S:\"Protocol Name\"=SSH2\r\nS:\"Hostname\"=10.0.0.5\r\nS:\"Username\"=deploy\r\nD:\"[SSH2] Port\"=00000898\r\nS:\"Identity Filename V2\"=C:\\Users\\me\\.ssh\\id_rsa.pub::rawkey\r\nS:\"Firewall Name\"=None\r\nS:\"Password V2\"=02:abcdef\r\nZ:\"Port Forward Table V2\"=00000001\r\n";
        let files = vec![
            crt(&[], "Default", "S:\"Hostname\"=\n"),
            crt(&["Acme", "Prod"], "web1", web),
            crt(&["Acme"], "__FolderData__", "S:\"Is Expanded\"=1\n"),
            crt(&[], "lab", "S:\"Hostname\"=lab.local\nS:\"Firewall Name\"=Session:bastion\n"),
            crt(&[], "router", "S:\"Protocol Name\"=Telnet\nS:\"Hostname\"=192.168.1.1\n"),
            crt(&[], "empty", "S:\"Protocol Name\"=SSH2\n"),
        ];
        let (found, skipped) = securecrt_candidates(&files);
        assert_eq!(found.len(), 2);
        let w = &found[0];
        assert_eq!((w.name.as_str(), w.host.as_str(), w.port, w.user.as_deref()), ("web1", "10.0.0.5", 2200, Some("deploy")));
        assert_eq!(w.key_file.as_deref(), Some(r"C:\Users\me\.ssh\id_rsa"), "the private key, not the .pub");
        assert_eq!(w.folder.as_deref(), Some("Acme"), "top folder only");
        assert_eq!(w.notes, ["Port forwarding isn't imported yet"]);
        let lab = &found[1];
        assert_eq!((lab.port, lab.user.as_deref(), lab.folder.as_deref()), (22, None, None));
        assert_eq!(lab.notes, ["Jump host settings aren't imported"]);
        let reasons: Vec<_> = skipped.iter().map(|s| (s.name.as_str(), s.reason.as_str())).collect();
        assert_eq!(reasons, [("router", "Telnet sessions aren't supported, only SSH"), ("empty", "No host name saved")]);
        // Nothing secret ends up anywhere in a candidate.
        assert!(!format!("{found:?}").contains("abcdef"));
    }

    #[test]
    fn mobaxterm_bookmarks() {
        let ini = "[Misc]\nSkin=1\n[Bookmarks]\nSubRep=\nImgNum=42\napi (prod)=#109#0%api.example.com%2222%deploy%%-1%-1%%bastion.example.com%22%ops%0%0%0%_ProfileDir_\\.ssh\\id_ed25519%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15#0# #-1\nwin=#91#4%10.0.0.9%3389%admin%%-1#MobaFont#0\n[Bookmarks_1]\nSubRep=Clients\\Acme\\Prod\nImgNum=41\nweb=#109#0%web.acme.test%22%%%-1%-1%%%22%%0%0%0%_CurrentDrive_\\keys\\k%%-1%0#MobaFont#0\nbroken=nothing here\n[Other]\nnot=#109#0%x%22%y\n";
        let (found, skipped) = mobaxterm_candidates(ini);
        assert_eq!(found.len(), 2, "{found:?}");
        let api = &found[0];
        assert_eq!((api.name.as_str(), api.host.as_str(), api.port, api.user.as_deref(), api.folder.as_deref()), ("api (prod)", "api.example.com", 2222, Some("deploy"), None));
        assert_eq!(api.key_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(api.notes, ["SSH gateway (jump host) isn't imported"]);
        let web = &found[1];
        assert_eq!((web.user.as_deref(), web.folder.as_deref(), web.key_file.as_deref()), (None, Some("Clients"), None));
        assert_eq!(web.notes, ["The key file path depends on MobaXterm's folders; pick it after importing"]);
        let reasons: Vec<_> = skipped.iter().map(|s| (s.name.as_str(), s.reason.as_str())).collect();
        assert_eq!(reasons, [("win", "RDP sessions aren't supported, only SSH"), ("broken", "Not a session MobaXterm format Shellwick knows")]);
    }

    #[test]
    fn text_decodes_utf8_bom_and_code_pages() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFS:\"Hostname\"=x"), "S:\"Hostname\"=x");
        assert_eq!(decode_text(b"caf\xe9"), "café");
        assert_eq!(decode_text("Zürich".as_bytes()), "Zürich");
    }

    #[test]
    fn folders_are_cut_to_the_limit() {
        assert_eq!(top_folder(["", " Acme ", "Prod"]).as_deref(), Some("Acme"));
        assert_eq!(top_folder(["x".repeat(MAX_FOLDER + 20).as_str()]).map(|f| f.chars().count()), Some(MAX_FOLDER));
        assert_eq!(top_folder(["", "  "]), None);
    }

    #[test]
    fn known_hosts_gives_the_ed25519_key_only() {
        let dir = std::env::temp_dir().join(format!("shellwick-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        let ed = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let rsa_only = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC3";
        // A hashed entry for web.example.com, made like `ssh-keygen -H` does.
        use hmac_sha1_for_test::hashed;
        let text = format!(
            "# comment\nplain.example.com,10.0.0.1 ssh-ed25519 {ed}\n[alt.example.com]:2222 ssh-ed25519 {ed}\nold.example.com ssh-rsa {rsa_only}\n{} ssh-ed25519 {ed}\n",
            hashed("web.example.com")
        );
        std::fs::write(&path, text).unwrap();
        let fp = known_ed25519(&path, "plain.example.com", 22).expect("listed");
        assert!(fp.starts_with("SHA256:"), "{fp}");
        assert_eq!(known_ed25519(&path, "10.0.0.1", 22).as_deref(), Some(fp.as_str()));
        assert_eq!(known_ed25519(&path, "alt.example.com", 2222).as_deref(), Some(fp.as_str()));
        assert_eq!(known_ed25519(&path, "alt.example.com", 22), None, "another port");
        assert_eq!(known_ed25519(&path, "web.example.com", 22).as_deref(), Some(fp.as_str()), "hashed");
        assert_eq!(known_ed25519(&path, "nowhere.example.com", 22), None);
        assert_eq!(known_ed25519(&path, "old.example.com", 22), None, "RSA only (and unreadable here)");
        assert_eq!(known_ed25519(&dir.join("missing"), "plain.example.com", 22), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `|1|salt|hash` entries like `ssh-keygen -H` writes (HMAC-SHA1 of the name).
    mod hmac_sha1_for_test {
        pub fn hashed(host: &str) -> String {
            let salt = [7u8; 20];
            let mac = hmac_sha1(&salt, host.as_bytes());
            format!("|1|{}|{}", b64(&salt), b64(&mac))
        }

        fn b64(data: &[u8]) -> String {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
                for i in 0..4 {
                    out.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
                }
            }
            out
        }

        // A tiny HMAC-SHA1 (test only), so the test needs no extra crates.
        fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
            let mut k = [0u8; 64];
            k[..key.len()].copy_from_slice(key);
            let inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).chain(msg.iter().copied()).collect();
            let ih = sha1(&inner);
            let outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).chain(ih.iter().copied()).collect();
            sha1(&outer)
        }

        fn sha1(data: &[u8]) -> [u8; 20] {
            let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
            let mut msg = data.to_vec();
            let bits = (data.len() as u64) * 8;
            msg.push(0x80);
            while msg.len() % 64 != 56 {
                msg.push(0);
            }
            msg.extend_from_slice(&bits.to_be_bytes());
            for chunk in msg.chunks(64) {
                let mut w = [0u32; 80];
                for i in 0..16 {
                    w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
                }
                for i in 16..80 {
                    w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
                }
                let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
                for (i, wi) in w.iter().enumerate() {
                    let (f, k) = match i {
                        0..=19 => ((b & c) | (!b & d), 0x5A827999),
                        20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                        40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                        _ => (b ^ c ^ d, 0xCA62C1D6),
                    };
                    let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
                    e = d;
                    d = c;
                    c = b.rotate_left(30);
                    b = a;
                    a = t;
                }
                h = [h[0].wrapping_add(a), h[1].wrapping_add(b), h[2].wrapping_add(c), h[3].wrapping_add(d), h[4].wrapping_add(e)];
            }
            let mut out = [0u8; 20];
            for (i, v) in h.iter().enumerate() {
                out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
            }
            out
        }
    }
}
