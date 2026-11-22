//! Reads this machine's real PuTTY sessions, ~/.ssh/config, SecureCRT /
//! MobaXterm sessions and known_hosts. Ignored by
//! default; run with
//!
//!   cargo test -p sshcore --test import_live -- --ignored --nocapture
//!
//! Prints counts and which fields were found — never host names or users.

use sshcore::import::{plan_import, putty_candidates, read_putty_sessions, read_ssh_config, ImportCandidate};

fn summarize(label: &str, c: &[ImportCandidate]) {
    let with_user = c.iter().filter(|x| x.user.is_some()).count();
    let with_key = c.iter().filter(|x| x.key_file.is_some()).count();
    let ppk = c.iter().filter(|x| x.key_file.as_deref().is_some_and(|k| k.to_ascii_lowercase().ends_with(".ppk"))).count();
    let non_default_port = c.iter().filter(|x| x.port != 22).count();
    let notes: usize = c.iter().map(|x| x.notes.len()).sum();
    println!("{label}: {} hosts, {with_user} with user, {with_key} with key ({ppk} .ppk), {non_default_port} non-22 port, {notes} notes", c.len());
}

#[test]
#[ignore = "reads this machine's real configuration"]
fn scan_this_machine() {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).expect("home dir");
    let ssh = read_ssh_config(std::path::Path::new(&home)).expect("read ~/.ssh/config").unwrap_or_default();
    summarize("ssh config", &ssh);

    let sessions = read_putty_sessions().expect("read PuTTY sessions");
    let (putty, skipped) = putty_candidates(&sessions);
    summarize("PuTTY", &putty);
    println!("PuTTY skipped: {}", skipped.len());

    use sshcore::import_apps as apps;
    let home = std::path::Path::new(&home);
    let mut others = Vec::new();
    for dir in apps::securecrt_dirs(home) {
        let (found, skipped) = apps::securecrt_candidates(&apps::read_securecrt_dir(&dir).expect("read SecureCRT sessions"));
        summarize("SecureCRT", &found);
        println!("SecureCRT skipped: {}, in folders: {}", skipped.len(), found.iter().filter(|c| c.folder.is_some()).count());
        others.extend(found);
    }
    let moba_files = apps::mobaxterm_files(home);
    for file in &moba_files {
        let (found, skipped) = apps::mobaxterm_candidates(&apps::decode_text(&std::fs::read(file).expect("read MobaXterm.ini")));
        summarize("MobaXterm (ini)", &found);
        println!("MobaXterm skipped: {}", skipped.len());
        others.extend(found);
    }
    let registry = apps::read_mobaxterm_registry();
    if !registry.is_empty() {
        let (found, _) = apps::mobaxterm_candidates(&registry);
        summarize("MobaXterm (registry)", &found);
        others.extend(found);
    }
    println!("SecureCRT folders found: {}, MobaXterm.ini found: {}, MobaXterm registry: {}", apps::securecrt_dirs(home).len(), moba_files.len(), !registry.is_empty());
    let known = apps::known_hosts_path(home);
    let all: Vec<ImportCandidate> = ssh.into_iter().chain(putty).chain(others).collect();
    let with_known = all.iter().filter(|c| apps::known_ed25519(&known, &c.host, c.port).is_some()).count();
    println!("known_hosts exists: {}, candidates with a known Ed25519 key: {with_known}", known.is_file());

    let plan = plan_import(all, &[]);
    println!("planned: {}, duplicates within the scan: {}", plan.len(), plan.iter().filter(|p| p.duplicate.is_some()).count());
}
