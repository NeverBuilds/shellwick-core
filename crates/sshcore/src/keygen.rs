//! Generating SSH keys: Ed25519 only, saved as standard OpenSSH files
//! (`name` + `name.pub`) so ssh, git and other tools can use them too.
//! Existing files are never overwritten.

use crate::Error;
use crate::ssh_key::private::{Ed25519Keypair, KeypairData};
use crate::ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A freshly written key pair.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    pub private_path: PathBuf,
    pub public_path: PathBuf,
    /// The `.pub` line: `ssh-ed25519 AAAA… comment`.
    pub public_line: String,
    /// SHA-256 fingerprint of the public key.
    pub fingerprint: String,
}

/// The OS random source, as the RNG ssh-key expects.
fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
    getrandom::rand_core::UnwrapErr(getrandom::SysRng)
}

/// Problem with `name` as a key file name, or `None`.
pub fn check_key_name(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some("Give the key a file name.")
    } else if name.len() > 64 {
        Some("Keep the file name under 64 characters.")
    } else if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        Some("Use only letters, digits, dots, dashes and underscores in the file name.")
    } else if name.starts_with('.') {
        Some("The file name can't start with a dot.")
    } else if name.ends_with(".pub") {
        Some("Leave off .pub: Shellwick adds it for the public key.")
    } else {
        None
    }
}

/// Writes `contents` to a new file, failing if it exists. Private keys get
/// owner-only permissions on Unix (Windows: the profile folder's ACL applies).
fn write_new(path: &Path, contents: &[u8], private: bool) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

/// Generates an Ed25519 key pair in `dir` as `name` and `name.pub`.
/// A non-empty `passphrase` encrypts the private key (OpenSSH format,
/// bcrypt-pbkdf + AES-256-CTR, readable by ssh and by Shellwick).
pub fn generate_ed25519(dir: &Path, name: &str, comment: &str, passphrase: Option<&str>) -> Result<GeneratedKey, Error> {
    if let Some(problem) = check_key_name(name) {
        return Err(Error::KeyGen(problem.into()));
    }
    let private_path = dir.join(name);
    let public_path = dir.join(format!("{name}.pub"));
    if private_path.exists() || public_path.exists() {
        return Err(Error::KeyGen(format!("There's already a key called {name} there. Pick another name.")));
    }

    let mut rng = rng();
    let mut key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)), comment)
        .map_err(|e| Error::KeyGen(format!("Couldn't create the key: {e}")))?;
    let public = key.public_key().clone();
    if let Some(pw) = passphrase.filter(|p| !p.is_empty()) {
        key = key.encrypt(&mut rng, pw).map_err(|e| Error::KeyGen(format!("Couldn't encrypt the key: {e}")))?;
    }
    let private_text = key.to_openssh(LineEnding::LF).map_err(|e| Error::KeyGen(format!("Couldn't encode the key: {e}")))?;
    let public_line = public.to_openssh().map_err(|e| Error::KeyGen(format!("Couldn't encode the key: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;

    write_new(&private_path, private_text.as_bytes(), true)?;
    if let Err(e) = write_new(&public_path, format!("{public_line}\n").as_bytes(), false) {
        let _ = std::fs::remove_file(&private_path);
        return Err(e.into());
    }
    Ok(GeneratedKey {
        private_path,
        public_path,
        public_line,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// The `type base64` part of a public key line (no comment / options), used
/// to tell whether a key is already in an authorized_keys file.
pub fn key_blob(public_line: &str) -> Result<String, Error> {
    let key = PublicKey::from_openssh(public_line.trim()).map_err(|_| Error::KeyGen("That isn't an OpenSSH public key.".into()))?;
    let mut bare = key.clone();
    bare.set_comment("");
    bare.to_openssh().map(|s| s.trim().to_string()).map_err(|e| Error::KeyGen(e.to_string()))
}

/// Whether `authorized_keys` already lists the key with blob `blob`
/// (`type base64`), with or without options and comments.
pub fn authorized_keys_contains(authorized_keys: &str, blob: &str) -> bool {
    let Some(b64) = blob.split_whitespace().nth(1) else { return false };
    authorized_keys
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| l.split_whitespace().any(|tok| tok == b64))
}

/// What to append to an authorized_keys file whose current content is
/// `existing` so that `public_line` ends up on its own line.
pub fn authorized_keys_append(existing: &str, public_line: &str) -> String {
    let sep = if existing.is_empty() || existing.ends_with('\n') { "" } else { "\n" };
    format!("{sep}{}\n", public_line.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("shellwick-keygen-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn names_are_plain_file_names() {
        assert_eq!(check_key_name("id_ed25519_shellwick"), None);
        assert_eq!(check_key_name("work-2026.key"), None);
        assert!(check_key_name("").is_some());
        assert!(check_key_name("../evil").is_some());
        assert!(check_key_name("a/b").is_some());
        assert!(check_key_name("C:\\x").is_some());
        assert!(check_key_name(".hidden").is_some());
        assert!(check_key_name("key.pub").is_some());
        assert!(check_key_name(&"x".repeat(65)).is_some());
    }

    #[test]
    fn generates_a_usable_unencrypted_key() {
        let dir = temp_dir("plain");
        let k = generate_ed25519(&dir, "id_test", "me@box", None).unwrap();
        let text = std::fs::read_to_string(&k.private_path).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // russh (what Shellwick connects with) reads it back, without a passphrase.
        let loaded = russh::keys::load_secret_key(&k.private_path, None).unwrap();
        assert_eq!(loaded.public_key().fingerprint(HashAlg::Sha256).to_string(), k.fingerprint);
        let pub_file = std::fs::read_to_string(&k.public_path).unwrap();
        assert_eq!(pub_file.trim(), k.public_line);
        assert!(k.public_line.starts_with("ssh-ed25519 ") && k.public_line.ends_with(" me@box"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn passphrase_encrypts_the_file() {
        let dir = temp_dir("enc");
        let k = generate_ed25519(&dir, "id_test", "", Some("correct horse")).unwrap();
        assert!(russh::keys::load_secret_key(&k.private_path, None).is_err(), "must not open without the passphrase");
        assert!(russh::keys::load_secret_key(&k.private_path, Some("wrong")).is_err());
        let loaded = russh::keys::load_secret_key(&k.private_path, Some("correct horse")).unwrap();
        assert_eq!(loaded.public_key().fingerprint(HashAlg::Sha256).to_string(), k.fingerprint);
        // An empty passphrase means none.
        let k2 = generate_ed25519(&dir, "id_test2", "", Some("")).unwrap();
        assert!(russh::keys::load_secret_key(&k2.private_path, None).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn never_overwrites() {
        let dir = temp_dir("exists");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("taken.pub"), "keep me").unwrap();
        let err = generate_ed25519(&dir, "taken", "", None).unwrap_err().to_string();
        assert_eq!(err, "There's already a key called taken there. Pick another name.");
        assert_eq!(std::fs::read_to_string(dir.join("taken.pub")).unwrap(), "keep me");
        assert!(!dir.join("taken").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn authorized_keys_matching_ignores_comments_and_options() {
        let mut public = PublicKey::from(Ed25519Keypair::from_seed(&[9; 32]).public);
        public.set_comment("me@box");
        let line = public.to_openssh().unwrap();
        let b64 = line.split_whitespace().nth(1).unwrap().to_string();
        let blob = key_blob(&line).unwrap();
        assert_eq!(blob, format!("ssh-ed25519 {b64}"));
        let file = format!("# mine\nssh-rsa AAAAB3Nza other\nfrom=\"10.0.0.0/8\" ssh-ed25519 {b64} old-comment\n");
        assert!(authorized_keys_contains(&file, &blob));
        assert!(!authorized_keys_contains("ssh-rsa AAAAB3Nza other\n", &blob));
        assert!(!authorized_keys_contains(&format!("# ssh-ed25519 {b64}\n"), &blob));
        assert!(key_blob("not a key").is_err());
    }

    #[test]
    fn appended_key_lands_on_its_own_line() {
        assert_eq!(authorized_keys_append("", "k1 x"), "k1 x\n");
        assert_eq!(authorized_keys_append("k0 y\n", "k1 x"), "k1 x\n");
        assert_eq!(authorized_keys_append("k0 y", " k1 x \n"), "\nk1 x\n");
    }
}
