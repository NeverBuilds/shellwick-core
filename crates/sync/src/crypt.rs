//! The sync file on disk: a small JSON envelope around the encrypted document.
//!
//! ```json
//! { "shellwick_sync": 1,
//!   "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<b64>" },
//!   "nonce": "<b64>", "ciphertext": "<b64>" }
//! ```
//!
//! The key is Argon2id(passphrase, salt); the document is AES-256-GCM
//! encrypted with a fresh random nonce on every write. The header (format and
//! KDF parameters) is authenticated as associated data, so it can't be
//! swapped without decryption failing. Only the envelope is plain text: no
//! server names, addresses or users are readable without the passphrase.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Envelope format this build writes and reads.
pub const ENVELOPE: u32 = 1;
/// Passphrases shorter than this are refused when a sync file is created.
pub const MIN_PASSPHRASE: usize = 10;

/// Argon2id cost: 64 MiB, 3 passes (well above OWASP's minimum; about half a
/// second on a laptop, once per session since the key is kept in memory).
const DEFAULT_M: u32 = 64 * 1024;
const DEFAULT_T: u32 = 3;
const DEFAULT_P: u32 = 1;
/// Limits on what a file may ask for, so a hostile file can't exhaust memory.
const MAX_M: u32 = 1024 * 1024;
const MAX_T: u32 = 10;
const MAX_P: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    shellwick_sync: u32,
    kdf: Kdf,
    nonce: String,
    ciphertext: String,
}

/// A key derived from the passphrase for one sync file (its salt and cost).
/// Kept in memory so each sync doesn't pay for Argon2 again.
#[derive(Clone)]
pub struct SyncKey {
    key: [u8; 32],
    kdf: Kdf,
}

impl fmt::Debug for SyncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("SyncKey").field("kdf", &self.kdf).finish_non_exhaustive()
    }
}

impl SyncKey {
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }
}

/// Why a sync file couldn't be read or written. `Display` is user-facing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptError {
    WeakPassphrase,
    WrongPassphrase,
    NotSyncFile,
    Damaged,
    NewerFormat,
    Internal(String),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::WeakPassphrase => write!(f, "Use a sync passphrase of at least {MIN_PASSPHRASE} characters."),
            CryptError::WrongPassphrase => f.write_str("The sync passphrase doesn't match this sync file. Use the passphrase you chose on your first device."),
            CryptError::NotSyncFile => f.write_str("That file isn't a Shellwick sync file."),
            CryptError::Damaged => f.write_str("The sync file is damaged or incomplete. If your sync service is still downloading it, wait a moment and try again."),
            CryptError::NewerFormat => f.write_str("This sync file was written by a newer version of Shellwick. Update Shellwick on this device."),
            CryptError::Internal(e) => write!(f, "Couldn't encrypt the sync file ({e})."),
        }
    }
}

impl std::error::Error for CryptError {}

/// Refuses passphrases that are too short (counted in characters, not bytes).
pub fn check_passphrase(passphrase: &str) -> Result<(), CryptError> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(CryptError::WeakPassphrase);
    }
    Ok(())
}

/// A key for a new sync file: random salt, default cost.
pub fn new_key(passphrase: &str) -> Result<SyncKey, CryptError> {
    check_passphrase(passphrase)?;
    new_key_with(passphrase, DEFAULT_M, DEFAULT_T, DEFAULT_P)
}

fn new_key_with(passphrase: &str, m: u32, t: u32, p: u32) -> Result<SyncKey, CryptError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| CryptError::Internal(e.to_string()))?;
    let kdf = Kdf { alg: "argon2id".into(), m, t, p, salt: STANDARD.encode(salt) };
    derive(passphrase, &kdf)
}

fn derive(passphrase: &str, kdf: &Kdf) -> Result<SyncKey, CryptError> {
    if kdf.alg != "argon2id" {
        return Err(CryptError::NewerFormat);
    }
    if kdf.m > MAX_M || kdf.t > MAX_T || kdf.p > MAX_P || kdf.t == 0 || kdf.p == 0 {
        return Err(CryptError::Damaged);
    }
    let salt = STANDARD.decode(&kdf.salt).map_err(|_| CryptError::Damaged)?;
    let params = argon2::Params::new(kdf.m, kdf.t, kdf.p, Some(32)).map_err(|_| CryptError::Damaged)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(passphrase.as_bytes(), &salt, &mut key).map_err(|_| CryptError::Damaged)?;
    Ok(SyncKey { key, kdf: kdf.clone() })
}

/// What the header authenticates: format and KDF parameters.
fn aad(kdf: &Kdf) -> Vec<u8> {
    // serde_json writes struct fields in declaration order: stable bytes.
    serde_json::to_vec(&(ENVELOPE, kdf)).unwrap_or_default()
}

/// Encrypts `plaintext` into the envelope bytes (fresh nonce every time).
pub fn seal(plaintext: &[u8], key: &SyncKey) -> Result<Vec<u8>, CryptError> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| CryptError::Internal(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&key.key).map_err(|e| CryptError::Internal(e.to_string()))?;
    let aad = aad(&key.kdf);
    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: plaintext, aad: &aad })
        .map_err(|e| CryptError::Internal(e.to_string()))?;
    let env = Envelope { shellwick_sync: ENVELOPE, kdf: key.kdf.clone(), nonce: STANDARD.encode(nonce), ciphertext: STANDARD.encode(ciphertext) };
    serde_json::to_vec_pretty(&env).map_err(|e| CryptError::Internal(e.to_string()))
}

/// The KDF parameters of a sync file, read without the passphrase.
pub fn kdf_of(bytes: &[u8]) -> Result<Kdf, CryptError> {
    Ok(envelope(bytes)?.kdf)
}

fn envelope(bytes: &[u8]) -> Result<Envelope, CryptError> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        // Half-downloaded JSON vs. something else entirely.
        if bytes.trim_ascii_start().starts_with(b"{") { CryptError::Damaged } else { CryptError::NotSyncFile }
    })?;
    let Some(format) = v.get("shellwick_sync").and_then(|f| f.as_u64()) else { return Err(CryptError::NotSyncFile) };
    if format > u64::from(ENVELOPE) {
        return Err(CryptError::NewerFormat);
    }
    serde_json::from_value(v).map_err(|_| CryptError::Damaged)
}

/// Decrypts a sync file. Reuses `cached` when it was derived for this file's
/// salt and cost; otherwise derives a key from `passphrase`. Returns the
/// plaintext and the key to cache.
pub fn open(bytes: &[u8], passphrase: &str, cached: Option<&SyncKey>) -> Result<(Vec<u8>, SyncKey), CryptError> {
    let env = envelope(bytes)?;
    let key = match cached {
        Some(k) if k.kdf == env.kdf => k.clone(),
        _ => derive(passphrase, &env.kdf)?,
    };
    let nonce: [u8; 12] = STANDARD.decode(&env.nonce).ok().and_then(|n| n.try_into().ok()).ok_or(CryptError::Damaged)?;
    let ciphertext = STANDARD.decode(&env.ciphertext).map_err(|_| CryptError::Damaged)?;
    let cipher = Aes256Gcm::new_from_slice(&key.key).map_err(|e| CryptError::Internal(e.to_string()))?;
    let aad = aad(&env.kdf);
    // GCM can't tell a wrong key from altered bytes; a wrong passphrase is by
    // far the likelier cause when the envelope itself parsed.
    let plaintext = cipher.decrypt(&nonce.into(), Payload { msg: &ciphertext, aad: &aad }).map_err(|_| CryptError::WrongPassphrase)?;
    Ok((plaintext, key))
}

#[cfg(test)]
pub(crate) fn test_key(passphrase: &str) -> SyncKey {
    // Cheap cost so tests stay fast; the format is the same.
    new_key_with(passphrase, 1024, 1, 1).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";

    #[test]
    fn round_trip_with_fresh_nonces() {
        let key = test_key(PASS);
        let a = seal(b"hello sync", &key).unwrap();
        let b = seal(b"hello sync", &key).unwrap();
        assert_ne!(a, b, "a new nonce on every write");
        let (plain, k2) = open(&a, PASS, None).unwrap();
        assert_eq!(plain, b"hello sync");
        assert_eq!(k2.kdf(), key.kdf());
        // The cached key is reused (wrong passphrase text doesn't matter then).
        assert_eq!(open(&b, "ignored", Some(&key)).unwrap().0, b"hello sync");
        let text = String::from_utf8(a).unwrap();
        assert!(!text.contains("hello"), "the document is not readable in the file");
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_refused() {
        let key = test_key(PASS);
        let bytes = seal(b"servers", &key).unwrap();
        assert_eq!(open(&bytes, "wrong passphrase!", None).unwrap_err(), CryptError::WrongPassphrase);
        // Flip one ciphertext byte.
        let mut env: Envelope = serde_json::from_slice(&bytes).unwrap();
        let mut ct = STANDARD.decode(&env.ciphertext).unwrap();
        ct[0] ^= 1;
        env.ciphertext = STANDARD.encode(ct);
        assert!(open(&serde_json::to_vec(&env).unwrap(), PASS, Some(&key)).is_err());
        // Change the authenticated header (cost) but keep the ciphertext.
        let mut env: Envelope = serde_json::from_slice(&bytes).unwrap();
        env.kdf.t = 2;
        assert!(open(&serde_json::to_vec(&env).unwrap(), PASS, None).is_err());
    }

    #[test]
    fn plain_language_for_bad_files() {
        let key = test_key(PASS);
        let bytes = seal(b"x", &key).unwrap();
        assert_eq!(open(&bytes[..bytes.len() / 2], PASS, None).unwrap_err(), CryptError::Damaged, "half downloaded");
        assert_eq!(open(b"hello", PASS, None).unwrap_err(), CryptError::NotSyncFile);
        assert_eq!(open(br#"{"other":"json"}"#, PASS, None).unwrap_err(), CryptError::NotSyncFile);
        let newer = br#"{"shellwick_sync":2,"kdf":{},"nonce":"","ciphertext":""}"#;
        assert_eq!(open(newer, PASS, None).unwrap_err(), CryptError::NewerFormat);
        let greedy = br#"{"shellwick_sync":1,"kdf":{"alg":"argon2id","m":99999999,"t":3,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"nonce":"","ciphertext":""}"#;
        assert_eq!(open(greedy, PASS, None).unwrap_err(), CryptError::Damaged, "refuses absurd memory cost");
        assert!(CryptError::WrongPassphrase.to_string().starts_with("The sync passphrase doesn't match"));
    }

    #[test]
    fn short_passphrases_are_refused() {
        assert_eq!(check_passphrase("short").unwrap_err(), CryptError::WeakPassphrase);
        assert_eq!(check_passphrase("九个字的中文密码短").unwrap_err(), CryptError::WeakPassphrase, "9 characters (27 bytes)");
        assert!(check_passphrase("十个字的中文密码短语").is_ok(), "10 characters");
        assert_eq!(new_key("too short").unwrap_err(), CryptError::WeakPassphrase);
        assert_eq!(CryptError::WeakPassphrase.to_string(), "Use a sync passphrase of at least 10 characters.");
    }

    #[test]
    fn default_cost_is_what_new_files_get() {
        // Slow-ish (real Argon2 cost), run once.
        let key = new_key(PASS).unwrap();
        assert_eq!((key.kdf().m, key.kdf().t, key.kdf().p), (DEFAULT_M, DEFAULT_T, DEFAULT_P));
        assert!(!format!("{key:?}").contains("key:"), "Debug never shows the key");
    }
}
