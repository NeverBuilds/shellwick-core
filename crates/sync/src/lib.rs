//! Shellwick sync: an encrypted file in a folder the user's own sync tool keeps
//! in step (OneDrive, iCloud Drive, Dropbox, Syncthing, a NAS share). No
//! server, no network code. The app reads the file, merges it with what it
//! has, and writes it back.
//!
//! - [`merge`]: per-item last-writer-wins sets with deletion markers.
//! - [`crypt`]: the envelope (Argon2id + AES-256-GCM).
//! - [`SyncDoc`]: what is inside: servers and snippets. Never secrets:
//!   passwords and passphrases stay in each device's keychain.

pub mod crypt;
pub mod merge;

pub use crypt::{check_passphrase, CryptError, SyncKey};
pub use merge::{Changes, Entry};

use serde::{Deserialize, Serialize};

/// The default file name inside the chosen folder.
pub const FILE_NAME: &str = "shellwick-sync.json";
/// Document format inside the envelope.
pub const DOC_FORMAT: u32 = 1;

/// The decrypted contents.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncDoc {
    pub v: u32,
    #[serde(default)]
    pub hosts: Vec<Entry>,
    #[serde(default)]
    pub snippets: Vec<Entry>,
    /// Collections a newer version added; kept as they were.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl SyncDoc {
    pub fn new(hosts: Vec<Entry>, snippets: Vec<Entry>) -> Self {
        Self { v: DOC_FORMAT, hosts, snippets, extra: serde_json::Map::new() }
    }

    /// Item-by-item merge of both collections (see [`merge::merge`]).
    pub fn merge(&self, other: &SyncDoc) -> SyncDoc {
        let mut extra = other.extra.clone();
        for (k, v) in &self.extra {
            extra.entry(k.clone()).or_insert_with(|| v.clone());
        }
        SyncDoc { v: DOC_FORMAT, hosts: merge::merge(&self.hosts, &other.hosts), snippets: merge::merge(&self.snippets, &other.snippets), extra }
    }
}

/// Encrypts a document into sync-file bytes.
pub fn seal_doc(doc: &SyncDoc, key: &SyncKey) -> Result<Vec<u8>, CryptError> {
    let plain = serde_json::to_vec(doc).map_err(|e| CryptError::Internal(e.to_string()))?;
    crypt::seal(&plain, key)
}

/// Decrypts sync-file bytes (see [`crypt::open`] for the key cache).
pub fn open_doc(bytes: &[u8], passphrase: &str, cached: Option<&SyncKey>) -> Result<(SyncDoc, SyncKey), CryptError> {
    let (plain, key) = crypt::open(bytes, passphrase, cached)?;
    let value: serde_json::Value = serde_json::from_slice(&plain).map_err(|_| CryptError::Damaged)?;
    if value.get("v").and_then(|v| v.as_u64()).is_some_and(|v| v > u64::from(DOC_FORMAT)) {
        return Err(CryptError::NewerFormat);
    }
    let doc = serde_json::from_value(value).map_err(|_| CryptError::Damaged)?;
    Ok((doc, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn doc_round_trip_and_merge() {
        let key = crypt::test_key("a long sync passphrase");
        let laptop = SyncDoc::new(vec![Entry::live("h1", 10, json!({"name": "api"}))], vec![Entry::live("s1", 10, json!({"name": "df"}))]);
        let bytes = seal_doc(&laptop, &key).unwrap();
        let (back, _) = open_doc(&bytes, "a long sync passphrase", None).unwrap();
        assert_eq!(back, laptop);

        let desktop = SyncDoc::new(vec![Entry::live("h2", 20, json!({"name": "db"})), Entry::tombstone("h1", 30)], vec![]);
        let merged = laptop.merge(&desktop);
        assert_eq!(merge::live(&merged.hosts).len(), 1, "h1 was deleted later on the desktop");
        assert_eq!(merge::live(&merged.snippets).len(), 1);
        assert_eq!(merged, desktop.merge(&laptop));
    }

    #[test]
    fn unknown_collections_survive() {
        let key = crypt::test_key("a long sync passphrase");
        let plain = br#"{"v":1,"hosts":[],"snippets":[],"themes":[{"id":"t","modified":1}]}"#;
        let bytes = crypt::seal(plain, &key).unwrap();
        let (doc, _) = open_doc(&bytes, "a long sync passphrase", None).unwrap();
        let merged = doc.merge(&SyncDoc::new(vec![], vec![]));
        assert!(merged.extra.contains_key("themes"));
        let newer = crypt::seal(br#"{"v":2}"#, &key).unwrap();
        assert_eq!(open_doc(&newer, "a long sync passphrase", None).unwrap_err(), CryptError::NewerFormat);
    }
}
