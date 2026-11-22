//! OS credential store (macOS Keychain / Windows Credential Manager / Linux Secret Service).
//! Config files only ever hold host ids; the secret is looked up here at connect time.

use keyring::Entry;

const SERVICE: &str = "app.shellwick";

#[derive(Debug, thiserror::Error)]
#[error("credential store: {0}")]
pub struct CredError(#[from] keyring::Error);

fn entry(host_id: &str, kind: &str) -> Result<Entry, CredError> {
    Ok(Entry::new(SERVICE, &format!("{host_id}:{kind}"))?)
}

pub fn set(host_id: &str, kind: &str, secret: &str) -> Result<(), CredError> {
    entry(host_id, kind)?.set_password(secret)?;
    Ok(())
}

pub fn get(host_id: &str, kind: &str) -> Result<Option<String>, CredError> {
    match entry(host_id, kind)?.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn delete(host_id: &str, kind: &str) -> Result<(), CredError> {
    match entry(host_id, kind)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Convenience: load everything a host might need.
pub fn secrets_for(host_id: &str) -> Result<crate::Secrets, CredError> {
    Ok(crate::Secrets {
        password: get(host_id, "password")?,
        key_passphrase: get(host_id, "passphrase")?,
        proxy_password: get(host_id, "proxy_password")?,
    })
}
