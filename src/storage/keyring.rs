use std::sync::Arc;

use keyring_core::{CredentialStore, Entry};
use zeroize::Zeroizing;

use crate::{Error, Result};

const SERVICE: &str = "shieldenv";
const ACCOUNT: &str = "identity";

pub fn save(secret_text: &str) -> Result<()> {
    save_as(ACCOUNT, secret_text)
}

pub fn load() -> Result<Option<Zeroizing<String>>> {
    load_as(ACCOUNT)
}

pub fn save_as(account: &str, secret_text: &str) -> Result<()> {
    entry(account)?
        .set_password(secret_text)
        .map_err(|error| failure(&error))
}

pub fn load_as(account: &str) -> Result<Option<Zeroizing<String>>> {
    match entry(account)?.get_password() {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(error) => Err(failure(&error)),
    }
}

fn entry(account: &str) -> Result<Entry> {
    ensure_store()?;
    Entry::new(SERVICE, account).map_err(|error| failure(&error))
}

fn ensure_store() -> Result<()> {
    if keyring_core::get_default_store().is_none() {
        keyring_core::set_default_store(platform_store()?);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store = zbus_secret_service_keyring_store::Store::new().map_err(|error| failure(&error))?;
    Ok(store)
}

#[cfg(target_os = "macos")]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store =
        apple_native_keyring_store::keychain::Store::new().map_err(|error| failure(&error))?;
    Ok(store)
}

#[cfg(windows)]
fn platform_store() -> Result<Arc<CredentialStore>> {
    let store = windows_native_keyring_store::Store::new().map_err(|error| failure(&error))?;
    Ok(store)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_store() -> Result<Arc<CredentialStore>> {
    Err(Error::Keyring(
        "this platform has no supported keyring".to_owned(),
    ))
}

fn failure(error: &keyring_core::Error) -> Error {
    Error::Keyring(error.to_string())
}

#[cfg(test)]
pub(crate) fn use_mock_store() {
    use std::sync::Once;

    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        if let Ok(store) = keyring_core::mock::Store::new() {
            keyring_core::set_default_store(store);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_round_trip_through_the_keyring() {
        use_mock_store();
        assert!(load_as("round-trip").unwrap().is_none());
        save_as("round-trip", "secret-text").unwrap();
        assert_eq!(
            load_as("round-trip")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("secret-text")
        );
        save_as("round-trip", "replaced").unwrap();
        assert_eq!(
            load_as("round-trip")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("replaced")
        );
    }

    #[test]
    fn accounts_are_isolated() {
        use_mock_store();
        save_as("account-a", "a").unwrap();
        assert!(load_as("account-b").unwrap().is_none());
    }
}
