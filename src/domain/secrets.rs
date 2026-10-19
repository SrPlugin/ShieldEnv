use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::SecretKey;
use crate::{Error, Result};

pub type SecretValue = Zeroizing<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretMeta {
    pub created: u64,
    pub updated: u64,
}

#[derive(Debug)]
struct Entry {
    value: SecretValue,
    meta: SecretMeta,
}

#[derive(Debug, Default)]
pub struct Secrets(BTreeMap<SecretKey, Entry>);

impl Secrets {
    pub const MAX_ENTRIES: usize = 10_000;
    pub const MAX_VALUE_LEN: usize = 1 << 20;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: SecretKey, value: SecretValue) -> Result<bool> {
        self.insert_at(key, value, unix_now())
    }

    pub fn insert_at(&mut self, key: SecretKey, value: SecretValue, now: u64) -> Result<bool> {
        let created = self.0.get(&key).map_or(now, |entry| entry.meta.created);
        self.store(
            key,
            value,
            SecretMeta {
                created,
                updated: now,
            },
        )
    }

    pub fn restore(&mut self, key: SecretKey, value: SecretValue, meta: SecretMeta) -> Result<()> {
        self.store(key, value, meta).map(drop)
    }

    pub fn rename(&mut self, old: &str, new: SecretKey) -> Result<()> {
        let entry = self
            .0
            .remove(old)
            .ok_or_else(|| Error::KeyNotFound(old.to_owned()))?;
        self.0.insert(new, entry);
        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> Option<SecretValue> {
        self.0.remove(key).map(|entry| entry.value)
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|entry| entry.value.as_str())
    }

    #[must_use]
    pub fn meta(&self, key: &str) -> Option<SecretMeta> {
        self.0.get(key).map(|entry| entry.meta)
    }

    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &SecretKey> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SecretKey, &str)> {
        self.0
            .iter()
            .map(|(key, entry)| (key, entry.value.as_str()))
    }

    pub fn iter_with_meta(&self) -> impl Iterator<Item = (&SecretKey, &str, SecretMeta)> {
        self.0
            .iter()
            .map(|(key, entry)| (key, entry.value.as_str(), entry.meta))
    }

    pub fn updated_before(&self, cutoff: u64) -> impl Iterator<Item = (&SecretKey, SecretMeta)> {
        self.0
            .iter()
            .filter(move |(_, entry)| entry.meta.updated <= cutoff)
            .map(|(key, entry)| (key, entry.meta))
    }

    fn store(&mut self, key: SecretKey, value: SecretValue, meta: SecretMeta) -> Result<bool> {
        Self::validate_value(&value)?;
        if !self.0.contains_key(&key) && self.0.len() >= Self::MAX_ENTRIES {
            return Err(Error::LimitExceeded("too many secrets in one vault"));
        }
        Ok(self.0.insert(key, Entry { value, meta }).is_some())
    }

    fn validate_value(value: &str) -> Result<()> {
        if value.len() > Self::MAX_VALUE_LEN {
            return Err(Error::LimitExceeded("secret value larger than 1 MiB"));
        }
        if value.contains('\0') {
            return Err(Error::InvalidValue("values cannot contain NUL bytes"));
        }
        Ok(())
    }
}

#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> SecretKey {
        name.parse().unwrap()
    }

    fn value(text: &str) -> SecretValue {
        Zeroizing::new(text.to_owned())
    }

    #[test]
    fn insert_reports_replacement() {
        let mut secrets = Secrets::new();
        assert!(!secrets.insert(key("A"), value("1")).unwrap());
        assert!(secrets.insert(key("A"), value("2")).unwrap());
        assert_eq!(secrets.get("A"), Some("2"));
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn keys_are_sorted() {
        let mut secrets = Secrets::new();
        for name in ["C", "A", "B"] {
            secrets.insert(key(name), value(name)).unwrap();
        }
        let keys: Vec<_> = secrets.keys().map(SecretKey::as_str).collect();
        assert_eq!(keys, ["A", "B", "C"]);
    }

    #[test]
    fn remove_returns_value() {
        let mut secrets = Secrets::new();
        secrets.insert(key("A"), value("1")).unwrap();
        assert_eq!(
            secrets.remove("A").as_deref().map(String::as_str),
            Some("1")
        );
        assert!(secrets.is_empty());
        assert!(secrets.remove("A").is_none());
    }

    #[test]
    fn timestamps_track_creation_and_updates() {
        let mut secrets = Secrets::new();
        secrets.insert_at(key("A"), value("1"), 100).unwrap();
        assert_eq!(
            secrets.meta("A"),
            Some(SecretMeta {
                created: 100,
                updated: 100
            })
        );
        secrets.insert_at(key("A"), value("2"), 250).unwrap();
        assert_eq!(
            secrets.meta("A"),
            Some(SecretMeta {
                created: 100,
                updated: 250
            })
        );
        assert!(secrets.meta("B").is_none());
    }

    #[test]
    fn updated_before_selects_stale_secrets() {
        let mut secrets = Secrets::new();
        secrets.insert_at(key("OLD"), value("v"), 100).unwrap();
        secrets.insert_at(key("EDGE"), value("v"), 200).unwrap();
        secrets.insert_at(key("NEW"), value("v"), 300).unwrap();
        let stale: Vec<_> = secrets
            .updated_before(200)
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(stale, ["EDGE", "OLD"]);
        assert_eq!(secrets.updated_before(0).count(), 0);
    }

    #[test]
    fn rename_keeps_value_and_timestamps() {
        let mut secrets = Secrets::new();
        secrets.insert_at(key("OLD"), value("v"), 7).unwrap();
        secrets.rename("OLD", key("NEW")).unwrap();
        assert!(!secrets.contains("OLD"));
        assert_eq!(secrets.get("NEW"), Some("v"));
        assert_eq!(secrets.meta("NEW").map(|meta| meta.created), Some(7));
        assert!(matches!(
            secrets.rename("OLD", key("OTHER")),
            Err(Error::KeyNotFound(_))
        ));
    }

    #[test]
    fn rejects_nul_and_oversized_values() {
        let mut secrets = Secrets::new();
        assert!(secrets.insert(key("A"), value("a\0b")).is_err());
        let oversized = "x".repeat(Secrets::MAX_VALUE_LEN + 1);
        assert!(secrets.insert(key("A"), value(&oversized)).is_err());
        let maximum = "x".repeat(Secrets::MAX_VALUE_LEN);
        assert!(secrets.insert(key("A"), value(&maximum)).is_ok());
    }

    #[test]
    fn enforces_entry_limit_for_new_keys_only() {
        let mut secrets = Secrets::new();
        for index in 0..Secrets::MAX_ENTRIES {
            secrets
                .insert(key(&format!("K{index}")), value(""))
                .unwrap();
        }
        assert!(matches!(
            secrets.insert(key("EXTRA"), value("")),
            Err(Error::LimitExceeded(_))
        ));
        assert!(secrets.insert(key("K0"), value("updated")).unwrap());
    }
}
