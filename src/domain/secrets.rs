use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::SecretKey;
use crate::{Error, Result};

pub type SecretValue = Zeroizing<String>;

#[derive(Debug, Default)]
pub struct Secrets(BTreeMap<SecretKey, SecretValue>);

impl Secrets {
    pub const MAX_ENTRIES: usize = 10_000;
    pub const MAX_VALUE_LEN: usize = 1 << 20;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: SecretKey, value: SecretValue) -> Result<bool> {
        Self::validate_value(&value)?;
        if !self.0.contains_key(&key) && self.0.len() >= Self::MAX_ENTRIES {
            return Err(Error::LimitExceeded("too many secrets in one vault"));
        }
        Ok(self.0.insert(key, value).is_some())
    }

    pub fn remove(&mut self, key: &str) -> Option<SecretValue> {
        self.0.remove(key)
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|value| value.as_str())
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
        self.0.iter().map(|(key, value)| (key, value.as_str()))
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
