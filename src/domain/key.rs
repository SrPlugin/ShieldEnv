use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretKey(String);

impl SecretKey {
    pub const MAX_LEN: usize = 128;

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(candidate: &str) -> bool {
        let mut bytes = candidate.bytes();
        candidate.len() <= Self::MAX_LEN
            && bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }
}

impl FromStr for SecretKey {
    type Err = Error;

    fn from_str(candidate: &str) -> Result<Self> {
        if Self::is_valid(candidate) {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(Error::InvalidKey(candidate.to_owned()))
        }
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for SecretKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for SecretKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_posix_names() {
        for name in ["A", "_", "API_KEY", "db_url_2", "_PRIVATE"] {
            assert_eq!(name.parse::<SecretKey>().unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_invalid_names() {
        let too_long = "A".repeat(SecretKey::MAX_LEN + 1);
        for name in [
            "", "1KEY", "API-KEY", "API KEY", "KEY=1", "KEY\n", "KEY\0", "CLÉ", "../x", &too_long,
        ] {
            assert!(name.parse::<SecretKey>().is_err(), "{name:?} accepted");
        }
    }

    #[test]
    fn accepts_maximum_length() {
        let name = "A".repeat(SecretKey::MAX_LEN);
        assert!(name.parse::<SecretKey>().is_ok());
    }
}
