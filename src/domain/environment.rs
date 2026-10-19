use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Environment(String);

impl Environment {
    pub const DEFAULT: &str = "dev";
    pub const MAX_LEN: usize = 64;
    const RESERVED: [&str; 4] = ["con", "prn", "aux", "nul"];

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(candidate: &str) -> bool {
        let mut bytes = candidate.bytes();
        candidate.len() <= Self::MAX_LEN
            && !Self::is_reserved_device(candidate)
            && bytes
                .next()
                .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    }
}

impl Environment {
    fn is_reserved_device(candidate: &str) -> bool {
        let numbered = |prefix: &str| {
            candidate.strip_prefix(prefix).is_some_and(|rest| {
                rest.len() == 1 && rest.bytes().all(|byte| byte.is_ascii_digit())
            })
        };
        Self::RESERVED.contains(&candidate) || numbered("com") || numbered("lpt")
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

impl FromStr for Environment {
    type Err = Error;

    fn from_str(candidate: &str) -> Result<Self> {
        if Self::is_valid(candidate) {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(Error::InvalidEnvironment(candidate.to_owned()))
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_dev() {
        assert_eq!(Environment::default().as_str(), "dev");
    }

    #[test]
    fn accepts_safe_names() {
        for name in [
            "dev",
            "production",
            "staging-eu",
            "qa_2",
            "1",
            "console",
            "com10",
        ] {
            assert_eq!(name.parse::<Environment>().unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_path_traversal_and_unsafe_names() {
        let too_long = "a".repeat(Environment::MAX_LEN + 1);
        for name in [
            "",
            "..",
            "../x",
            "a/b",
            "a\\b",
            ".hidden",
            "-flag",
            "_x",
            "Prod",
            "dev ",
            "dev\0",
            "dév",
            "con.vault",
            "con",
            "nul",
            "com1",
            "lpt9",
            &too_long,
        ] {
            assert!(name.parse::<Environment>().is_err(), "{name:?} accepted");
        }
    }
}
