use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberName(String);

impl MemberName {
    pub const MAX_LEN: usize = 64;

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(candidate: &str) -> bool {
        let mut bytes = candidate.bytes();
        candidate.len() <= Self::MAX_LEN
            && bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphanumeric())
            && bytes.all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-')
            })
    }
}

impl FromStr for MemberName {
    type Err = Error;

    fn from_str(candidate: &str) -> Result<Self> {
        if Self::is_valid(candidate) {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(Error::InvalidMemberName(candidate.to_owned()))
        }
    }
}

impl fmt::Display for MemberName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_emails_and_handles() {
        for name in [
            "ana",
            "ana@empresa.com",
            "ci-prod",
            "dev_2",
            "a+b@x.io",
            "7",
        ] {
            assert_eq!(name.parse::<MemberName>().unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_unsafe_names() {
        let too_long = "a".repeat(MemberName::MAX_LEN + 1);
        for name in [
            "", "-flag", ".hidden", "a b", "a/b", "a\nb", "a\0", "ánna", "a:b", &too_long,
        ] {
            assert!(name.parse::<MemberName>().is_err(), "{name:?}");
        }
        assert!(
            "a".repeat(MemberName::MAX_LEN)
                .parse::<MemberName>()
                .is_ok()
        );
    }
}
