use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretKey(String);

const HOOK_PREFIXES: [&str; 2] = ["LD_", "DYLD_"];
const HOOKS: [&str; 24] = [
    "PATH",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PROMPT_COMMAND",
    "PS4",
    "IFS",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];
const GIT_HOOKS: [&str; 5] = [
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
];

impl SecretKey {
    pub const MAX_LEN: usize = 128;

    #[must_use]
    pub fn is_process_hook(&self) -> bool {
        HOOK_PREFIXES
            .iter()
            .any(|prefix| self.0.starts_with(prefix))
            || HOOKS.contains(&self.0.as_str())
            || GIT_HOOKS.contains(&self.0.as_str())
    }

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
    fn recognizes_variables_that_change_how_programs_load_code() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "BASH_ENV",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "JAVA_TOOL_OPTIONS",
            "GIT_SSH_COMMAND",
        ] {
            assert!(
                name.parse::<SecretKey>().unwrap().is_process_hook(),
                "{name}"
            );
        }
        for name in [
            "API_KEY",
            "DATABASE_URL",
            "OLD_PATH",
            "PATHS",
            "LDAP_URL",
            "NODE_ENV",
        ] {
            assert!(
                !name.parse::<SecretKey>().unwrap().is_process_hook(),
                "{name}"
            );
        }
    }

    #[test]
    fn accepts_maximum_length() {
        let name = "A".repeat(SecretKey::MAX_LEN);
        assert!(name.parse::<SecretKey>().is_ok());
    }
}
