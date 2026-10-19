use std::str::FromStr;

use super::SecretKey;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern(String);

impl Pattern {
    #[must_use]
    pub fn matches(&self, key: &SecretKey) -> bool {
        wildcard_match(self.0.as_bytes(), key.as_str().as_bytes())
    }
}

impl FromStr for Pattern {
    type Err = Error;

    fn from_str(candidate: &str) -> Result<Self> {
        let valid = !candidate.is_empty()
            && candidate.len() <= SecretKey::MAX_LEN
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'*' | b'?'));
        if valid {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(Error::InvalidPattern(candidate.to_owned()))
        }
    }
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pattern_index, mut text_index) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while text_index < text.len() {
        match pattern.get(pattern_index) {
            Some(b'*') => {
                backtrack = Some((pattern_index, text_index));
                pattern_index += 1;
            }
            Some(&expected) if expected == b'?' || text.get(text_index) == Some(&expected) => {
                pattern_index += 1;
                text_index += 1;
            }
            _ => match backtrack {
                Some((star, consumed)) => {
                    pattern_index = star + 1;
                    text_index = consumed + 1;
                    backtrack = Some((star, consumed + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(pattern_index..)
        .is_some_and(|rest| rest.iter().all(|&byte| byte == b'*'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn matches(pattern: &str, key: &str) -> bool {
        pattern
            .parse::<Pattern>()
            .unwrap()
            .matches(&key.parse().unwrap())
    }

    #[test]
    fn matches_literals_and_wildcards() {
        assert!(matches("API_KEY", "API_KEY"));
        assert!(!matches("API_KEY", "API_KEYS"));
        assert!(matches("DB_*", "DB_URL"));
        assert!(matches("DB_*", "DB_"));
        assert!(!matches("DB_*", "XDB_URL"));
        assert!(matches("*_URL", "DATABASE_URL"));
        assert!(matches("*", "ANYTHING"));
        assert!(matches("A?C", "ABC"));
        assert!(!matches("A?C", "AC"));
        assert!(matches("*A*B*", "XXAYYBZZ"));
        assert!(!matches("*A*B*", "XXBYYAZZ"));
        assert!(matches("**", "K"));
    }

    #[test]
    fn rejects_invalid_patterns() {
        for pattern in ["", "DB-*", "a/b", "[A]", "K\n"] {
            assert!(pattern.parse::<Pattern>().is_err(), "{pattern:?} accepted");
        }
    }

    proptest! {
        #[test]
        fn star_matches_every_key(key in "[A-Za-z_][A-Za-z0-9_]{0,40}") {
            prop_assert!(matches("*", &key));
            prop_assert!(matches(&key, &key));
        }

        #[test]
        fn prefix_pattern_matches_extensions(prefix in "[A-Z_]{1,10}", suffix in "[A-Z0-9_]{0,10}") {
            let key = format!("{prefix}{suffix}");
            let pattern = format!("{prefix}*");
            prop_assert!(matches(&pattern, &key));
        }
    }
}
