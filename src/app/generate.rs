use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::{Error, Result};

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 1024;

const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const BASE64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Charset {
    #[default]
    Alphanumeric,
    Hex,
    Base64Url,
}

impl Charset {
    fn alphabet(self) -> &'static [u8] {
        match self {
            Self::Alphanumeric => ALPHANUMERIC,
            Self::Hex => HEX,
            Self::Base64Url => BASE64_URL,
        }
    }
}

pub fn random_secret(charset: Charset, length: usize) -> Result<Zeroizing<String>> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(Error::InvalidValue("length must be between 8 and 1024"));
    }
    let alphabet = charset.alphabet();
    let unbiased_limit = 256 - 256 % alphabet.len();
    let mut secret = Zeroizing::new(String::with_capacity(length));
    let mut entropy = Zeroizing::new([0_u8; 64]);
    while secret.len() < length {
        fill_random(entropy.as_mut())?;
        for &byte in entropy.iter() {
            if secret.len() == length {
                break;
            }
            if usize::from(byte) < unbiased_limit
                && let Some(&symbol) = alphabet.get(usize::from(byte) % alphabet.len())
            {
                secret.push(char::from(symbol));
            }
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_the_requested_length_and_alphabet() {
        for (charset, alphabet) in [
            (Charset::Alphanumeric, ALPHANUMERIC),
            (Charset::Hex, HEX),
            (Charset::Base64Url, BASE64_URL),
        ] {
            for length in [MIN_LENGTH, 33, 64, 65, MAX_LENGTH] {
                let secret = random_secret(charset, length).unwrap();
                assert_eq!(secret.len(), length);
                assert!(secret.bytes().all(|byte| alphabet.contains(&byte)));
            }
        }
    }

    #[test]
    fn rejects_lengths_out_of_range() {
        assert!(random_secret(Charset::Hex, MIN_LENGTH - 1).is_err());
        assert!(random_secret(Charset::Hex, MAX_LENGTH + 1).is_err());
    }

    #[test]
    fn every_symbol_appears_and_outputs_differ() {
        let sample = random_secret(Charset::Hex, MAX_LENGTH).unwrap();
        assert!(HEX.iter().all(|symbol| sample.as_bytes().contains(symbol)));
        let other = random_secret(Charset::Hex, MAX_LENGTH).unwrap();
        assert_ne!(*sample, *other);
    }
}
