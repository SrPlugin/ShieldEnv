use std::ops::RangeInclusive;

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const RECOMMENDED: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    const MEMORY_KIB: RangeInclusive<u32> = 19 * 1024..=256 * 1024;
    const ITERATIONS: RangeInclusive<u32> = 2..=8;
    const PARALLELISM: RangeInclusive<u32> = 1..=8;

    pub fn validate(self) -> Result<Self> {
        if Self::MEMORY_KIB.contains(&self.memory_kib)
            && Self::ITERATIONS.contains(&self.iterations)
            && Self::PARALLELISM.contains(&self.parallelism)
        {
            Ok(self)
        } else {
            Err(Error::Malformed("key derivation parameters out of bounds"))
        }
    }
}

pub fn derive(password: &SecretString, salt: &[u8], params: KdfParams) -> Result<Key> {
    let params = params.validate()?;
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Malformed("key derivation parameters rejected"))?;
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
        .hash_password_into(password.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Malformed("key derivation failed"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    fn password(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7_u8; 16];
        let first = derive(&password("correct horse"), &salt, FAST).unwrap();
        let second = derive(&password("correct horse"), &salt, FAST).unwrap();
        assert_eq!(*first, *second);
    }

    #[test]
    fn salt_and_password_change_the_key() {
        let base = derive(&password("correct horse"), &[1; 16], FAST).unwrap();
        let other_salt = derive(&password("correct horse"), &[2; 16], FAST).unwrap();
        let other_password = derive(&password("correct horsf"), &[1; 16], FAST).unwrap();
        assert_ne!(*base, *other_salt);
        assert_ne!(*base, *other_password);
    }

    #[test]
    fn recommended_parameters_are_valid() {
        assert!(KdfParams::RECOMMENDED.validate().is_ok());
        assert!(derive(&password("pw"), &[0; 16], KdfParams::RECOMMENDED).is_ok());
    }

    #[test]
    fn rejects_out_of_bounds_parameters() {
        let cases = [
            KdfParams {
                memory_kib: 19 * 1024 - 1,
                ..FAST
            },
            KdfParams {
                memory_kib: 256 * 1024 + 1,
                ..FAST
            },
            KdfParams {
                iterations: 1,
                ..FAST
            },
            KdfParams {
                iterations: 9,
                ..FAST
            },
            KdfParams {
                parallelism: 0,
                ..FAST
            },
            KdfParams {
                parallelism: 9,
                ..FAST
            },
        ];
        for params in cases {
            assert!(
                derive(&password("pw"), &[0; 16], params).is_err(),
                "{params:?}"
            );
        }
    }
}
