mod kdf;

pub use kdf::{KEY_LEN, KdfParams, Key, derive};

use crate::{Error, Result};

pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    getrandom::fill(buffer).map_err(|_| Error::Random)
}
