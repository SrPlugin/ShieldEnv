mod envelope;
mod hex;
mod identity;
mod kdf;
pub mod shamir;

pub use envelope::{Envelope, FORMAT_VERSION, MAX_VAULT_LEN};
pub use identity::{Identity, PublicIdentity, SIGNATURE_LEN, VERIFYING_KEY_LEN};
pub use kdf::{KEY_LEN, KdfParams, Key, derive};

use crate::{Error, Result};

pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    getrandom::fill(buffer).map_err(|_| Error::Random)
}
