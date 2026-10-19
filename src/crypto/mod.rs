mod envelope;
mod hex;
mod identity;
pub mod identity_file;
mod kdf;
pub mod shamir;

pub use envelope::{Envelope, FORMAT_VERSION, Inspection, MAX_VAULT_LEN, Member, Unlock, inspect};
pub use identity::{Identity, PublicIdentity, SIGNATURE_LEN, VERIFYING_KEY_LEN};
pub use kdf::{KEY_LEN, KdfParams, Key, derive};

use crate::{Error, Result};

pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    getrandom::fill(buffer).map_err(|_| Error::Random)
}
