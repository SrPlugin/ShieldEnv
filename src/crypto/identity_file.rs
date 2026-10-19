use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{Identity, KdfParams, Key, PublicIdentity, derive, fill_random};
use crate::wire::Reader;
use crate::{Error, Result};

const MAGIC: [u8; 4] = *b"SHID";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const PLAIN_PREFIX: &str = "shieldenv-secret1:";

pub const MAX_FILE_LEN: usize = 4096;

#[must_use]
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC)
}

pub fn seal(identity: &Identity, passphrase: &SecretString) -> Result<Vec<u8>> {
    seal_with(identity, passphrase, KdfParams::RECOMMENDED)
}

pub fn public_of(bytes: &[u8]) -> Result<PublicIdentity> {
    if is_encrypted(bytes) {
        return Parsed::from_bytes(bytes).map(|parsed| parsed.public);
    }
    Identity::from_secret_text(plain_text(bytes)?).map(|identity| identity.public())
}

pub fn open(bytes: &[u8], passphrase: Option<&SecretString>) -> Result<Identity> {
    if !is_encrypted(bytes) {
        return Identity::from_secret_text(plain_text(bytes)?);
    }
    let parsed = Parsed::from_bytes(bytes)?;
    let passphrase = passphrase.ok_or(Error::InvalidIdentity("identity needs a passphrase"))?;
    let key = derive(passphrase, &parsed.salt, parsed.params)?;
    let mut plaintext = Zeroizing::new(parsed.ciphertext.to_vec());
    cipher(&key)?
        .decrypt_inout_detached(
            &XNonce::from(parsed.nonce),
            parsed.header,
            InOutBuf::from(plaintext.as_mut_slice()),
            &parsed.tag,
        )
        .map_err(|_| Error::Authentication)?;
    let text = std::str::from_utf8(&plaintext)
        .map_err(|_| Error::InvalidIdentity("identity is not valid text"))?;
    let identity = Identity::from_secret_text(text)?;
    if identity.public() == parsed.public {
        Ok(identity)
    } else {
        Err(Error::InvalidIdentity("identity does not match its label"))
    }
}

fn seal_with(identity: &Identity, passphrase: &SecretString, params: KdfParams) -> Result<Vec<u8>> {
    let public = identity.public().to_string();
    let public_len = u8::try_from(public.len())
        .map_err(|_| Error::InvalidIdentity("public identity too long"))?;
    let mut salt = [0; SALT_LEN];
    let mut nonce = [0; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    let key = derive(passphrase, &salt, params)?;
    let mut output = Vec::with_capacity(MAX_FILE_LEN / 8);
    output.extend_from_slice(&MAGIC);
    output.push(VERSION);
    output.push(public_len);
    output.extend_from_slice(public.as_bytes());
    output.extend_from_slice(&params.memory_kib.to_le_bytes());
    output.extend_from_slice(&params.iterations.to_le_bytes());
    output.extend_from_slice(&params.parallelism.to_le_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    let header_len = output.len();
    output.extend_from_slice(identity.secret_text().as_bytes());
    let (header, body) = output
        .split_at_mut_checked(header_len)
        .ok_or(Error::Malformed("identity encoding failed"))?;
    let tag = cipher(&key)?
        .encrypt_inout_detached(&XNonce::from(nonce), header, InOutBuf::from(body))
        .map_err(|_| Error::Malformed("identity encryption failed"))?;
    output.extend_from_slice(&tag);
    Ok(output)
}

fn plain_text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|text| text.trim_start().starts_with(PLAIN_PREFIX))
        .ok_or(Error::InvalidIdentity("unrecognized identity file"))
}

struct Parsed<'a> {
    public: PublicIdentity,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    header: &'a [u8],
    ciphertext: &'a [u8],
    tag: Tag,
}

impl<'a> Parsed<'a> {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE_LEN {
            return Err(Error::LimitExceeded("identity file too large"));
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC {
            return Err(Error::InvalidIdentity("not an identity file"));
        }
        let version = reader.u8()?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let public_len = usize::from(reader.u8()?);
        let public = std::str::from_utf8(reader.slice(public_len)?)
            .map_err(|_| Error::InvalidIdentity("invalid public identity"))?
            .parse::<PublicIdentity>()?;
        let params = KdfParams {
            memory_kib: reader.u32()?,
            iterations: reader.u32()?,
            parallelism: reader.u32()?,
        }
        .validate()?;
        let salt = reader.array()?;
        let nonce = reader.array()?;
        let header_len = bytes.len() - reader.remaining_len();
        let header = bytes
            .get(..header_len)
            .ok_or(Error::Malformed("truncated identity header"))?;
        let body = reader.rest();
        let ciphertext_len = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Malformed("truncated identity"))?;
        let (ciphertext, tag) = body
            .split_at_checked(ciphertext_len)
            .ok_or(Error::Malformed("truncated identity"))?;
        let tag = Tag::try_from(tag).map_err(|_| Error::Malformed("truncated identity"))?;
        Ok(Self {
            public,
            params,
            salt,
            nonce,
            header,
            ciphertext,
            tag,
        })
    }
}

fn cipher(key: &Key) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::Malformed("invalid key length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    #[test]
    fn encrypted_files_round_trip() {
        let identity = Identity::generate().unwrap();
        let bytes = seal_with(&identity, &passphrase("long enough passphrase"), FAST).unwrap();
        assert!(is_encrypted(&bytes));
        assert_eq!(public_of(&bytes).unwrap(), identity.public());
        let opened = open(&bytes, Some(&passphrase("long enough passphrase"))).unwrap();
        assert_eq!(opened.public(), identity.public());
        assert_eq!(*opened.secret_text(), *identity.secret_text());
    }

    #[test]
    fn secret_never_appears_in_encrypted_files() {
        let identity = Identity::generate().unwrap();
        let bytes = seal_with(&identity, &passphrase("long enough passphrase"), FAST).unwrap();
        let secret = identity.secret_text();
        let age_part = secret.split(':').nth(1).unwrap();
        assert!(
            !bytes
                .windows(age_part.len())
                .any(|window| window == age_part.as_bytes())
        );
    }

    #[test]
    fn wrong_or_missing_passphrase_is_rejected() {
        let identity = Identity::generate().unwrap();
        let bytes = seal_with(&identity, &passphrase("long enough passphrase"), FAST).unwrap();
        assert!(matches!(
            open(&bytes, Some(&passphrase("another passphrase!"))),
            Err(Error::Authentication)
        ));
        assert!(matches!(open(&bytes, None), Err(Error::InvalidIdentity(_))));
    }

    #[test]
    fn plain_files_are_read_without_a_passphrase() {
        let identity = Identity::generate().unwrap();
        let text = format!("{}\n", identity.secret_text().as_str());
        assert!(!is_encrypted(text.as_bytes()));
        assert_eq!(public_of(text.as_bytes()).unwrap(), identity.public());
        assert_eq!(
            open(text.as_bytes(), None).unwrap().public(),
            identity.public()
        );
        assert!(open(b"garbage", None).is_err());
        assert!(public_of(b"").is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let identity = Identity::generate().unwrap();
        let bytes = seal_with(&identity, &passphrase("long enough passphrase"), FAST).unwrap();
        for index in (0..bytes.len()).step_by(5).chain([bytes.len() - 1]) {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            assert!(
                open(&tampered, Some(&passphrase("long enough passphrase"))).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn truncation_and_oversize_are_rejected() {
        let identity = Identity::generate().unwrap();
        let bytes = seal_with(&identity, &passphrase("long enough passphrase"), FAST).unwrap();
        for length in (0..bytes.len()).step_by(7) {
            assert!(open(&bytes[..length], Some(&passphrase("x"))).is_err());
        }
        let oversized = vec![b'S'; MAX_FILE_LEN + 1];
        assert!(public_of(&[&MAGIC[..], &oversized].concat()).is_err());
    }
}
