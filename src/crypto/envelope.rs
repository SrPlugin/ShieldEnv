use std::fmt;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{KEY_LEN, KdfParams, Key, derive, fill_random};
use crate::wire::Reader;
use crate::{Error, Result};

const MAGIC: [u8; 4] = *b"SHLD";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
const KEY_WRAP_AAD_LEN: usize = MAGIC.len() + 1 + 3 * 4 + SALT_LEN + NONCE_LEN;

pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = KEY_WRAP_AAD_LEN + WRAPPED_KEY_LEN + NONCE_LEN;
pub const MAX_VAULT_LEN: usize = 16 << 20;

#[derive(Debug, Clone)]
struct KeySlot {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_KEY_LEN],
}

impl KeySlot {
    fn seal(data_key: &Key, password: &SecretString, params: KdfParams) -> Result<Self> {
        let mut slot = Self {
            params,
            salt: [0; SALT_LEN],
            nonce: [0; NONCE_LEN],
            wrapped: [0; WRAPPED_KEY_LEN],
        };
        fill_random(&mut slot.salt)?;
        fill_random(&mut slot.nonce)?;
        let key_encryption_key = derive(password, &slot.salt, params)?;
        let mut buffer = Zeroizing::new(**data_key);
        let tag = cipher(&key_encryption_key)?
            .encrypt_inout_detached(
                &XNonce::from(slot.nonce),
                &slot.associated_data(),
                InOutBuf::from(buffer.as_mut_slice()),
            )
            .map_err(|_| Error::Malformed("key wrapping failed"))?;
        for (target, source) in slot.wrapped.iter_mut().zip(buffer.iter().chain(tag.iter())) {
            *target = *source;
        }
        Ok(slot)
    }

    fn unseal(&self, password: &SecretString) -> Result<Key> {
        let key_encryption_key = derive(password, &self.salt, self.params)?;
        self.unseal_with(&key_encryption_key)
    }

    fn unseal_with(&self, key_encryption_key: &Key) -> Result<Key> {
        let (ciphertext, tag) = self
            .wrapped
            .split_first_chunk::<KEY_LEN>()
            .ok_or(Error::Malformed("wrapped key truncated"))?;
        let tag = Tag::try_from(tag).map_err(|_| Error::Malformed("wrapped key truncated"))?;
        let mut data_key = Zeroizing::new(*ciphertext);
        cipher(key_encryption_key)?
            .decrypt_inout_detached(
                &XNonce::from(self.nonce),
                &self.associated_data(),
                InOutBuf::from(data_key.as_mut_slice()),
                &tag,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(data_key)
    }

    fn associated_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(KEY_WRAP_AAD_LEN);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        bytes.extend_from_slice(&self.params.iterations.to_le_bytes());
        bytes.extend_from_slice(&self.params.parallelism.to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    fn encode_header(&self, payload_nonce: &[u8; NONCE_LEN], output: &mut Vec<u8>) {
        output.extend_from_slice(&self.associated_data());
        output.extend_from_slice(&self.wrapped);
        output.extend_from_slice(payload_nonce);
    }
}

struct Parsed<'a> {
    slot: KeySlot,
    payload_nonce: [u8; NONCE_LEN],
    header: &'a [u8],
    ciphertext: &'a [u8],
    tag: Tag,
}

impl<'a> Parsed<'a> {
    fn from_bytes(blob: &'a [u8]) -> Result<Self> {
        if blob.len() > MAX_VAULT_LEN {
            return Err(Error::LimitExceeded("vault file larger than 16 MiB"));
        }
        let mut reader = Reader::new(blob);
        if reader.array::<4>()? != MAGIC {
            return Err(Error::Malformed("not a shieldenv vault"));
        }
        let version = reader.u8()?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let params = KdfParams {
            memory_kib: reader.u32()?,
            iterations: reader.u32()?,
            parallelism: reader.u32()?,
        }
        .validate()?;
        let slot = KeySlot {
            params,
            salt: reader.array()?,
            nonce: reader.array()?,
            wrapped: reader.array()?,
        };
        let payload_nonce = reader.array()?;
        let body = reader.rest();
        let header = blob
            .get(..HEADER_LEN)
            .ok_or(Error::Malformed("truncated header"))?;
        let ciphertext_len = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Malformed("truncated payload"))?;
        let (ciphertext, tag) = body
            .split_at_checked(ciphertext_len)
            .ok_or(Error::Malformed("truncated payload"))?;
        let tag = Tag::try_from(tag).map_err(|_| Error::Malformed("truncated payload"))?;
        Ok(Self {
            slot,
            payload_nonce,
            header,
            ciphertext,
            tag,
        })
    }

    fn decrypt(&self, data_key: &Key) -> Result<Zeroizing<Vec<u8>>> {
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        cipher(data_key)?
            .decrypt_inout_detached(
                &XNonce::from(self.payload_nonce),
                self.header,
                InOutBuf::from(plaintext.as_mut_slice()),
                &self.tag,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(plaintext)
    }
}

pub struct Envelope {
    slot: KeySlot,
    data_key: Key,
}

impl Envelope {
    pub fn create(password: &SecretString) -> Result<Self> {
        Self::create_with(password, KdfParams::RECOMMENDED)
    }

    fn create_with(password: &SecretString, params: KdfParams) -> Result<Self> {
        let mut data_key = Zeroizing::new([0; KEY_LEN]);
        fill_random(data_key.as_mut())?;
        let slot = KeySlot::seal(&data_key, password, params)?;
        Ok(Self { slot, data_key })
    }

    pub fn open(blob: &[u8], password: &SecretString) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let parsed = Parsed::from_bytes(blob)?;
        let data_key = parsed.slot.unseal(password)?;
        Self::finish_open(parsed, data_key)
    }

    pub fn open_with_key(blob: &[u8], data_key: Key) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let parsed = Parsed::from_bytes(blob)?;
        Self::finish_open(parsed, data_key)
    }

    fn finish_open(parsed: Parsed<'_>, data_key: Key) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let plaintext = parsed.decrypt(&data_key)?;
        Ok((
            Self {
                slot: parsed.slot,
                data_key,
            },
            plaintext,
        ))
    }

    pub fn rewrap(&mut self, password: &SecretString) -> Result<()> {
        self.slot = KeySlot::seal(&self.data_key, password, KdfParams::RECOMMENDED)?;
        Ok(())
    }

    pub fn reseal_for(&self, password: &SecretString) -> Result<Self> {
        let mut data_key = Zeroizing::new([0; KEY_LEN]);
        fill_random(data_key.as_mut())?;
        let slot = KeySlot::seal(&data_key, password, self.slot.params)?;
        Ok(Self { slot, data_key })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let total_len = HEADER_LEN + plaintext.len() + TAG_LEN;
        if total_len > MAX_VAULT_LEN {
            return Err(Error::LimitExceeded("vault file larger than 16 MiB"));
        }
        let mut payload_nonce = [0; NONCE_LEN];
        fill_random(&mut payload_nonce)?;
        let mut output = Vec::with_capacity(total_len);
        self.slot.encode_header(&payload_nonce, &mut output);
        output.extend_from_slice(plaintext);
        let (header, body) = output
            .split_at_mut_checked(HEADER_LEN)
            .ok_or(Error::Malformed("header encoding failed"))?;
        let tag = cipher(&self.data_key)?
            .encrypt_inout_detached(&XNonce::from(payload_nonce), header, InOutBuf::from(body))
            .map_err(|_| Error::LimitExceeded("payload too large to encrypt"))?;
        output.extend_from_slice(&tag);
        Ok(output)
    }

    #[must_use]
    pub fn params(&self) -> KdfParams {
        self.slot.params
    }

    #[must_use]
    pub fn data_key(&self) -> &Key {
        &self.data_key
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Envelope")
            .field("params", &self.slot.params)
            .finish_non_exhaustive()
    }
}

fn cipher(key: &Key) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::Malformed("invalid key length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const FAST: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    fn password(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn sealed(plaintext: &[u8]) -> Vec<u8> {
        Envelope::create_with(&password("correct horse battery"), FAST)
            .unwrap()
            .seal(plaintext)
            .unwrap()
    }

    #[test]
    fn round_trip_restores_plaintext() {
        let blob = sealed(b"secret payload");
        assert_eq!(blob.len(), HEADER_LEN + 14 + TAG_LEN);
        let (envelope, plaintext) =
            Envelope::open(&blob, &password("correct horse battery")).unwrap();
        assert_eq!(plaintext.as_slice(), b"secret payload");
        assert_eq!(envelope.params(), FAST);
    }

    #[test]
    fn empty_payload_round_trips() {
        let blob = sealed(b"");
        let (_, plaintext) = Envelope::open(&blob, &password("correct horse battery")).unwrap();
        assert!(plaintext.is_empty());
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let blob = sealed(b"secret");
        assert!(matches!(
            Envelope::open(&blob, &password("wrong password!")),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn every_flipped_byte_is_rejected() {
        let blob = sealed(b"payload");
        for index in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[index] ^= 0x01;
            assert!(
                Envelope::open(&tampered, &password("correct horse battery")).is_err(),
                "flip at byte {index} accepted"
            );
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let blob = sealed(b"payload");
        for len in 0..blob.len() {
            assert!(Envelope::open(&blob[..len], &password("correct horse battery")).is_err());
        }
        let mut extended = blob;
        extended.push(0);
        assert!(Envelope::open(&extended, &password("correct horse battery")).is_err());
    }

    #[test]
    fn reports_foreign_files_and_versions() {
        let mut blob = sealed(b"payload");
        blob[4] = 2;
        assert!(matches!(
            Envelope::open(&blob, &password("x")),
            Err(Error::UnsupportedVersion(2))
        ));
        blob[0] = b'X';
        assert!(matches!(
            Envelope::open(&blob, &password("x")),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn rejects_oversized_input_before_key_derivation() {
        let blob = vec![0; MAX_VAULT_LEN + 1];
        assert!(matches!(
            Envelope::open(&blob, &password("x")),
            Err(Error::LimitExceeded(_))
        ));
    }

    #[test]
    fn rewrap_changes_password_and_keeps_data_key() {
        let mut envelope = Envelope::create_with(&password("old password"), FAST).unwrap();
        let original_key = **envelope.data_key();
        envelope.rewrap(&password("new password")).unwrap();
        let blob = envelope.seal(b"data").unwrap();
        assert!(Envelope::open(&blob, &password("old password")).is_err());
        let (reopened, plaintext) = Envelope::open(&blob, &password("new password")).unwrap();
        assert_eq!(plaintext.as_slice(), b"data");
        assert_eq!(**reopened.data_key(), original_key);
        assert_eq!(reopened.params(), KdfParams::RECOMMENDED);
    }

    #[test]
    fn data_key_opens_without_password() {
        let envelope = Envelope::create_with(&password("password"), FAST).unwrap();
        let blob = envelope.seal(b"data").unwrap();
        let (_, plaintext) = Envelope::open_with_key(&blob, envelope.data_key().clone()).unwrap();
        assert_eq!(plaintext.as_slice(), b"data");
        let wrong = Zeroizing::new([9; KEY_LEN]);
        assert!(matches!(
            Envelope::open_with_key(&blob, wrong),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn reseal_uses_a_fresh_data_key() {
        let source = Envelope::create_with(&password("password"), FAST).unwrap();
        let copy = source.reseal_for(&password("password")).unwrap();
        assert_ne!(**source.data_key(), **copy.data_key());
        let blob = copy.seal(b"data").unwrap();
        assert!(Envelope::open(&blob, &password("password")).is_ok());
    }

    #[test]
    fn each_seal_uses_fresh_nonces() {
        let envelope = Envelope::create_with(&password("password"), FAST).unwrap();
        assert_ne!(
            envelope.seal(b"same").unwrap(),
            envelope.seal(b"same").unwrap()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_bytes_never_panic(mut bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Some(first) = bytes.first_mut() {
                *first ^= 0xFF;
            }
            prop_assert!(Envelope::open(&bytes, &password("x")).is_err());
        }

        #[test]
        fn arbitrary_header_fields_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut bytes = MAGIC.to_vec();
            bytes.push(FORMAT_VERSION);
            bytes.extend_from_slice(&[0xFF; 12]);
            bytes.extend_from_slice(&tail);
            prop_assert!(Envelope::open(&bytes, &password("x")).is_err());
        }
    }
}
