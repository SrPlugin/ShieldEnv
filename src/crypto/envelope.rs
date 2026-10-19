use std::fmt;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{KEY_LEN, KdfParams, Key, derive, fill_random};
use crate::wire::Reader;
use crate::{Error, Result};

const MAGIC: [u8; 4] = *b"SHLD";
const VAULT_ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
const PASSWORD_SLOT: u8 = 1;
const MAX_SLOTS: usize = 64;

pub const FORMAT_VERSION: u8 = 2;
pub const MAX_VAULT_LEN: usize = 16 << 20;

type VaultId = [u8; VAULT_ID_LEN];

#[derive(Debug, Clone)]
struct PasswordSlot {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_KEY_LEN],
}

impl PasswordSlot {
    fn seal(
        vault_id: &VaultId,
        data_key: &Key,
        password: &SecretString,
        params: KdfParams,
    ) -> Result<Self> {
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
                &slot.associated_data(vault_id),
                InOutBuf::from(buffer.as_mut_slice()),
            )
            .map_err(|_| Error::Malformed("key wrapping failed"))?;
        for (target, source) in slot.wrapped.iter_mut().zip(buffer.iter().chain(tag.iter())) {
            *target = *source;
        }
        Ok(slot)
    }

    fn unseal(&self, vault_id: &VaultId, password: &SecretString) -> Result<Key> {
        let key_encryption_key = derive(password, &self.salt, self.params)?;
        let (ciphertext, tag) = self
            .wrapped
            .split_first_chunk::<KEY_LEN>()
            .ok_or(Error::Malformed("wrapped key truncated"))?;
        let tag = Tag::try_from(tag).map_err(|_| Error::Malformed("wrapped key truncated"))?;
        let mut data_key = Zeroizing::new(*ciphertext);
        cipher(&key_encryption_key)?
            .decrypt_inout_detached(
                &XNonce::from(self.nonce),
                &self.associated_data(vault_id),
                InOutBuf::from(data_key.as_mut_slice()),
                &tag,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(data_key)
    }

    fn associated_data(&self, vault_id: &VaultId) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(vault_id);
        bytes.push(PASSWORD_SLOT);
        self.encode_parameters(&mut bytes);
        bytes
    }

    fn encode_parameters(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        output.extend_from_slice(&self.params.iterations.to_le_bytes());
        output.extend_from_slice(&self.params.parallelism.to_le_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&self.nonce);
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.push(PASSWORD_SLOT);
        self.encode_parameters(output);
        output.extend_from_slice(&self.wrapped);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let params = KdfParams {
            memory_kib: reader.u32()?,
            iterations: reader.u32()?,
            parallelism: reader.u32()?,
        }
        .validate()?;
        Ok(Self {
            params,
            salt: reader.array()?,
            nonce: reader.array()?,
            wrapped: reader.array()?,
        })
    }
}

#[derive(Debug, Clone)]
enum Slot {
    Password(PasswordSlot),
}

impl Slot {
    fn encode(&self, output: &mut Vec<u8>) {
        match self {
            Self::Password(slot) => slot.encode(output),
        }
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.u8()? {
            PASSWORD_SLOT => PasswordSlot::decode(reader).map(Self::Password),
            _ => Err(Error::Malformed("unknown access slot")),
        }
    }
}

struct Parsed<'a> {
    vault_id: VaultId,
    generation: u32,
    slots: Vec<Slot>,
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
        let vault_id = reader.array()?;
        let generation = reader.u32()?;
        let slot_count = usize::from(reader.u8()?);
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(Error::Malformed("invalid number of access slots"));
        }
        let slots = (0..slot_count)
            .map(|_| Slot::decode(&mut reader))
            .collect::<Result<Vec<_>>>()?;
        let password_slots = slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Password(_)))
            .count();
        if password_slots > 1 {
            return Err(Error::Malformed("duplicate password slot"));
        }
        let payload_nonce = reader.array()?;
        let header_len = blob.len() - reader.remaining_len();
        let header = blob
            .get(..header_len)
            .ok_or(Error::Malformed("truncated header"))?;
        let body = reader.rest();
        let ciphertext_len = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Malformed("truncated payload"))?;
        let (ciphertext, tag) = body
            .split_at_checked(ciphertext_len)
            .ok_or(Error::Malformed("truncated payload"))?;
        let tag = Tag::try_from(tag).map_err(|_| Error::Malformed("truncated payload"))?;
        Ok(Self {
            vault_id,
            generation,
            slots,
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
    vault_id: VaultId,
    generation: u32,
    slots: Vec<Slot>,
    data_key: Key,
}

impl Envelope {
    pub fn create(password: &SecretString) -> Result<Self> {
        Self::create_with(password, KdfParams::RECOMMENDED)
    }

    fn create_with(password: &SecretString, params: KdfParams) -> Result<Self> {
        let mut vault_id = [0; VAULT_ID_LEN];
        fill_random(&mut vault_id)?;
        let data_key = random_key()?;
        let slot = PasswordSlot::seal(&vault_id, &data_key, password, params)?;
        Ok(Self {
            vault_id,
            generation: 0,
            slots: vec![Slot::Password(slot)],
            data_key,
        })
    }

    pub fn open(blob: &[u8], password: &SecretString) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let parsed = Parsed::from_bytes(blob)?;
        let slot = parsed
            .slots
            .iter()
            .map(|Slot::Password(slot)| slot)
            .next()
            .ok_or(Error::Authentication)?;
        let data_key = slot.unseal(&parsed.vault_id, password)?;
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
                vault_id: parsed.vault_id,
                generation: parsed.generation,
                slots: parsed.slots,
                data_key,
            },
            plaintext,
        ))
    }

    pub fn rewrap(&mut self, password: &SecretString) -> Result<()> {
        let slot = PasswordSlot::seal(
            &self.vault_id,
            &self.data_key,
            password,
            KdfParams::RECOMMENDED,
        )?;
        self.slots
            .retain(|existing| !matches!(existing, Slot::Password(_)));
        self.slots.insert(0, Slot::Password(slot));
        Ok(())
    }

    pub fn rekey(&mut self, password: &SecretString) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::LimitExceeded("vault key rotated too many times"))?;
        self.data_key = random_key()?;
        self.rewrap(password)
    }

    pub fn sibling(&self, password: &SecretString) -> Result<Self> {
        Self::create_with(password, self.params().unwrap_or(KdfParams::RECOMMENDED))
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut payload_nonce = [0; NONCE_LEN];
        fill_random(&mut payload_nonce)?;
        let mut output = self.encode_header(&payload_nonce)?;
        let header_len = output.len();
        if header_len + plaintext.len() + TAG_LEN > MAX_VAULT_LEN {
            return Err(Error::LimitExceeded("vault file larger than 16 MiB"));
        }
        output.reserve(plaintext.len() + TAG_LEN);
        output.extend_from_slice(plaintext);
        let (header, body) = output
            .split_at_mut_checked(header_len)
            .ok_or(Error::Malformed("header encoding failed"))?;
        let tag = cipher(&self.data_key)?
            .encrypt_inout_detached(&XNonce::from(payload_nonce), header, InOutBuf::from(body))
            .map_err(|_| Error::LimitExceeded("payload too large to encrypt"))?;
        output.extend_from_slice(&tag);
        Ok(output)
    }

    fn encode_header(&self, payload_nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
        let slot_count = u8::try_from(self.slots.len())
            .map_err(|_| Error::LimitExceeded("too many access slots"))?;
        let mut header = Vec::with_capacity(160);
        header.extend_from_slice(&MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&self.vault_id);
        header.extend_from_slice(&self.generation.to_le_bytes());
        header.push(slot_count);
        for slot in &self.slots {
            slot.encode(&mut header);
        }
        header.extend_from_slice(payload_nonce);
        Ok(header)
    }

    #[must_use]
    pub fn params(&self) -> Option<KdfParams> {
        self.slots
            .iter()
            .map(|Slot::Password(slot)| slot.params)
            .next()
    }

    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
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
            .field("generation", &self.generation)
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}

fn random_key() -> Result<Key> {
    let mut key = Zeroizing::new([0; KEY_LEN]);
    fill_random(key.as_mut())?;
    Ok(key)
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
    const PASSWORD: &str = "correct horse battery";

    fn password(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn envelope() -> Envelope {
        Envelope::create_with(&password(PASSWORD), FAST).unwrap()
    }

    fn sealed(plaintext: &[u8]) -> Vec<u8> {
        envelope().seal(plaintext).unwrap()
    }

    #[test]
    fn round_trip_restores_plaintext() {
        let blob = sealed(b"secret payload");
        let (opened, plaintext) = Envelope::open(&blob, &password(PASSWORD)).unwrap();
        assert_eq!(plaintext.as_slice(), b"secret payload");
        assert_eq!(opened.params(), Some(FAST));
        assert_eq!(opened.generation(), 0);
    }

    #[test]
    fn empty_payload_round_trips() {
        let blob = sealed(b"");
        let (_, plaintext) = Envelope::open(&blob, &password(PASSWORD)).unwrap();
        assert!(plaintext.is_empty());
    }

    #[test]
    fn wrong_password_fails_authentication() {
        assert!(matches!(
            Envelope::open(&sealed(b"secret"), &password("wrong password!")),
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
                Envelope::open(&tampered, &password(PASSWORD)).is_err(),
                "flip at byte {index} accepted"
            );
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let blob = sealed(b"payload");
        for len in 0..blob.len() {
            assert!(Envelope::open(&blob[..len], &password(PASSWORD)).is_err());
        }
        let mut extended = blob;
        extended.push(0);
        assert!(Envelope::open(&extended, &password(PASSWORD)).is_err());
    }

    #[test]
    fn reports_foreign_files_and_versions() {
        let mut blob = sealed(b"payload");
        blob[4] = 1;
        assert!(matches!(
            Envelope::open(&blob, &password("x")),
            Err(Error::UnsupportedVersion(1))
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
        assert_eq!(reopened.params(), Some(KdfParams::RECOMMENDED));
        assert_eq!(reopened.generation(), 0);
    }

    #[test]
    fn rekey_replaces_the_data_key_and_advances_the_generation() {
        let mut envelope = envelope();
        let old_blob = envelope.seal(b"data").unwrap();
        let old_key = envelope.data_key().clone();
        envelope.rekey(&password(PASSWORD)).unwrap();
        assert_eq!(envelope.generation(), 1);
        assert_ne!(*old_key, **envelope.data_key());
        let new_blob = envelope.seal(b"data").unwrap();
        assert!(matches!(
            Envelope::open_with_key(&new_blob, old_key),
            Err(Error::Authentication)
        ));
        let (reopened, plaintext) = Envelope::open(&new_blob, &password(PASSWORD)).unwrap();
        assert_eq!(plaintext.as_slice(), b"data");
        assert_eq!(reopened.generation(), 1);
        assert!(Envelope::open(&old_blob, &password(PASSWORD)).is_ok());
    }

    #[test]
    fn data_key_opens_without_password() {
        let envelope = envelope();
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
    fn siblings_have_independent_keys_and_identities() {
        let source = envelope();
        let copy = source.sibling(&password(PASSWORD)).unwrap();
        assert_ne!(**source.data_key(), **copy.data_key());
        assert_ne!(source.vault_id, copy.vault_id);
        assert_eq!(copy.params(), Some(FAST));
        let blob = copy.seal(b"data").unwrap();
        assert!(Envelope::open(&blob, &password(PASSWORD)).is_ok());
    }

    #[test]
    fn slots_cannot_be_transplanted_between_vaults() {
        let first = sealed(b"one");
        let second = sealed(b"two");
        let slot_start = 4 + 1 + VAULT_ID_LEN + 4 + 1;
        let slot_end = slot_start + 1 + 12 + SALT_LEN + NONCE_LEN + WRAPPED_KEY_LEN;
        let mut spliced = first.clone();
        spliced[slot_start..slot_end].copy_from_slice(&second[slot_start..slot_end]);
        assert!(Envelope::open(&spliced, &password(PASSWORD)).is_err());
    }

    #[test]
    fn each_seal_uses_fresh_nonces() {
        let envelope = envelope();
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
            bytes.extend_from_slice(&[0; VAULT_ID_LEN + 4]);
            bytes.push(1);
            bytes.push(PASSWORD_SLOT);
            bytes.extend_from_slice(&tail);
            prop_assert!(Envelope::open(&bytes, &password("x")).is_err());
        }
    }
}
