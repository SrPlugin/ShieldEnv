use std::fmt;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{
    Identity, KEY_LEN, KdfParams, Key, PublicIdentity, SIGNATURE_LEN, VERIFYING_KEY_LEN, derive,
    fill_random,
};
use crate::domain::MemberName;
use crate::wire::Reader;
use crate::{Error, Result};

const MAGIC: [u8; 4] = *b"SHLD";
const VAULT_ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
const PASSWORD_SLOT: u8 = 1;
const MEMBER_SLOT: u8 = 2;
const ADMIN_FLAG: u8 = 1;
const MAX_SLOTS: usize = 64;
const MAX_WRAPPED_MEMBER_KEY_LEN: usize = 512;
const MEMBERSHIP_CONTEXT: &[u8] = b"shieldenv/members/v2\0";

pub const FORMAT_VERSION: u8 = 2;
pub const MAX_VAULT_LEN: usize = 16 << 20;

type VaultId = [u8; VAULT_ID_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: MemberName,
    pub admin: bool,
    pub public: PublicIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub has_password: bool,
    pub members: Vec<Member>,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum Unlock<'a> {
    Password(&'a SecretString),
    Identity(&'a Identity),
}

impl<'a> From<&'a SecretString> for Unlock<'a> {
    fn from(password: &'a SecretString) -> Self {
        Self::Password(password)
    }
}

impl<'a> From<&'a Identity> for Unlock<'a> {
    fn from(identity: &'a Identity) -> Self {
        Self::Identity(identity)
    }
}

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
struct MemberSlot {
    member: Member,
    wrapped: Vec<u8>,
}

impl MemberSlot {
    fn seal(member: Member, data_key: &Key) -> Result<Self> {
        let wrapped = member.public.wrap_key(data_key)?;
        Ok(Self { member, wrapped })
    }

    fn rewrap(&mut self, data_key: &Key) -> Result<()> {
        self.wrapped = self.member.public.wrap_key(data_key)?;
        Ok(())
    }

    fn encode_identity(&self, output: &mut Vec<u8>) -> Result<()> {
        let name = self.member.name.as_str().as_bytes();
        let recipient = self.member.public.recipient_text();
        output.push(u8::from(self.member.admin) * ADMIN_FLAG);
        output
            .push(u8::try_from(name.len()).map_err(|_| Error::Malformed("member name too long"))?);
        output.extend_from_slice(name);
        output.push(
            u8::try_from(recipient.len()).map_err(|_| Error::Malformed("member key too long"))?,
        );
        output.extend_from_slice(recipient.as_bytes());
        output.extend_from_slice(&self.member.public.verifying_bytes());
        Ok(())
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<()> {
        output.push(MEMBER_SLOT);
        self.encode_identity(output)?;
        let wrapped_len = u16::try_from(self.wrapped.len())
            .map_err(|_| Error::Malformed("wrapped member key too long"))?;
        output.extend_from_slice(&wrapped_len.to_le_bytes());
        output.extend_from_slice(&self.wrapped);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let flags = reader.u8()?;
        if flags & !ADMIN_FLAG != 0 {
            return Err(Error::Malformed("unknown member flags"));
        }
        let name_len = usize::from(reader.u8()?);
        let name = std::str::from_utf8(reader.slice(name_len)?)
            .ok()
            .and_then(|text| text.parse::<MemberName>().ok())
            .ok_or(Error::Malformed("invalid member name"))?;
        let recipient_len = usize::from(reader.u8()?);
        let recipient = std::str::from_utf8(reader.slice(recipient_len)?)
            .map_err(|_| Error::Malformed("invalid member key"))?;
        let public = PublicIdentity::from_parts(recipient, reader.array::<VERIFYING_KEY_LEN>()?)
            .map_err(|_| Error::Malformed("invalid member key"))?;
        let wrapped_len = usize::from(reader.u16()?);
        if wrapped_len > MAX_WRAPPED_MEMBER_KEY_LEN {
            return Err(Error::Malformed("wrapped member key too long"));
        }
        Ok(Self {
            member: Member {
                name,
                admin: flags & ADMIN_FLAG != 0,
                public,
            },
            wrapped: reader.slice(wrapped_len)?.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
struct MembershipSignature {
    signer: u8,
    bytes: [u8; SIGNATURE_LEN],
}

fn membership_message(vault_id: &VaultId, members: &[MemberSlot]) -> Result<Vec<u8>> {
    let mut message = Vec::with_capacity(MEMBERSHIP_CONTEXT.len() + 256 * members.len());
    message.extend_from_slice(MEMBERSHIP_CONTEXT);
    message.extend_from_slice(vault_id);
    message
        .push(u8::try_from(members.len()).map_err(|_| Error::LimitExceeded("too many members"))?);
    for slot in members {
        slot.encode_identity(&mut message)?;
    }
    Ok(message)
}

fn verify_membership(
    vault_id: &VaultId,
    members: &[MemberSlot],
    signature: Option<&MembershipSignature>,
) -> Result<()> {
    if members.is_empty() {
        return Ok(());
    }
    let unsigned = Error::Malformed("member list is not signed by an administrator");
    let signature = signature.ok_or(unsigned)?;
    let signer = members
        .get(usize::from(signature.signer))
        .filter(|slot| slot.member.admin)
        .ok_or(Error::Malformed(
            "member list is not signed by an administrator",
        ))?;
    let message = membership_message(vault_id, members)?;
    if signer.member.public.verify(&message, &signature.bytes) {
        Ok(())
    } else {
        Err(Error::Malformed("member list signature is invalid"))
    }
}

struct Parsed<'a> {
    vault_id: VaultId,
    generation: u32,
    password: Option<PasswordSlot>,
    members: Vec<MemberSlot>,
    signature: Option<MembershipSignature>,
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
        let mut password = None;
        let mut members: Vec<MemberSlot> = Vec::new();
        for _ in 0..slot_count {
            match reader.u8()? {
                PASSWORD_SLOT if password.is_none() => {
                    password = Some(PasswordSlot::decode(&mut reader)?);
                }
                PASSWORD_SLOT => return Err(Error::Malformed("duplicate password slot")),
                MEMBER_SLOT => {
                    let slot = MemberSlot::decode(&mut reader)?;
                    let duplicate = members.iter().any(|existing| {
                        existing.member.name == slot.member.name
                            || existing.member.public == slot.member.public
                    });
                    if duplicate {
                        return Err(Error::Malformed("duplicate member"));
                    }
                    members.push(slot);
                }
                _ => return Err(Error::Malformed("unknown access slot")),
            }
        }
        let signature = if members.is_empty() {
            None
        } else {
            Some(MembershipSignature {
                signer: reader.u8()?,
                bytes: reader.array()?,
            })
        };
        verify_membership(&vault_id, &members, signature.as_ref())?;
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
            password,
            members,
            signature,
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

pub fn inspect(blob: &[u8]) -> Result<Inspection> {
    let parsed = Parsed::from_bytes(blob)?;
    Ok(Inspection {
        has_password: parsed.password.is_some(),
        members: parsed.members.into_iter().map(|slot| slot.member).collect(),
        generation: parsed.generation,
    })
}

pub struct Envelope {
    vault_id: VaultId,
    generation: u32,
    password: Option<PasswordSlot>,
    members: Vec<MemberSlot>,
    signature: Option<MembershipSignature>,
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
        let password = PasswordSlot::seal(&vault_id, &data_key, password, params)?;
        Ok(Self {
            vault_id,
            generation: 0,
            password: Some(password),
            members: Vec::new(),
            signature: None,
            data_key,
        })
    }

    pub fn open<'a>(
        blob: &[u8],
        unlock: impl Into<Unlock<'a>>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let parsed = Parsed::from_bytes(blob)?;
        let data_key = match unlock.into() {
            Unlock::Password(password) => parsed
                .password
                .as_ref()
                .ok_or(Error::NoPasswordAccess)?
                .unseal(&parsed.vault_id, password)?,
            Unlock::Identity(identity) => {
                let public = identity.public();
                let slot = parsed
                    .members
                    .iter()
                    .find(|slot| slot.member.public == public)
                    .ok_or(Error::NotAMember)?;
                identity.unwrap_key(&slot.wrapped)?
            }
        };
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
                password: parsed.password,
                members: parsed.members,
                signature: parsed.signature,
                data_key,
            },
            plaintext,
        ))
    }

    pub fn rewrap(&mut self, password: &SecretString) -> Result<()> {
        self.password = Some(PasswordSlot::seal(
            &self.vault_id,
            &self.data_key,
            password,
            KdfParams::RECOMMENDED,
        )?);
        Ok(())
    }

    pub fn rekey(&mut self, password: Option<&SecretString>) -> Result<bool> {
        let dropped_password = self.password.is_some() && password.is_none();
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::LimitExceeded("vault key rotated too many times"))?;
        self.data_key = random_key()?;
        for slot in &mut self.members {
            slot.rewrap(&self.data_key)?;
        }
        self.password = None;
        if let Some(password) = password {
            self.rewrap(password)?;
        }
        Ok(dropped_password)
    }

    pub fn init_admin(&mut self, signer: &Identity, name: MemberName) -> Result<()> {
        if !self.members.is_empty() {
            return Err(Error::MembersExist);
        }
        let member = Member {
            name,
            admin: true,
            public: signer.public(),
        };
        self.members.push(MemberSlot::seal(member, &self.data_key)?);
        self.sign_members(signer)
    }

    pub fn add_member(
        &mut self,
        signer: &Identity,
        name: MemberName,
        public: PublicIdentity,
        admin: bool,
    ) -> Result<()> {
        self.require_admin(signer)?;
        if self.members.iter().any(|slot| slot.member.name == name) {
            return Err(Error::MemberExists(name.to_string()));
        }
        if self.members.iter().any(|slot| slot.member.public == public) {
            return Err(Error::MemberExists(public.fingerprint()));
        }
        if self.members.len() + usize::from(self.password.is_some()) >= MAX_SLOTS {
            return Err(Error::LimitExceeded("too many members"));
        }
        let member = Member {
            name,
            admin,
            public,
        };
        self.members.push(MemberSlot::seal(member, &self.data_key)?);
        self.sign_members(signer)
    }

    pub fn remove_member(
        &mut self,
        signer: &Identity,
        name: &MemberName,
        password: Option<&SecretString>,
    ) -> Result<bool> {
        let signer_index = self.require_admin(signer)?;
        let index = self
            .members
            .iter()
            .position(|slot| &slot.member.name == name)
            .ok_or_else(|| Error::MemberNotFound(name.to_string()))?;
        if index == signer_index {
            return Err(Error::RemoveSelf);
        }
        let removes_last_admin = self
            .members
            .get(index)
            .is_some_and(|slot| slot.member.admin)
            && self.members.iter().filter(|slot| slot.member.admin).count() == 1;
        if removes_last_admin {
            return Err(Error::LastAdmin);
        }
        self.members.remove(index);
        let dropped_password = self.rekey(password)?;
        self.sign_members(signer)?;
        Ok(dropped_password)
    }

    pub fn sibling(
        &self,
        password: Option<&SecretString>,
        signer: Option<&Identity>,
    ) -> Result<Self> {
        let mut vault_id = [0; VAULT_ID_LEN];
        fill_random(&mut vault_id)?;
        let data_key = random_key()?;
        let params = self.params().unwrap_or(KdfParams::RECOMMENDED);
        let password_slot = password
            .map(|password| PasswordSlot::seal(&vault_id, &data_key, password, params))
            .transpose()?;
        let mut sibling = Self {
            vault_id,
            generation: 0,
            password: password_slot,
            members: Vec::new(),
            signature: None,
            data_key,
        };
        if let Some(signer) = signer.filter(|signer| self.is_admin(signer)) {
            for slot in &self.members {
                let member = slot.member.clone();
                sibling
                    .members
                    .push(MemberSlot::seal(member, &sibling.data_key)?);
            }
            sibling.sign_members(signer)?;
        }
        if sibling.password.is_none() && sibling.members.is_empty() {
            return Err(Error::NoAccess);
        }
        Ok(sibling)
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
        let slot_count = self.members.len() + usize::from(self.password.is_some());
        if slot_count == 0 {
            return Err(Error::NoAccess);
        }
        let slot_count =
            u8::try_from(slot_count).map_err(|_| Error::LimitExceeded("too many access slots"))?;
        let mut header = Vec::with_capacity(160 + 320 * self.members.len());
        header.extend_from_slice(&MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&self.vault_id);
        header.extend_from_slice(&self.generation.to_le_bytes());
        header.push(slot_count);
        if let Some(password) = &self.password {
            password.encode(&mut header);
        }
        for slot in &self.members {
            slot.encode(&mut header)?;
        }
        if !self.members.is_empty() {
            let signature = self
                .signature
                .as_ref()
                .ok_or(Error::Malformed("member list is not signed"))?;
            header.push(signature.signer);
            header.extend_from_slice(&signature.bytes);
        }
        header.extend_from_slice(payload_nonce);
        Ok(header)
    }

    fn sign_members(&mut self, signer: &Identity) -> Result<()> {
        let index = self.require_admin(signer)?;
        let message = membership_message(&self.vault_id, &self.members)?;
        self.signature = Some(MembershipSignature {
            signer: u8::try_from(index).map_err(|_| Error::LimitExceeded("too many members"))?,
            bytes: signer.sign(&message),
        });
        Ok(())
    }

    fn require_admin(&self, identity: &Identity) -> Result<usize> {
        let public = identity.public();
        match self
            .members
            .iter()
            .position(|slot| slot.member.public == public)
        {
            None => Err(Error::NotAMember),
            Some(index)
                if self
                    .members
                    .get(index)
                    .is_some_and(|slot| slot.member.admin) =>
            {
                Ok(index)
            }
            Some(_) => Err(Error::NotAdmin),
        }
    }

    #[must_use]
    pub fn is_admin(&self, identity: &Identity) -> bool {
        self.require_admin(identity).is_ok()
    }

    #[must_use]
    pub fn members(&self) -> Vec<Member> {
        self.members
            .iter()
            .map(|slot| slot.member.clone())
            .collect()
    }

    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    #[must_use]
    pub fn params(&self) -> Option<KdfParams> {
        self.password.as_ref().map(|slot| slot.params)
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
            .field("password", &self.password.is_some())
            .field("members", &self.members.len())
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

    fn name(text: &str) -> MemberName {
        text.parse().unwrap()
    }

    fn envelope() -> Envelope {
        Envelope::create_with(&password(PASSWORD), FAST).unwrap()
    }

    fn sealed(plaintext: &[u8]) -> Vec<u8> {
        envelope().seal(plaintext).unwrap()
    }

    fn with_admin() -> (Envelope, Identity) {
        let mut envelope = envelope();
        let admin = Identity::generate().unwrap();
        envelope.init_admin(&admin, name("alice")).unwrap();
        (envelope, admin)
    }

    #[test]
    fn round_trip_restores_plaintext() {
        let blob = sealed(b"secret payload");
        let (opened, plaintext) = Envelope::open(&blob, &password(PASSWORD)).unwrap();
        assert_eq!(plaintext.as_slice(), b"secret payload");
        assert_eq!(opened.params(), Some(FAST));
        assert_eq!(opened.generation(), 0);
        assert!(opened.members().is_empty());
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
        let dropped = envelope.rekey(Some(&password(PASSWORD))).unwrap();
        assert!(!dropped);
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
    fn password_siblings_have_independent_keys_and_identities() {
        let source = envelope();
        let copy = source.sibling(Some(&password(PASSWORD)), None).unwrap();
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

    #[test]
    fn the_first_administrator_unlocks_with_identity_or_password() {
        let (envelope, admin) = with_admin();
        let blob = envelope.seal(b"data").unwrap();
        let (by_identity, plaintext) = Envelope::open(&blob, &admin).unwrap();
        assert_eq!(plaintext.as_slice(), b"data");
        assert_eq!(by_identity.members().len(), 1);
        assert!(by_identity.members()[0].admin);
        assert_eq!(by_identity.members()[0].name, name("alice"));
        assert!(Envelope::open(&blob, &password(PASSWORD)).is_ok());
        let inspected = inspect(&blob).unwrap();
        assert!(inspected.has_password);
        assert_eq!(inspected.members, by_identity.members());
    }

    #[test]
    fn members_are_added_by_administrators_only() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        let third = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        assert!(matches!(
            envelope.add_member(&peer, name("carol"), third.public(), false),
            Err(Error::NotAdmin)
        ));
        assert!(matches!(
            envelope.add_member(&third, name("dave"), third.public(), false),
            Err(Error::NotAMember)
        ));
        let blob = envelope.seal(b"shared").unwrap();
        let (_, plaintext) = Envelope::open(&blob, &peer).unwrap();
        assert_eq!(plaintext.as_slice(), b"shared");
        assert!(matches!(
            Envelope::open(&blob, &third),
            Err(Error::NotAMember)
        ));
    }

    #[test]
    fn duplicate_names_and_keys_are_rejected() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let other = Identity::generate().unwrap();
        assert!(matches!(
            envelope.add_member(&admin, name("bob"), other.public(), false),
            Err(Error::MemberExists(_))
        ));
        assert!(matches!(
            envelope.add_member(&admin, name("robert"), peer.public(), false),
            Err(Error::MemberExists(_))
        ));
        assert!(matches!(
            envelope.init_admin(&admin, name("again")),
            Err(Error::MembersExist)
        ));
    }

    #[test]
    fn administrators_can_delegate_administration() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        let third = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), true)
            .unwrap();
        envelope
            .add_member(&peer, name("carol"), third.public(), false)
            .unwrap();
        let blob = envelope.seal(b"x").unwrap();
        assert!(Envelope::open(&blob, &third).is_ok());
        assert_eq!(inspect(&blob).unwrap().members.len(), 3);
    }

    #[test]
    fn removed_members_lose_access_to_new_versions() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let before = envelope.seal(b"before").unwrap();
        let dropped = envelope
            .remove_member(&admin, &name("bob"), Some(&password(PASSWORD)))
            .unwrap();
        assert!(!dropped);
        assert_eq!(envelope.generation(), 1);
        let after = envelope.seal(b"after").unwrap();
        assert!(matches!(
            Envelope::open(&after, &peer),
            Err(Error::NotAMember)
        ));
        assert!(Envelope::open(&after, &admin).is_ok());
        assert!(Envelope::open(&after, &password(PASSWORD)).is_ok());
        assert!(Envelope::open(&before, &peer).is_ok());
    }

    #[test]
    fn removal_without_a_password_drops_password_access() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let dropped = envelope.remove_member(&admin, &name("bob"), None).unwrap();
        assert!(dropped);
        assert!(!envelope.has_password());
        let blob = envelope.seal(b"x").unwrap();
        assert!(matches!(
            Envelope::open(&blob, &password(PASSWORD)),
            Err(Error::NoPasswordAccess)
        ));
        assert!(Envelope::open(&blob, &admin).is_ok());
    }

    #[test]
    fn removal_is_guarded() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        assert!(matches!(
            envelope.remove_member(&admin, &name("alice"), None),
            Err(Error::RemoveSelf)
        ));
        assert!(matches!(
            envelope.remove_member(&admin, &name("ghost"), None),
            Err(Error::MemberNotFound(_))
        ));
        assert!(matches!(
            envelope.remove_member(&peer, &name("alice"), None),
            Err(Error::NotAdmin)
        ));
        let third = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("carol"), third.public(), true)
            .unwrap();
        envelope
            .remove_member(&third, &name("alice"), None)
            .unwrap();
        assert!(matches!(
            envelope.remove_member(&third, &name("carol"), None),
            Err(Error::RemoveSelf)
        ));
        assert_eq!(envelope.members().len(), 2);
    }

    #[test]
    fn rekey_keeps_members_working() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let old_key = envelope.data_key().clone();
        envelope.rekey(Some(&password(PASSWORD))).unwrap();
        assert_ne!(*old_key, **envelope.data_key());
        let blob = envelope.seal(b"data").unwrap();
        assert!(Envelope::open(&blob, &peer).is_ok());
        assert!(Envelope::open(&blob, &admin).is_ok());
    }

    #[test]
    fn every_flipped_byte_of_a_vault_with_members_is_rejected() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let blob = envelope.seal(b"payload").unwrap();
        for index in 0..blob.len() {
            let mut tampered = blob.clone();
            tampered[index] ^= 0x01;
            assert!(Envelope::open(&tampered, &peer).is_err(), "flip at {index}");
        }
        for len in 0..blob.len() {
            assert!(Envelope::open(&blob[..len], &peer).is_err(), "length {len}");
        }
    }

    #[test]
    fn member_lists_forged_by_non_administrators_are_rejected() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let mallory = Identity::generate().unwrap();
        let member = Member {
            name: name("mallory"),
            admin: false,
            public: mallory.public(),
        };
        envelope
            .members
            .push(MemberSlot::seal(member, &envelope.data_key).unwrap());
        let message = membership_message(&envelope.vault_id, &envelope.members).unwrap();
        envelope.signature = Some(MembershipSignature {
            signer: 1,
            bytes: peer.sign(&message),
        });
        let forged_by_member = envelope.seal(b"x").unwrap();
        assert!(matches!(
            Envelope::open(&forged_by_member, &mallory),
            Err(Error::Malformed(_))
        ));
        envelope.signature = Some(MembershipSignature {
            signer: 0,
            bytes: mallory.sign(&message),
        });
        let forged_as_admin = envelope.seal(b"x").unwrap();
        assert!(matches!(
            Envelope::open(&forged_as_admin, &peer),
            Err(Error::Malformed(_))
        ));
        envelope.signature = None;
        assert!(envelope.seal(b"x").is_err());
    }

    #[test]
    fn member_lists_cannot_be_moved_to_another_vault() {
        let (donor, _) = with_admin();
        let mut other = envelope();
        other.members = donor.members.clone();
        other.signature = donor.signature.clone();
        let blob = other.seal(b"x").unwrap();
        assert!(matches!(
            Envelope::open(&blob, &password(PASSWORD)),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn administrator_siblings_inherit_the_member_list() {
        let (mut envelope, admin) = with_admin();
        let peer = Identity::generate().unwrap();
        envelope
            .add_member(&admin, name("bob"), peer.public(), false)
            .unwrap();
        let copy = envelope.sibling(None, Some(&admin)).unwrap();
        assert_ne!(**copy.data_key(), **envelope.data_key());
        assert!(!copy.has_password());
        let blob = copy.seal(b"copy").unwrap();
        assert!(Envelope::open(&blob, &peer).is_ok());
        assert!(Envelope::open(&blob, &admin).is_ok());
        assert!(matches!(
            envelope.sibling(None, Some(&peer)),
            Err(Error::NoAccess)
        ));
        assert!(matches!(envelope.sibling(None, None), Err(Error::NoAccess)));
        let with_both = envelope
            .sibling(Some(&password(PASSWORD)), Some(&peer))
            .unwrap();
        assert!(with_both.members().is_empty());
        assert!(with_both.has_password());
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
        fn arbitrary_slot_data_never_panics(
            kind in prop_oneof![Just(PASSWORD_SLOT), Just(MEMBER_SLOT), any::<u8>()],
            tail in proptest::collection::vec(any::<u8>(), 0..400),
        ) {
            let mut bytes = MAGIC.to_vec();
            bytes.push(FORMAT_VERSION);
            bytes.extend_from_slice(&[0; VAULT_ID_LEN + 4]);
            bytes.push(1);
            bytes.push(kind);
            bytes.extend_from_slice(&tail);
            prop_assert!(Envelope::open(&bytes, &password("x")).is_err());
            prop_assert!(inspect(&bytes).is_err());
        }
    }
}
