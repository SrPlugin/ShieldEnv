use std::fmt;
use std::io::Read;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use ed25519_dalek::{Digest, Sha512, Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::{KEY_LEN, Key, fill_random, hex};
use crate::{Error, Result};

const SECRET_TAG: &str = "shieldenv-secret1";
const PUBLIC_TAG: &str = "shieldenv-public1";
const SEED_LEN: usize = 32;

pub const SIGNATURE_LEN: usize = 64;
pub const VERIFYING_KEY_LEN: usize = 32;

pub struct Identity {
    agreement: age::x25519::Identity,
    signing: SigningKey,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    recipient: age::x25519::Recipient,
    verifying: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
        fill_random(seed.as_mut())?;
        Ok(Self {
            agreement: age::x25519::Identity::generate(),
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn from_secret_text(text: &str) -> Result<Self> {
        let mut fields = text.trim().split(':');
        let (Some(SECRET_TAG), Some(agreement), Some(seed), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::InvalidIdentity(
                "unrecognized secret identity format",
            ));
        };
        let agreement = age::x25519::Identity::from_str(agreement)
            .map_err(|_| Error::InvalidIdentity("invalid encryption key"))?;
        let seed = hex::decode(seed)
            .and_then(|bytes| <[u8; SEED_LEN]>::try_from(bytes.as_slice()).ok())
            .map(Zeroizing::new)
            .ok_or(Error::InvalidIdentity("invalid signing key"))?;
        Ok(Self {
            agreement,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    #[must_use]
    pub fn secret_text(&self) -> Zeroizing<String> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        let mut text = Zeroizing::new(String::with_capacity(160));
        text.push_str(SECRET_TAG);
        text.push(':');
        text.push_str(self.agreement.to_string().expose_secret());
        text.push(':');
        hex::push(&mut text, seed.as_slice());
        text
    }

    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            recipient: self.agreement.to_public(),
            verifying: self.signing.verifying_key(),
        }
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<Key> {
        let decryptor = age::Decryptor::new_buffered(wrapped).map_err(|_| Error::Authentication)?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.agreement as &dyn age::Identity))
            .map_err(|_| Error::Authentication)?;
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        reader
            .read_exact(key.as_mut())
            .map_err(|_| Error::Authentication)?;
        let mut trailing = [0_u8; 1];
        match reader.read(&mut trailing) {
            Ok(0) => Ok(key),
            _ => Err(Error::Authentication),
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("fingerprint", &self.public().fingerprint())
            .finish_non_exhaustive()
    }
}

impl PublicIdentity {
    pub fn from_parts(recipient: &str, verifying: [u8; VERIFYING_KEY_LEN]) -> Result<Self> {
        let recipient = age::x25519::Recipient::from_str(recipient)
            .map_err(|_| Error::InvalidIdentity("invalid encryption key"))?;
        let verifying = VerifyingKey::from_bytes(&verifying)
            .ok()
            .filter(|key| !key.is_weak())
            .ok_or(Error::InvalidIdentity("invalid signing key"))?;
        Ok(Self {
            recipient,
            verifying,
        })
    }

    pub fn wrap_key(&self, key: &Key) -> Result<Vec<u8>> {
        age::encrypt(&self.recipient, key.as_slice())
            .map_err(|_| Error::Malformed("member key wrapping failed"))
    }

    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        self.verifying
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }

    #[must_use]
    pub fn recipient_text(&self) -> String {
        self.recipient.to_string()
    }

    #[must_use]
    pub fn verifying_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.verifying.to_bytes()
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha512::digest(self.to_string().as_bytes());
        let short = digest.get(..8).unwrap_or_default();
        short
            .chunks(2)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Display for PublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{PUBLIC_TAG}:{}:{}",
            self.recipient,
            hex::encode(&self.verifying.to_bytes())
        )
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PublicIdentity({})", self.fingerprint())
    }
}

impl FromStr for PublicIdentity {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let mut fields = text.trim().split(':');
        let (Some(PUBLIC_TAG), Some(recipient), Some(verifying), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::InvalidIdentity(
                "unrecognized public identity format",
            ));
        };
        let verifying = hex::decode(verifying)
            .and_then(|bytes| <[u8; VERIFYING_KEY_LEN]>::try_from(bytes.as_slice()).ok())
            .ok_or(Error::InvalidIdentity("invalid signing key"))?;
        Self::from_parts(recipient, verifying)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_key(byte: u8) -> Key {
        Zeroizing::new([byte; KEY_LEN])
    }

    #[test]
    fn identities_are_unique_and_round_trip_through_text() {
        let first = Identity::generate().unwrap();
        let second = Identity::generate().unwrap();
        assert_ne!(first.public(), second.public());
        let restored = Identity::from_secret_text(&first.secret_text()).unwrap();
        assert_eq!(restored.public(), first.public());
        let public: PublicIdentity = first.public().to_string().parse().unwrap();
        assert_eq!(public, first.public());
        assert!(
            first
                .public()
                .to_string()
                .starts_with("shieldenv-public1:age1")
        );
        assert!(
            first
                .secret_text()
                .starts_with("shieldenv-secret1:AGE-SECRET-KEY-1")
        );
    }

    #[test]
    fn rejects_malformed_identity_text() {
        let identity = Identity::generate().unwrap();
        let secret = identity.secret_text();
        let public = identity.public().to_string();
        let weak = format!(
            "{PUBLIC_TAG}:{}:01{}",
            identity.public().recipient_text(),
            "00".repeat(31)
        );
        for text in [
            String::new(),
            "shieldenv-secret1".to_owned(),
            secret.replace("shieldenv-secret1", "other"),
            format!("{}:extra", secret.as_str()),
            secret.replace("AGE-SECRET-KEY-1", "AGE-SECRET-KEY-2"),
            format!("{}0", secret.as_str()),
        ] {
            assert!(Identity::from_secret_text(&text).is_err(), "{text:?}");
        }
        for text in [
            String::new(),
            public.replace("age1", "age2"),
            format!("{public}:extra"),
            public.replace(PUBLIC_TAG, "other"),
            format!("{public}00"),
            weak,
        ] {
            assert!(text.parse::<PublicIdentity>().is_err(), "{text:?}");
        }
    }

    #[test]
    fn wrapped_keys_open_only_for_their_recipient() {
        let owner = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let wrapped = owner.public().wrap_key(&data_key(7)).unwrap();
        assert_eq!(*owner.unwrap_key(&wrapped).unwrap(), [7; KEY_LEN]);
        assert!(matches!(
            stranger.unwrap_key(&wrapped),
            Err(Error::Authentication)
        ));
        assert_ne!(wrapped, owner.public().wrap_key(&data_key(7)).unwrap());
    }

    #[test]
    fn tampered_or_truncated_wrapped_keys_are_rejected() {
        let owner = Identity::generate().unwrap();
        let wrapped = owner.public().wrap_key(&data_key(1)).unwrap();
        for index in 0..wrapped.len() {
            let mut tampered = wrapped.clone();
            tampered[index] ^= 0x01;
            assert!(owner.unwrap_key(&tampered).is_err(), "byte {index}");
        }
        for length in 0..wrapped.len() {
            assert!(
                owner.unwrap_key(&wrapped[..length]).is_err(),
                "length {length}"
            );
        }
    }

    #[test]
    fn signatures_bind_message_and_signer() {
        let signer = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let signature = signer.sign(b"member list");
        assert!(signer.public().verify(b"member list", &signature));
        assert!(!signer.public().verify(b"member list!", &signature));
        assert!(!other.public().verify(b"member list", &signature));
        let mut forged = signature;
        forged[0] ^= 1;
        assert!(!signer.public().verify(b"member list", &forged));
    }

    #[test]
    fn fingerprint_is_stable_and_readable() {
        let identity = Identity::generate().unwrap();
        let fingerprint = identity.public().fingerprint();
        assert_eq!(fingerprint, identity.public().fingerprint());
        assert_eq!(fingerprint.len(), 19);
        assert_eq!(fingerprint.matches('-').count(), 3);
        assert_ne!(
            fingerprint,
            Identity::generate().unwrap().public().fingerprint()
        );
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let identity = Identity::generate().unwrap();
        let rendered = format!("{identity:?}");
        let secret = identity.secret_text();
        assert!(rendered.contains("fingerprint"));
        assert!(!rendered.contains(secret.split(':').nth(1).unwrap()));
    }
}
