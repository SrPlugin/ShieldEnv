use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use super::file::{FileLock, LockMode, WriteMode, create_private_dir, read_bounded, write_atomic};
use crate::crypto::{Inspection, PublicIdentity, hex};
use crate::{Error, Result};

const FILE_LIMIT: usize = 4 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NoMembers,
    FirstUse,
    Unchanged,
    Advanced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    generation: u32,
    administrators: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
}

impl TrustStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        dirs::data_dir().map(|directory| directory.join("shieldenv").join("trust.json"))
    }

    pub fn evaluate(&self, inspection: &Inspection) -> Result<Outcome> {
        let _lock = self.lock(LockMode::Shared)?;
        let pins = self.load()?;
        let pin = pins.get(&hex::encode(&inspection.vault_id));
        if inspection.members.is_empty() {
            return match pin {
                Some(_) => Err(Error::UntrustedAccess(
                    "this vault used to have members and now has none".to_owned(),
                )),
                None => Ok(Outcome::NoMembers),
            };
        }
        let Some(pin) = pin else {
            return Ok(Outcome::FirstUse);
        };
        if inspection.generation < pin.generation {
            return Err(Error::UntrustedAccess(format!(
                "this vault went back from generation {} to {}, which looks like a rollback",
                pin.generation, inspection.generation
            )));
        }
        let signer = inspection
            .signer
            .as_ref()
            .ok_or_else(|| Error::UntrustedAccess("the member list is not signed".to_owned()))?;
        if !pin.administrators.contains(&signer.to_string()) {
            let name = inspection
                .members
                .iter()
                .find(|member| member.public == *signer)
                .map_or_else(|| "unknown".to_owned(), |member| member.name.to_string());
            return Err(Error::UntrustedAccess(format!(
                "the member list is signed by {name} ({}), who is not an administrator you trusted",
                signer.fingerprint()
            )));
        }
        if administrators(inspection) == pin.administrators
            && inspection.generation == pin.generation
        {
            Ok(Outcome::Unchanged)
        } else {
            Ok(Outcome::Advanced)
        }
    }

    pub fn record(&self, inspection: &Inspection) -> Result<()> {
        if inspection.members.is_empty() {
            return Ok(());
        }
        let _lock = self.lock(LockMode::Exclusive)?;
        let mut pins = self.load()?;
        pins.insert(
            hex::encode(&inspection.vault_id),
            Pin {
                generation: inspection.generation,
                administrators: administrators(inspection),
            },
        );
        self.save(&pins)
    }

    pub fn check(&self, inspection: &Inspection) -> Result<Outcome> {
        let outcome = self.evaluate(inspection)?;
        if matches!(outcome, Outcome::FirstUse | Outcome::Advanced) {
            self.record(inspection)?;
        }
        Ok(outcome)
    }

    fn lock(&self, mode: LockMode) -> Result<FileLock> {
        let directory = self
            .path
            .parent()
            .ok_or(Error::Malformed("trust store has no directory"))?;
        create_private_dir(directory)?;
        FileLock::acquire(&self.path.with_extension("lock"), mode)
    }

    fn load(&self) -> Result<BTreeMap<String, Pin>> {
        let Some(bytes) = read_bounded(&self.path, FILE_LIMIT)? else {
            return Ok(BTreeMap::new());
        };
        let corrupt = || Error::Malformed("the trust store is corrupt; delete it to start over");
        let Value::Object(entries) = serde_json::from_slice(&bytes).map_err(|_| corrupt())? else {
            return Err(corrupt());
        };
        entries
            .into_iter()
            .map(|(vault, entry)| {
                let generation = entry
                    .get("generation")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(corrupt)?;
                let administrators = entry
                    .get("administrators")
                    .and_then(Value::as_array)
                    .ok_or_else(corrupt)?
                    .iter()
                    .map(|admin| {
                        admin
                            .as_str()
                            .filter(|text| text.parse::<PublicIdentity>().is_ok())
                            .map(str::to_owned)
                            .ok_or_else(corrupt)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((
                    vault,
                    Pin {
                        generation,
                        administrators,
                    },
                ))
            })
            .collect()
    }

    fn save(&self, pins: &BTreeMap<String, Pin>) -> Result<()> {
        let entries: Map<String, Value> = pins
            .iter()
            .map(|(vault, pin)| {
                (
                    vault.clone(),
                    json!({
                        "generation": pin.generation,
                        "administrators": pin.administrators,
                    }),
                )
            })
            .collect();
        let mut text = serde_json::to_string_pretty(&Value::Object(entries))
            .map_err(|_| Error::Malformed("trust store could not be encoded"))?;
        text.push('\n');
        write_atomic(&self.path, text.as_bytes(), WriteMode::Replace)
    }
}

fn administrators(inspection: &Inspection) -> Vec<String> {
    let mut admins: Vec<String> = inspection
        .members
        .iter()
        .filter(|member| member.admin)
        .map(|member| member.public.to_string())
        .collect();
    admins.sort();
    admins
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Identity, Member};

    struct Fixture {
        _directory: tempfile::TempDir,
        store: TrustStore,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let store = TrustStore::new(directory.path().join("shieldenv").join("trust.json"));
        Fixture {
            _directory: directory,
            store,
        }
    }

    fn member(name: &str, admin: bool, identity: &Identity) -> Member {
        Member {
            name: name.parse().unwrap(),
            admin,
            public: identity.public(),
        }
    }

    fn inspection(
        vault: u8,
        generation: u32,
        members: Vec<Member>,
        signer: Option<&Identity>,
    ) -> Inspection {
        Inspection {
            vault_id: [vault; 16],
            signer: signer.map(Identity::public),
            has_password: true,
            members,
            generation,
        }
    }

    #[test]
    fn vaults_without_members_need_no_pin() {
        let fixture = fixture();
        let plain = inspection(1, 0, Vec::new(), None);
        assert_eq!(fixture.store.check(&plain).unwrap(), Outcome::NoMembers);
        assert!(!fixture.store.path.exists());
    }

    #[test]
    fn the_first_open_pins_and_later_opens_are_unchanged() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        let state = inspection(1, 0, vec![member("alice", true, &alice)], Some(&alice));
        assert_eq!(fixture.store.check(&state).unwrap(), Outcome::FirstUse);
        assert_eq!(fixture.store.check(&state).unwrap(), Outcome::Unchanged);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&fixture.store.path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn administrators_signed_in_by_a_trusted_one_are_accepted() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let before = inspection(1, 0, vec![member("alice", true, &alice)], Some(&alice));
        fixture.store.check(&before).unwrap();
        let after = inspection(
            1,
            1,
            vec![member("alice", true, &alice), member("bob", true, &bob)],
            Some(&alice),
        );
        assert_eq!(fixture.store.check(&after).unwrap(), Outcome::Advanced);
        let signed_by_bob = inspection(
            1,
            1,
            vec![member("alice", true, &alice), member("bob", true, &bob)],
            Some(&bob),
        );
        assert_eq!(
            fixture.store.check(&signed_by_bob).unwrap(),
            Outcome::Unchanged
        );
    }

    #[test]
    fn self_promotion_by_a_member_is_rejected() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let honest = inspection(1, 0, vec![member("alice", true, &alice)], Some(&alice));
        fixture.store.check(&honest).unwrap();
        let forged = inspection(
            1,
            0,
            vec![
                member("alice", true, &alice),
                member("mallory", true, &mallory),
            ],
            Some(&mallory),
        );
        let Err(Error::UntrustedAccess(message)) = fixture.store.check(&forged) else {
            panic!("forgery accepted");
        };
        assert!(message.contains("mallory"), "{message}");
        assert_eq!(fixture.store.check(&honest).unwrap(), Outcome::Unchanged);
    }

    #[test]
    fn rollbacks_and_stripped_members_are_rejected() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        let members = vec![member("alice", true, &alice)];
        fixture
            .store
            .check(&inspection(1, 3, members.clone(), Some(&alice)))
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .check(&inspection(1, 2, members, Some(&alice))),
            Err(Error::UntrustedAccess(_))
        ));
        assert!(matches!(
            fixture.store.check(&inspection(1, 3, Vec::new(), None)),
            Err(Error::UntrustedAccess(_))
        ));
    }

    #[test]
    fn accepting_replaces_the_pin_and_vaults_are_independent() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        let carol = Identity::generate().unwrap();
        let original = inspection(1, 0, vec![member("alice", true, &alice)], Some(&alice));
        fixture.store.check(&original).unwrap();
        let replaced = inspection(1, 0, vec![member("carol", true, &carol)], Some(&carol));
        assert!(fixture.store.check(&replaced).is_err());
        fixture.store.record(&replaced).unwrap();
        assert_eq!(fixture.store.check(&replaced).unwrap(), Outcome::Unchanged);
        let other = inspection(2, 0, vec![member("alice", true, &alice)], Some(&alice));
        assert_eq!(fixture.store.check(&other).unwrap(), Outcome::FirstUse);
    }

    #[test]
    fn a_corrupt_store_is_reported() {
        let fixture = fixture();
        let alice = Identity::generate().unwrap();
        create_private_dir(fixture.store.path.parent().unwrap()).unwrap();
        std::fs::write(&fixture.store.path, b"not json").unwrap();
        let state = inspection(1, 0, vec![member("alice", true, &alice)], Some(&alice));
        assert!(matches!(
            fixture.store.check(&state),
            Err(Error::Malformed(_))
        ));
    }
}
