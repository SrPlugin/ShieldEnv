use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::crypto::{Envelope, Key, Unlock};
use crate::domain::{SecretKey, Secrets};
use crate::storage::codec;
use crate::{Error, Result};

pub fn merge_secrets(base: &Secrets, ours: &Secrets, theirs: &Secrets) -> Result<Secrets> {
    let keys: BTreeSet<&SecretKey> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .collect();
    let mut merged = Secrets::new();
    let mut conflicts = Vec::new();
    for key in keys {
        let name = key.as_str();
        let (original, mine, other) = (base.get(name), ours.get(name), theirs.get(name));
        let source = if mine == other || other == original {
            ours
        } else if mine == original {
            theirs
        } else {
            conflicts.push(name);
            continue;
        };
        if let (Some(value), Some(meta)) = (source.get(name), source.meta(name)) {
            merged.restore(key.clone(), Zeroizing::new(value.to_owned()), meta)?;
        }
    }
    if conflicts.is_empty() {
        Ok(merged)
    } else {
        Err(Error::MergeConflict(format!(
            "changed differently on both sides: {}",
            conflicts.join(", ")
        )))
    }
}

pub fn merge_vaults(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    unlock: Unlock<'_>,
) -> Result<Vec<u8>> {
    let (our_envelope, our_plaintext) = Envelope::open(ours, unlock)?;
    let our_secrets = codec::decode(&our_plaintext)?;
    let (their_envelope, their_secrets) = open_related(theirs, unlock, &[our_envelope.data_key()])?;
    let (base_envelope, base_secrets) = open_related(
        base,
        unlock,
        &[our_envelope.data_key(), their_envelope.data_key()],
    )?;
    let merged = merge_secrets(&base_secrets, &our_secrets, &their_secrets)?;
    let (original, mine, other) = (
        base_envelope.access_summary(),
        our_envelope.access_summary(),
        their_envelope.access_summary(),
    );
    let access = if mine == other || other == original {
        &our_envelope
    } else if mine == original {
        &their_envelope
    } else {
        return Err(Error::MergeConflict(
            "access was changed differently on both sides; settle it with the 'member' commands"
                .to_owned(),
        ));
    };
    access.seal(&codec::encode(&merged)?)
}

fn open_related(
    blob: &[u8],
    unlock: Unlock<'_>,
    shared_keys: &[&Key],
) -> Result<(Envelope, Secrets)> {
    let (envelope, plaintext) = match Envelope::open(blob, unlock) {
        Ok(opened) => opened,
        Err(error) => shared_keys
            .iter()
            .find_map(|key| Envelope::open_with_key(blob, (*key).clone()).ok())
            .ok_or(error)?,
    };
    Ok((envelope, codec::decode(&plaintext)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;
    use secrecy::SecretString;

    fn secrets(entries: &[(&str, &str, u64)]) -> Secrets {
        let mut secrets = Secrets::new();
        for (key, value, at) in entries {
            secrets
                .insert_at(
                    key.parse().unwrap(),
                    Zeroizing::new((*value).to_owned()),
                    *at,
                )
                .unwrap();
        }
        secrets
    }

    fn pairs(secrets: &Secrets) -> Vec<(String, String)> {
        secrets
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_owned()))
            .collect()
    }

    fn expected(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn independent_changes_are_combined() {
        let base = secrets(&[("A", "1", 1), ("B", "1", 1), ("GONE", "x", 1)]);
        let ours = secrets(&[
            ("A", "2", 5),
            ("B", "1", 1),
            ("GONE", "x", 1),
            ("MINE", "m", 5),
        ]);
        let theirs = secrets(&[("A", "1", 1), ("B", "9", 6), ("THEIRS", "t", 6)]);
        let merged = merge_secrets(&base, &ours, &theirs).unwrap();
        assert_eq!(
            pairs(&merged),
            expected(&[("A", "2"), ("B", "9"), ("MINE", "m"), ("THEIRS", "t")])
        );
        assert_eq!(merged.meta("B").map(|meta| meta.updated), Some(6));
    }

    #[test]
    fn identical_changes_and_no_changes_merge_cleanly() {
        let base = secrets(&[("A", "1", 1)]);
        let both = secrets(&[("A", "2", 2), ("NEW", "n", 2)]);
        let merged = merge_secrets(&base, &both, &both).unwrap();
        assert_eq!(pairs(&merged), expected(&[("A", "2"), ("NEW", "n")]));
        let untouched = merge_secrets(&base, &base, &base).unwrap();
        assert_eq!(pairs(&untouched), expected(&[("A", "1")]));
    }

    #[test]
    fn deletions_follow_the_side_that_changed() {
        let base = secrets(&[("A", "1", 1), ("B", "1", 1), ("C", "1", 1)]);
        let ours = secrets(&[("B", "1", 1), ("C", "1", 1)]);
        let theirs = secrets(&[("A", "1", 1), ("C", "1", 1)]);
        let merged = merge_secrets(&base, &ours, &theirs).unwrap();
        assert_eq!(pairs(&merged), expected(&[("C", "1")]));
    }

    #[test]
    fn conflicts_are_reported_by_key_name_only() {
        let base = secrets(&[("A", "1", 1), ("B", "1", 1), ("D", "1", 1)]);
        let ours = secrets(&[("A", "ours-secret", 2), ("B", "1", 1), ("N", "x", 2)]);
        let theirs = secrets(&[
            ("A", "theirs-secret", 2),
            ("B", "changed", 2),
            ("D", "1", 1),
            ("N", "y", 2),
        ]);
        let Err(Error::MergeConflict(message)) = merge_secrets(&base, &ours, &theirs) else {
            panic!("expected a conflict");
        };
        assert!(message.contains("A, N"), "{message}");
        assert!(!message.contains("secret"));
        let deleted_vs_changed = secrets(&[("D", "2", 3)]);
        let deleted = Secrets::new();
        assert!(merge_secrets(&secrets(&[("D", "1", 1)]), &deleted, &deleted_vs_changed).is_err());
    }

    fn password() -> SecretString {
        SecretString::from("correct horse battery".to_owned())
    }

    fn seal(envelope: &Envelope, secrets: &Secrets) -> Vec<u8> {
        envelope.seal(&codec::encode(secrets).unwrap()).unwrap()
    }

    fn open_secrets(blob: &[u8], password: &SecretString) -> Secrets {
        let (_, plaintext) = Envelope::open(blob, password).unwrap();
        codec::decode(&plaintext).unwrap()
    }

    #[test]
    fn vault_blobs_merge_under_a_shared_envelope() {
        let password = password();
        let envelope = Envelope::create(&password).unwrap();
        let base = seal(&envelope, &secrets(&[("A", "1", 1)]));
        let ours = seal(&envelope, &secrets(&[("A", "1", 1), ("OURS", "o", 2)]));
        let theirs = seal(&envelope, &secrets(&[("A", "1", 1), ("THEIRS", "t", 2)]));
        let merged = merge_vaults(&base, &ours, &theirs, Unlock::from(&password)).unwrap();
        assert_eq!(
            pairs(&open_secrets(&merged, &password)),
            expected(&[("A", "1"), ("OURS", "o"), ("THEIRS", "t")])
        );
    }

    #[test]
    fn the_side_that_changed_access_keeps_its_envelope() {
        let password = password();
        let admin = Identity::generate().unwrap();
        let newcomer = Identity::generate().unwrap();
        let mut envelope = Envelope::create(&password).unwrap();
        envelope
            .init_admin(&admin, "admin".parse().unwrap())
            .unwrap();
        let base = seal(&envelope, &secrets(&[("A", "1", 1)]));
        let ours = seal(&envelope, &secrets(&[("A", "1", 1), ("OURS", "o", 2)]));
        let mut widened = Envelope::open(&base, &admin).unwrap().0;
        widened
            .add_member(
                &admin,
                "newcomer".parse().unwrap(),
                newcomer.public(),
                false,
            )
            .unwrap();
        let theirs = seal(&widened, &secrets(&[("A", "1", 1), ("THEIRS", "t", 2)]));
        let merged = merge_vaults(&base, &ours, &theirs, Unlock::from(&admin)).unwrap();
        let (opened, plaintext) = Envelope::open(&merged, &newcomer).unwrap();
        assert_eq!(opened.members().len(), 2);
        assert_eq!(
            pairs(&codec::decode(&plaintext).unwrap()),
            expected(&[("A", "1"), ("OURS", "o"), ("THEIRS", "t")])
        );
    }

    #[test]
    fn rotated_data_keys_survive_a_merge() {
        let password = password();
        let envelope = Envelope::create(&password).unwrap();
        let base = seal(&envelope, &secrets(&[("A", "1", 1)]));
        let ours = seal(&envelope, &secrets(&[("A", "1", 1), ("OURS", "o", 2)]));
        let mut rotated = Envelope::open(&base, &password).unwrap().0;
        rotated.rekey(Some(&password)).unwrap();
        let theirs = seal(&rotated, &secrets(&[("A", "1", 1)]));
        let merged = merge_vaults(&base, &ours, &theirs, Unlock::from(&password)).unwrap();
        let (opened, _) = Envelope::open(&merged, &password).unwrap();
        assert_eq!(opened.generation(), 1);
        assert_eq!(
            pairs(&open_secrets(&merged, &password)),
            expected(&[("A", "1"), ("OURS", "o")])
        );
    }

    #[test]
    fn access_changed_differently_on_both_sides_is_a_conflict() {
        let password = password();
        let envelope = Envelope::create(&password).unwrap();
        let base = seal(&envelope, &secrets(&[("A", "1", 1)]));
        let mut first = Envelope::open(&base, &password).unwrap().0;
        first.rekey(Some(&password)).unwrap();
        let mut second = Envelope::open(&base, &password).unwrap().0;
        second.rekey(Some(&password)).unwrap();
        second.rekey(Some(&password)).unwrap();
        let ours = seal(&first, &secrets(&[("A", "1", 1)]));
        let theirs = seal(&second, &secrets(&[("A", "1", 1)]));
        assert!(matches!(
            merge_vaults(&base, &ours, &theirs, Unlock::from(&password)),
            Err(Error::MergeConflict(_))
        ));
    }
}
