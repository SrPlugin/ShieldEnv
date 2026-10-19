use zeroize::Zeroizing;

use crate::domain::{SecretKey, Secrets};
use crate::wire::Reader;
use crate::{Error, Result};

pub fn encode(secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>> {
    let capacity = 4 + secrets
        .iter()
        .map(|(key, value)| 8 + key.as_str().len() + value.len())
        .sum::<usize>();
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    bytes.extend_from_slice(&length_prefix(secrets.len())?);
    for (key, value) in secrets.iter() {
        bytes.extend_from_slice(&length_prefix(key.as_str().len())?);
        bytes.extend_from_slice(key.as_str().as_bytes());
        bytes.extend_from_slice(&length_prefix(value.len())?);
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Secrets> {
    let mut reader = Reader::new(bytes);
    let count = reader.length()?;
    if count > Secrets::MAX_ENTRIES {
        return Err(Error::Malformed("too many entries"));
    }
    let mut secrets = Secrets::new();
    let mut previous: Option<SecretKey> = None;
    for _ in 0..count {
        let key = read_key(&mut reader)?;
        if previous.as_ref().is_some_and(|last| last >= &key) {
            return Err(Error::Malformed("entries out of order"));
        }
        let value_len = reader.length()?;
        if value_len > Secrets::MAX_VALUE_LEN {
            return Err(Error::Malformed("value too large"));
        }
        let value = std::str::from_utf8(reader.slice(value_len)?)
            .map_err(|_| Error::Malformed("value is not UTF-8"))?;
        secrets
            .insert(key.clone(), Zeroizing::new(value.to_owned()))
            .map_err(|_| Error::Malformed("invalid value"))?;
        previous = Some(key);
    }
    reader.finish()?;
    Ok(secrets)
}

fn read_key(reader: &mut Reader<'_>) -> Result<SecretKey> {
    let key_len = reader.length()?;
    if key_len > SecretKey::MAX_LEN {
        return Err(Error::Malformed("key too long"));
    }
    std::str::from_utf8(reader.slice(key_len)?)
        .ok()
        .and_then(|key| key.parse().ok())
        .ok_or(Error::Malformed("invalid key"))
}

fn length_prefix(len: usize) -> Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| Error::LimitExceeded("entry too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn secrets(entries: &[(&str, &str)]) -> Secrets {
        let mut secrets = Secrets::new();
        for (key, value) in entries {
            secrets
                .insert(key.parse().unwrap(), Zeroizing::new((*value).to_owned()))
                .unwrap();
        }
        secrets
    }

    fn entries(secrets: &Secrets) -> Vec<(String, String)> {
        secrets
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_owned()))
            .collect()
    }

    fn raw(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = u32::try_from(entries.len()).unwrap().to_le_bytes().to_vec();
        for (key, value) in entries {
            bytes.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    #[test]
    fn round_trips_entries() {
        let original = secrets(&[("B", "two"), ("A", "one = \"x\"\n"), ("EMPTY", "")]);
        let encoded = encode(&original).unwrap();
        assert_eq!(encoded.len(), encoded.capacity());
        assert_eq!(entries(&decode(&encoded).unwrap()), entries(&original));
    }

    #[test]
    fn empty_vault_is_four_bytes() {
        let encoded = encode(&Secrets::new()).unwrap();
        assert_eq!(encoded.as_slice(), [0, 0, 0, 0]);
        assert!(decode(&encoded).unwrap().is_empty());
    }

    #[test]
    fn every_truncation_and_extension_is_rejected() {
        let encoded = encode(&secrets(&[("A", "1"), ("B", "2")])).unwrap();
        for len in 0..encoded.len() {
            assert!(decode(&encoded[..len]).is_err(), "truncated to {len}");
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(decode(&extended).is_err());
    }

    #[test]
    fn rejects_structural_violations() {
        assert!(decode(&raw(&[(b"B", b"1"), (b"A", b"2")])).is_err());
        assert!(decode(&raw(&[(b"A", b"1"), (b"A", b"2")])).is_err());
        assert!(decode(&raw(&[(b"1BAD", b"1")])).is_err());
        assert!(decode(&raw(&[(b"A", b"\xff")])).is_err());
        assert!(decode(&raw(&[(b"A", b"a\0b")])).is_err());
        assert!(decode(&u32::MAX.to_le_bytes()).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_maps_round_trip(
            map in proptest::collection::btree_map("[A-Z_][A-Z0-9_]{0,20}", "[^\u{0}]{0,40}", 0..20)
        ) {
            let mut original = Secrets::new();
            for (key, value) in &map {
                original.insert(key.parse().unwrap(), Zeroizing::new(value.clone())).unwrap();
            }
            let decoded = decode(&encode(&original).unwrap()).unwrap();
            prop_assert_eq!(entries(&decoded), entries(&original));
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }
    }
}
