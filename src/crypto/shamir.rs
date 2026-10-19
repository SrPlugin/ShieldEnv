use std::fmt;

use zeroize::Zeroizing;

use super::{fill_random, hex};
use crate::{Error, Result};

const PREFIX: &str = "shieldenv-share";
const SHARE_VERSION: u8 = 1;
const SET_ID_LEN: usize = 8;
const MAX_SECRET_LEN: usize = 1024;

pub const MIN_THRESHOLD: u8 = 2;

pub struct Share {
    set_id: [u8; SET_ID_LEN],
    threshold: u8,
    index: u8,
    data: Zeroizing<Vec<u8>>,
}

impl Share {
    #[must_use]
    pub fn index(&self) -> u8 {
        self.index
    }

    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(
            PREFIX.len() + 16 + 2 * (SET_ID_LEN + self.data.len()),
        ));
        text.push_str(PREFIX);
        text.push(':');
        push_decimal(&mut text, SHARE_VERSION);
        text.push(':');
        hex::push(&mut text, &self.set_id);
        text.push(':');
        push_decimal(&mut text, self.threshold);
        text.push(':');
        push_decimal(&mut text, self.index);
        text.push(':');
        hex::push(&mut text, &self.data);
        text
    }

    pub fn decode(text: &str) -> Result<Self> {
        let mut fields = text.trim().split(':');
        let (
            Some(PREFIX),
            Some(version),
            Some(set_id),
            Some(threshold),
            Some(index),
            Some(payload),
            None,
        ) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        )
        else {
            return Err(Error::Shares("unrecognized share format"));
        };
        if version.parse::<u8>() != Ok(SHARE_VERSION) {
            return Err(Error::Shares("unsupported share version"));
        }
        let set_id = hex::decode(set_id)
            .and_then(|bytes| <[u8; SET_ID_LEN]>::try_from(bytes.as_slice()).ok())
            .ok_or(Error::Shares("invalid share set id"))?;
        let threshold = threshold
            .parse::<u8>()
            .ok()
            .filter(|&value| value >= MIN_THRESHOLD)
            .ok_or(Error::Shares("invalid share threshold"))?;
        let index = index
            .parse::<u8>()
            .ok()
            .filter(|&value| value > 0)
            .ok_or(Error::Shares("invalid share index"))?;
        let data = hex::decode(payload)
            .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_SECRET_LEN)
            .ok_or(Error::Shares("invalid share payload"))?;
        Ok(Self {
            set_id,
            threshold,
            index,
            data,
        })
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Share")
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

pub fn split(secret: &[u8], threshold: u8, count: u8) -> Result<Vec<Share>> {
    if threshold < MIN_THRESHOLD || threshold > count {
        return Err(Error::Shares(
            "threshold must be at least 2 and at most the number of shares",
        ));
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(Error::Shares("secret length out of range"));
    }
    let mut set_id = [0; SET_ID_LEN];
    fill_random(&mut set_id)?;
    let degree = usize::from(threshold - 1);
    let mut coefficients = Zeroizing::new(vec![0; secret.len() * degree]);
    fill_random(&mut coefficients)?;
    Ok((1..=count)
        .map(|index| Share {
            set_id,
            threshold,
            index,
            data: Zeroizing::new(
                secret
                    .iter()
                    .zip(coefficients.chunks_exact(degree))
                    .map(|(&constant, terms)| evaluate(constant, terms, index))
                    .collect(),
            ),
        })
        .collect())
}

pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
    let first = shares.first().ok_or(Error::Shares("no shares provided"))?;
    if shares.iter().any(|share| share.set_id != first.set_id) {
        return Err(Error::Shares("shares belong to different sets"));
    }
    if shares
        .iter()
        .any(|share| share.threshold != first.threshold || share.data.len() != first.data.len())
    {
        return Err(Error::Shares("shares are inconsistent"));
    }
    if shares.len() < usize::from(first.threshold) {
        return Err(Error::Shares("not enough shares to reach the threshold"));
    }
    let mut seen = [false; 256];
    for share in shares {
        let slot = seen
            .get_mut(usize::from(share.index))
            .ok_or(Error::Shares("invalid share index"))?;
        if *slot {
            return Err(Error::Shares("duplicate share index"));
        }
        *slot = true;
    }
    let mut secret = Zeroizing::new(vec![0; first.data.len()]);
    for share in shares {
        let basis = shares
            .iter()
            .filter(|other| other.index != share.index)
            .fold(1, |product, other| {
                mul(
                    product,
                    mul(other.index, inverse(other.index ^ share.index)),
                )
            });
        for (output, &value) in secret.iter_mut().zip(share.data.iter()) {
            *output ^= mul(value, basis);
        }
    }
    Ok(secret)
}

fn evaluate(constant: u8, terms: &[u8], x: u8) -> u8 {
    let higher = terms
        .iter()
        .rev()
        .fold(0, |accumulator, &term| mul(accumulator, x) ^ term);
    mul(higher, x) ^ constant
}

fn mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        product ^= left & (right & 1).wrapping_neg();
        let carry = (left >> 7).wrapping_neg();
        left = (left << 1) ^ (0x1B & carry);
        right >>= 1;
    }
    product
}

fn inverse(value: u8) -> u8 {
    let mut result = 1;
    let mut base = value;
    let mut exponent: u8 = 254;
    for _ in 0..8 {
        let mask = (exponent & 1).wrapping_neg();
        result = (mul(result, base) & mask) | (result & !mask);
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

fn push_decimal(text: &mut String, value: u8) {
    let hundreds = value / 100;
    let tens = value / 10 % 10;
    if hundreds > 0 {
        text.push(char::from(b'0' + hundreds));
    }
    if hundreds > 0 || tens > 0 {
        text.push(char::from(b'0' + tens));
    }
    text.push(char::from(b'0' + value % 10));
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::subsequence;

    fn transported(shares: &[&Share]) -> Vec<Share> {
        shares
            .iter()
            .map(|share| Share::decode(&share.encode()).unwrap())
            .collect()
    }

    #[test]
    fn field_arithmetic_matches_reference_values() {
        assert_eq!(mul(0x57, 0x83), 0xC1);
        assert_eq!(mul(0x57, 0x13), 0xFE);
        assert_eq!(mul(0, 0xFF), 0);
        for value in 1..=255_u8 {
            assert_eq!(mul(value, inverse(value)), 1, "inverse of {value}");
        }
    }

    #[test]
    fn every_threshold_subset_recovers_the_secret() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 3, 5).unwrap();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let subset = transported(&[&shares[a], &shares[b], &shares[c]]);
                    assert_eq!(combine(&subset).unwrap().as_slice(), secret);
                }
            }
        }
        assert_eq!(combine(&shares).unwrap().as_slice(), secret);
    }

    #[test]
    fn fewer_shares_than_threshold_are_rejected() {
        let shares = split(b"secret", 3, 5).unwrap();
        assert!(matches!(combine(&shares[..2]), Err(Error::Shares(_))));
        assert!(matches!(combine(&[]), Err(Error::Shares(_))));
    }

    #[test]
    fn mixed_sets_and_duplicates_are_rejected() {
        let first = split(b"secret", 2, 3).unwrap();
        let second = split(b"secret", 2, 3).unwrap();
        let mixed = transported(&[&first[0], &second[1]]);
        assert!(matches!(combine(&mixed), Err(Error::Shares(_))));
        let duplicated = transported(&[&first[0], &first[0]]);
        assert!(matches!(combine(&duplicated), Err(Error::Shares(_))));
    }

    #[test]
    fn single_share_does_not_expose_the_secret() {
        let zeros = split(&[0; 32], 2, 2).unwrap();
        let ones = split(&[0xFF; 32], 2, 2).unwrap();
        assert_ne!(zeros[0].data.as_slice(), [0; 32]);
        assert_ne!(ones[0].data.as_slice(), [0xFF; 32]);
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(split(b"secret", 1, 3).is_err());
        assert!(split(b"secret", 4, 3).is_err());
        assert!(split(b"", 2, 3).is_err());
        assert!(split(&[0; MAX_SECRET_LEN + 1], 2, 3).is_err());
        assert!(split(b"secret", 255, 255).is_ok());
    }

    #[test]
    fn encoding_round_trips() {
        let shares = split(b"\x00\x01\xfe\xff", 2, 200).unwrap();
        let share = &shares[199];
        let text = share.encode();
        assert!(text.starts_with("shieldenv-share:1:"));
        assert!(text.contains(":2:200:"));
        let decoded = Share::decode(&format!("  {}\n", text.as_str())).unwrap();
        assert_eq!(decoded.index(), 200);
        assert_eq!(decoded.threshold(), 2);
        assert_eq!(decoded.data.as_slice(), share.data.as_slice());
    }

    #[test]
    fn rejects_malformed_share_text() {
        for text in [
            "",
            "shieldenv-share",
            "other:1:0011223344556677:2:1:aa",
            "shieldenv-share:2:0011223344556677:2:1:aa",
            "shieldenv-share:1:00112233445566:2:1:aa",
            "shieldenv-share:1:0011223344556677:1:1:aa",
            "shieldenv-share:1:0011223344556677:2:0:aa",
            "shieldenv-share:1:0011223344556677:2:256:aa",
            "shieldenv-share:1:0011223344556677:2:1:",
            "shieldenv-share:1:0011223344556677:2:1:a",
            "shieldenv-share:1:0011223344556677:2:1:zz",
            "shieldenv-share:1:0011223344556677:2:1:aa:extra",
        ] {
            assert!(Share::decode(text).is_err(), "{text:?} accepted");
        }
    }

    fn scenario() -> impl Strategy<Value = (Vec<u8>, u8, u8, Vec<usize>)> {
        (2_u8..12)
            .prop_flat_map(|count| (Just(count), 2..=count))
            .prop_flat_map(|(count, threshold)| {
                let indices: Vec<usize> = (0..usize::from(count)).collect();
                (
                    proptest::collection::vec(any::<u8>(), 1..64),
                    Just(count),
                    Just(threshold),
                    subsequence(indices, usize::from(threshold)..=usize::from(count)),
                )
            })
    }

    proptest! {
        #[test]
        fn random_subsets_at_or_above_threshold_recover((secret, count, threshold, chosen) in scenario()) {
            let shares = split(&secret, threshold, count).unwrap();
            let picked: Vec<&Share> = chosen.iter().map(|&index| &shares[index]).collect();
            let recovered = combine(&transported(&picked)).unwrap();
            prop_assert_eq!(recovered.as_slice(), secret.as_slice());
        }

        #[test]
        fn decoding_arbitrary_text_never_panics(text in ".{0,200}") {
            let _ = Share::decode(&text);
        }
    }
}
