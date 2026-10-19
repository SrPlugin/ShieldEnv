use zeroize::Zeroizing;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn push(text: &mut String, bytes: &[u8]) {
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0F] {
            if let Some(&digit) = DIGITS.get(usize::from(nibble)) {
                text.push(char::from(digit));
            }
        }
    }
}

pub fn decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() / 2));
    for pair in text.as_bytes().chunks_exact(2) {
        let [high, low] = pair else { return None };
        bytes.push(value(*high)? << 4 | value(*low)?);
    }
    Some(bytes)
}

fn value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_byte_values() {
        let bytes: Vec<u8> = (0..=255).collect();
        let mut text = String::new();
        push(&mut text, &bytes);
        assert_eq!(text.len(), 512);
        assert_eq!(decode(&text).unwrap().as_slice(), bytes.as_slice());
        assert_eq!(
            decode(&text.to_uppercase()).unwrap().as_slice(),
            bytes.as_slice()
        );
    }

    #[test]
    fn rejects_odd_length_and_invalid_digits() {
        for text in ["a", "abc", "zz", "0g", "é1"] {
            assert!(decode(text).is_none(), "{text:?}");
        }
        assert_eq!(decode("").unwrap().len(), 0);
    }
}
