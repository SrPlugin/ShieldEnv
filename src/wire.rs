use crate::{Error, Result};

const TRUNCATED: Error = Error::Malformed("truncated data");

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self.remaining.split_first_chunk::<N>().ok_or(TRUNCATED)?;
        self.remaining = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_in_order() {
        let bytes = [1, 2, 0, 0, 0, 9, 8];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 1);
        assert_eq!(reader.u32().unwrap(), 2);
        assert_eq!(reader.array::<1>().unwrap(), [9]);
        assert_eq!(reader.rest(), [8]);
    }

    #[test]
    fn reports_truncation() {
        assert!(Reader::new(&[1, 2, 3]).u32().is_err());
        assert!(Reader::new(&[]).u8().is_err());
    }
}
