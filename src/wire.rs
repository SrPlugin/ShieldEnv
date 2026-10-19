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

    pub(crate) fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    pub(crate) fn length(&mut self) -> Result<usize> {
        usize::try_from(self.u32()?).map_err(|_| TRUNCATED)
    }

    pub(crate) fn slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.remaining.split_at_checked(len).ok_or(TRUNCATED)?;
        self.remaining = rest;
        Ok(head)
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.remaining
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_in_order() {
        let bytes = [1, 2, 0, 0, 0, 9, 8, 7];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 1);
        assert_eq!(reader.length().unwrap(), 2);
        assert_eq!(reader.slice(2).unwrap(), [9, 8]);
        assert_eq!(reader.array::<1>().unwrap(), [7]);
        assert!(reader.finish().is_ok());
    }

    #[test]
    fn reports_truncation_and_trailing_data() {
        assert!(Reader::new(&[1, 2, 3]).u32().is_err());
        assert!(Reader::new(&[1]).slice(2).is_err());
        assert!(Reader::new(&[1]).finish().is_err());
    }
}
