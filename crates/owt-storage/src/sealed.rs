//! The format of an encrypted object.
//!
//! An object is a header, then the plaintext in chunks, each sealed on its own, so an
//! object of any size is written and read in bounded memory:
//!
//! ```text
//! header = "OWTS" || 0x01 || chunk size (u32 BE) || key length (u16 BE)
//!          || sealed content key || nonce prefix (7 bytes)
//! chunk i = AES-256-GCM(content key, nonce = prefix || i (u32 BE) || last (0 or 1),
//!                       aad = header, plaintext chunk i)
//! ```
//!
//! The content key is random per object and sealed by `owt-crypt` for the field
//! (scope, `owt_storage`, `object`, the object's key), so the object opens only
//! under its own key in its own scope. Every chunk but the last holds exactly the
//! chunk size; the last is marked in its nonce, so a truncated object (a chunk
//! dropped from the end) and a reordered one both fail, as does any edited byte,
//! the header included. An empty plaintext is one empty last chunk. This is the
//! STREAM construction (Hoang, Reyhanitabar, Rogaway and Vizár, 2015).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

/// The header's magic bytes.
pub const MAGIC: &[u8; 4] = b"OWTS";
/// The format version.
pub const VERSION: u8 = 1;
/// The plaintext in each chunk but the last (1 MiB).
pub const CHUNK: usize = 1 << 20;
/// The tag each chunk adds.
pub const TAG: usize = 16;
/// The nonce prefix's length.
pub const PREFIX: usize = 7;
/// The longest header this reads: a sealed 32-byte key is 77 bytes (65 in
/// `owt-crypt`'s AES-256-GCM format).
pub const MAX_HEADER: usize = 4 + 1 + 4 + 2 + 256 + PREFIX;

/// Bytes that are not an encrypted object, or a chunk that does not authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an intact encrypted object")]
pub struct Malformed;

/// A parsed header.
pub struct Header {
    /// The header's bytes, every chunk's associated data.
    pub bytes: Vec<u8>,
    /// The plaintext per chunk.
    pub chunk: usize,
    /// The sealed content key.
    pub sealed_key: Vec<u8>,
    /// The nonce prefix.
    pub prefix: [u8; PREFIX],
}

impl Header {
    /// A header for a new object.
    #[must_use]
    pub fn new(sealed_key: Vec<u8>, prefix: [u8; PREFIX]) -> Self {
        let mut bytes = Vec::with_capacity(4 + 1 + 4 + 2 + sealed_key.len() + PREFIX);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&u32::try_from(CHUNK).unwrap_or(u32::MAX).to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(sealed_key.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&sealed_key);
        bytes.extend_from_slice(&prefix);
        Self {
            bytes,
            chunk: CHUNK,
            sealed_key,
            prefix,
        }
    }

    /// The header at the start of `bytes`, if all of it is there: `Ok(None)` when more
    /// bytes are needed.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>, Malformed> {
        if bytes.len() < 11 {
            return Ok(None);
        }
        if &bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(Malformed);
        }
        let chunk = u32::from_be_bytes(bytes[5..9].try_into().map_err(|_| Malformed)?) as usize;
        let key_len = usize::from(u16::from_be_bytes(
            bytes[9..11].try_into().map_err(|_| Malformed)?,
        ));
        // The writer always uses CHUNK; any other size would only let a crafted object
        // choose how much memory a read allocates before anything authenticates.
        if chunk != CHUNK || key_len > 256 {
            return Err(Malformed);
        }
        let end = 11 + key_len + PREFIX;
        if bytes.len() < end {
            return Ok(None);
        }
        Ok(Some(Self {
            bytes: bytes[..end].to_vec(),
            chunk,
            sealed_key: bytes[11..11 + key_len].to_vec(),
            prefix: bytes[11 + key_len..end].try_into().map_err(|_| Malformed)?,
        }))
    }
}

/// Seals or opens the chunks of one object.
pub struct Chunks {
    cipher: Aes256Gcm,
    header: Vec<u8>,
    prefix: [u8; PREFIX],
    next: u32,
}

impl Chunks {
    /// The chunks of the object with `header`, under `key`.
    ///
    /// # Panics
    ///
    /// Never: a 32-byte key is always a valid AES-256 key.
    #[must_use]
    pub fn new(key: &Zeroizing<[u8; 32]>, header: &Header) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key[..]).expect("a content key is 32 bytes"),
            header: header.bytes.clone(),
            prefix: header.prefix,
            next: 0,
        }
    }

    fn nonce(&self, last: bool) -> [u8; 12] {
        let mut n = [0_u8; 12];
        n[..PREFIX].copy_from_slice(&self.prefix);
        n[PREFIX..PREFIX + 4].copy_from_slice(&self.next.to_be_bytes());
        n[11] = u8::from(last);
        n
    }

    /// Seal the next chunk.
    pub fn seal(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, Malformed> {
        let nonce = self.nonce(last);
        let out = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.header,
                },
            )
            .map_err(|_| Malformed)?;
        self.next = self.next.checked_add(1).ok_or(Malformed)?;
        Ok(out)
    }

    /// Open the next chunk.
    pub fn open(&mut self, sealed: &[u8], last: bool) -> Result<Zeroizing<Vec<u8>>, Malformed> {
        let nonce = self.nonce(last);
        let out = self
            .cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &self.header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Malformed)?;
        self.next = self.next.checked_add(1).ok_or(Malformed)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// Two chunks sealed by an independent AES-256-GCM implementation (Python
    /// `cryptography`) under content key `40 41 .. 5f`, for the header of a sealed key
    /// of 65 `07` bytes and nonce prefix `01 .. 01`. An object stored before any
    /// upgrade of the cipher crates opens, and the chunk cipher writes the same bytes.
    #[test]
    fn known_chunks_open_and_seal_the_same() {
        const FIRST: &str = "024cfebb99c550cd48262a5fadccb1b5ab77f13e3d6af9b99c5bc8";
        const LAST: &str = "3be61ef1f5f87b78831e1492f6e260494afe9d29";
        let header = Header::new(vec![7; 65], [1; PREFIX]);
        let mut key = Zeroizing::new([0_u8; 32]);
        for (b, i) in key.iter_mut().zip(0x40_u8..) {
            *b = i;
        }
        let mut reader = Chunks::new(&key, &header);
        assert_eq!(
            &reader.open(&unhex(FIRST), false).unwrap()[..],
            b"first chunk"
        );
        assert_eq!(&reader.open(&unhex(LAST), true).unwrap()[..], b"last");
        let mut writer = Chunks::new(&key, &header);
        assert_eq!(writer.seal(b"first chunk", false).unwrap(), unhex(FIRST));
        assert_eq!(writer.seal(b"last", true).unwrap(), unhex(LAST));
        // The last chunk read as a middle one is refused.
        let mut early = Chunks::new(&key, &header);
        early.open(&unhex(FIRST), false).unwrap();
        assert!(early.open(&unhex(LAST), false).is_err());
    }

    #[test]
    fn only_the_writers_chunk_size_parses() {
        let header = Header::new(vec![7; 65], [1; PREFIX]);
        assert!(Header::parse(&header.bytes).unwrap().is_some());
        for chunk in [0_u32, 1, 1 << 19, (1 << 20) + 1, 64 << 20] {
            let mut bent = header.bytes.clone();
            bent[5..9].copy_from_slice(&chunk.to_be_bytes());
            assert!(Header::parse(&bent).is_err(), "{chunk}");
        }
    }
}
