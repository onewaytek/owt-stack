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
/// The longest header this reads: a sealed 32-byte key is 65 bytes.
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
