//! The stored formats: ciphertexts, their associated data, and the contexts data
//! keys are wrapped under. All are fixed: a change is a new format byte or domain.
//!
//! A ciphertext is `0x01 || version (u32, big-endian) || nonce (12) || AES-256-GCM
//! output (plaintext length + 16)`. Its associated data is
//! `FIELD_DOMAIN || lp(scope) || lp(table) || lp(column) || lp(row) || version`, where
//! `lp(x)` is `x`'s length as a big-endian u32, then `x`. A data key's wrap context
//! is `WRAP_DOMAIN || lp(scope) || lp(purpose) || version`. A blind index is
//! HMAC-SHA256 over `INDEX_DOMAIN || lp(table) || lp(column) || lp(value)`.

use crate::Field;

/// The ciphertext format byte.
pub const FORMAT: u8 = 1;
/// The nonce's length.
pub const NONCE_LEN: usize = 12;
/// The GCM tag's length.
pub const TAG_LEN: usize = 16;
/// The shortest ciphertext: an empty plaintext's.
pub const MIN_LEN: usize = 1 + 4 + NONCE_LEN + TAG_LEN;
/// The prefix of a field's associated data.
pub const FIELD_DOMAIN: &[u8] = b"owt-crypt/field/v1\0";
/// The prefix of a data key's wrap context.
pub const WRAP_DOMAIN: &[u8] = b"owt-crypt/key/v1\0";
/// The prefix of a blind index's input.
pub const INDEX_DOMAIN: &[u8] = b"owt-crypt/index/v1\0";

/// A ciphertext's parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed<'a> {
    /// The data key version that sealed it.
    pub version: u32,
    /// Its nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The sealed bytes, tag included.
    pub body: &'a [u8],
}

impl<'a> Sealed<'a> {
    /// The parts of `bytes`, if it is a ciphertext of this format.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < MIN_LEN || bytes[0] != FORMAT {
            return None;
        }
        let version = u32::from_be_bytes(bytes[1..5].try_into().ok()?);
        Some(Self {
            version,
            nonce: bytes[5..5 + NONCE_LEN].try_into().ok()?,
            body: &bytes[5 + NONCE_LEN..],
        })
    }
}

/// `x`'s length as a big-endian u32, then `x`.
///
/// # Panics
///
/// When `x` is 4 GiB or longer.
#[must_use]
pub fn lp(x: &[u8]) -> Vec<u8> {
    let n = u32::try_from(x.len()).expect("a field is shorter than 4 GiB");
    let mut out = Vec::with_capacity(4 + x.len());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(x);
    out
}

/// The associated data of `field`'s value sealed under key `version`.
#[must_use]
pub fn aad(field: &Field<'_>, version: u32) -> Vec<u8> {
    let mut out = FIELD_DOMAIN.to_vec();
    for part in [field.scope, field.table, field.column, field.row] {
        out.extend(lp(part.as_bytes()));
    }
    out.extend_from_slice(&version.to_be_bytes());
    out
}

/// The context key `version` of `scope` for `purpose` is wrapped under.
#[must_use]
pub fn wrap_context(scope: &str, purpose: &str, version: u32) -> Vec<u8> {
    let mut out = WRAP_DOMAIN.to_vec();
    out.extend(lp(scope.as_bytes()));
    out.extend(lp(purpose.as_bytes()));
    out.extend_from_slice(&version.to_be_bytes());
    out
}

/// A ciphertext from its parts.
#[must_use]
pub fn assemble(version: u32, nonce: &[u8; NONCE_LEN], sealed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + NONCE_LEN + sealed.len());
    out.push(FORMAT);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(sealed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_format_parses() {
        let ct = assemble(7, &[1; 12], &[2; 16]);
        assert_eq!(ct.len(), MIN_LEN);
        let s = Sealed::parse(&ct).unwrap();
        assert_eq!(
            (s.version, s.nonce, s.body),
            (7, [1_u8; 12], &[2_u8; 16][..])
        );
        assert!(Sealed::parse(&ct[..MIN_LEN - 1]).is_none());
        let mut other = ct.clone();
        other[0] = 2;
        assert!(Sealed::parse(&other).is_none());
        assert!(Sealed::parse(b"").is_none());
    }

    #[test]
    fn parts_never_run_together() {
        let a = aad(&Field::new("ab", "c", "d", "e"), 1);
        let b = aad(&Field::new("a", "bc", "d", "e"), 1);
        assert_ne!(a, b);
        assert_ne!(wrap_context("s", "data", 1), wrap_context("s", "index", 1));
    }
}
