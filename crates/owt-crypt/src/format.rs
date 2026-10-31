//! The stored formats: ciphertexts, their associated data, and the contexts data
//! keys are wrapped under. All are fixed: a change is a new format byte or domain.
//!
//! A ciphertext is `format || version (u32, big-endian) || nonce || sealed bytes`. Two
//! formats exist ([`Format`]):
//!
//! * `0x02`, written by every seal: a 24-byte random nonce, then XChaCha20-Poly1305
//!   output (plaintext length + 16).
//! * `0x01`, read only: a 12-byte random nonce, then AES-256-GCM output (plaintext
//!   length + 16). [`crate::Crypt::reencrypt`] moves such a value to `0x02`.
//!
//! Its associated data is
//! `FIELD_DOMAIN || format || lp(scope) || lp(table) || lp(column) || lp(row) || version`,
//! so a ciphertext whose format byte is edited (a `0x02` value presented as `0x01`, or
//! the reverse) does not open: the byte picks the cipher and is authenticated by it.
//! `lp(x)` is `x`'s length as a big-endian u32, then `x`. A data key's wrap context
//! is `WRAP_DOMAIN || lp(scope) || lp(purpose) || version`. A blind index is
//! HMAC-SHA256 over `INDEX_DOMAIN || lp(table) || lp(column) || lp(value)`.

use crate::Field;

/// A ciphertext format: the cipher its format byte names, and that cipher's nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// `0x01`: AES-256-GCM with a random 96-bit nonce. Read, never written.
    AesGcm,
    /// `0x02`: XChaCha20-Poly1305 with a random 192-bit nonce. Every seal writes it.
    XChaCha20Poly1305,
}

impl Format {
    /// The format byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::AesGcm => 1,
            Self::XChaCha20Poly1305 => 2,
        }
    }

    /// The format a byte names, if any.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::AesGcm),
            2 => Some(Self::XChaCha20Poly1305),
            _ => None,
        }
    }

    /// The nonce's length.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::AesGcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// The shortest ciphertext of this format: an empty plaintext's.
    #[must_use]
    pub const fn min_len(self) -> usize {
        1 + 4 + self.nonce_len() + TAG_LEN
    }
}

/// The format every seal writes.
pub const CURRENT: Format = Format::XChaCha20Poly1305;
/// The tag's length, in both formats.
pub const TAG_LEN: usize = 16;
/// The prefix of a field's associated data.
pub const FIELD_DOMAIN: &[u8] = b"owt-crypt/field/v1\0";
/// The prefix of a data key's wrap context.
pub const WRAP_DOMAIN: &[u8] = b"owt-crypt/key/v1\0";
/// The prefix of a blind index's input.
pub const INDEX_DOMAIN: &[u8] = b"owt-crypt/index/v1\0";

/// A ciphertext's parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed<'a> {
    /// Its format.
    pub format: Format,
    /// The data key version that sealed it.
    pub version: u32,
    /// Its nonce, [`Format::nonce_len`] bytes.
    pub nonce: &'a [u8],
    /// The sealed bytes, tag included.
    pub body: &'a [u8],
}

impl<'a> Sealed<'a> {
    /// The parts of `bytes`, if it is a ciphertext of a known format.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let format = Format::from_byte(*bytes.first()?)?;
        if bytes.len() < format.min_len() {
            return None;
        }
        let version = u32::from_be_bytes(bytes[1..5].try_into().ok()?);
        let (nonce, body) = bytes[5..].split_at(format.nonce_len());
        Some(Self {
            format,
            version,
            nonce,
            body,
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

/// The associated data of `field`'s value sealed in `format` under key `version`.
#[must_use]
pub fn aad(format: Format, field: &Field<'_>, version: u32) -> Vec<u8> {
    let mut out = FIELD_DOMAIN.to_vec();
    out.push(format.byte());
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
///
/// # Panics
///
/// When `nonce` is not `format`'s nonce length.
#[must_use]
pub fn assemble(format: Format, version: u32, nonce: &[u8], sealed: &[u8]) -> Vec<u8> {
    assert_eq!(
        nonce.len(),
        format.nonce_len(),
        "a nonce of the format's length"
    );
    let mut out = Vec::with_capacity(5 + nonce.len() + sealed.len());
    out.push(format.byte());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(sealed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_formats_parse() {
        let ct = assemble(Format::AesGcm, 7, &[1; 12], &[2; 16]);
        assert_eq!(ct.len(), Format::AesGcm.min_len());
        let s = Sealed::parse(&ct).unwrap();
        assert_eq!(
            (s.format, s.version, s.nonce, s.body),
            (Format::AesGcm, 7, &[1_u8; 12][..], &[2_u8; 16][..])
        );
        assert!(Sealed::parse(&ct[..Format::AesGcm.min_len() - 1]).is_none());

        let ct = assemble(Format::XChaCha20Poly1305, 7, &[1; 24], &[2; 16]);
        assert_eq!(ct.len(), Format::XChaCha20Poly1305.min_len());
        let s = Sealed::parse(&ct).unwrap();
        assert_eq!(
            (s.format, s.version, s.nonce, s.body),
            (
                Format::XChaCha20Poly1305,
                7,
                &[1_u8; 24][..],
                &[2_u8; 16][..]
            )
        );
        assert!(Sealed::parse(&ct[..Format::XChaCha20Poly1305.min_len() - 1]).is_none());

        for byte in [0, 3, 255] {
            let mut other = ct.clone();
            other[0] = byte;
            assert!(Sealed::parse(&other).is_none(), "{byte}");
        }
        assert!(Sealed::parse(b"").is_none());
        assert_eq!(CURRENT, Format::XChaCha20Poly1305);
        for f in [Format::AesGcm, Format::XChaCha20Poly1305] {
            assert_eq!(Format::from_byte(f.byte()), Some(f));
        }
    }

    #[test]
    fn parts_never_run_together() {
        let a = aad(CURRENT, &Field::new("ab", "c", "d", "e"), 1);
        let b = aad(CURRENT, &Field::new("a", "bc", "d", "e"), 1);
        assert_ne!(a, b);
        // The format byte is part of the associated data.
        let f = Field::new("a", "b", "c", "d");
        assert_ne!(
            aad(Format::AesGcm, &f, 1),
            aad(Format::XChaCha20Poly1305, &f, 1)
        );
        assert_ne!(wrap_context("s", "data", 1), wrap_context("s", "index", 1));
    }
}
