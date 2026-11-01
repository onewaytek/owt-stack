//! The stored formats: ciphertexts, their associated data, and the contexts data
//! keys are wrapped under. All are fixed: a change is a new format byte or domain.
//!
//! A ciphertext is `format || version (u32, big-endian) || nonce || sealed bytes`.
//! Three formats exist ([`Format`]):
//!
//! * `0x02`, written by every seal: a 24-byte random nonce, then XChaCha20-Poly1305
//!   output (plaintext length + 16).
//! * `0x03`, written by a padded seal ([`crate::Crypt::encrypt_padded`],
//!   [`crate::Sealer::seal_padded`]): `0x02`'s construction over the plaintext padded
//!   to a multiple of its [`Padding`] bucket, ISO/IEC 7816-4 style (one `0x80` byte,
//!   then `0x00` bytes up to the boundary; always at least the `0x80`). The padding is
//!   inside the AEAD and the format byte is in the associated data, so neither can be
//!   changed or stripped without the value being refused. Opening removes it.
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

use std::num::NonZeroUsize;

use zeroize::Zeroizing;

use crate::Field;

/// A ciphertext format: the cipher its format byte names, and that cipher's nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// `0x01`: AES-256-GCM with a random 96-bit nonce. Read, never written.
    AesGcm,
    /// `0x02`: XChaCha20-Poly1305 with a random 192-bit nonce. Every seal writes it.
    XChaCha20Poly1305,
    /// `0x03`: [`Format::XChaCha20Poly1305`] over a plaintext padded to a [`Padding`]
    /// bucket ([`pad`]). Padded seals write it.
    XChaCha20Poly1305Padded,
}

impl Format {
    /// The format byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::AesGcm => 1,
            Self::XChaCha20Poly1305 => 2,
            Self::XChaCha20Poly1305Padded => 3,
        }
    }

    /// The format a byte names, if any.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::AesGcm),
            2 => Some(Self::XChaCha20Poly1305),
            3 => Some(Self::XChaCha20Poly1305Padded),
            _ => None,
        }
    }

    /// The nonce's length.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::AesGcm => 12,
            Self::XChaCha20Poly1305 | Self::XChaCha20Poly1305Padded => 24,
        }
    }

    /// Whether this is a format seals write today: one that
    /// [`crate::Crypt::reencrypt`] leaves alone under the current key.
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(
            self,
            Self::XChaCha20Poly1305 | Self::XChaCha20Poly1305Padded
        )
    }

    /// The shortest ciphertext of this format: an empty plaintext's.
    #[must_use]
    pub const fn min_len(self) -> usize {
        1 + 4 + self.nonce_len() + TAG_LEN
    }
}

/// The format every seal writes.
pub const CURRENT: Format = Format::XChaCha20Poly1305;
/// The format every padded seal writes.
pub const PADDED: Format = Format::XChaCha20Poly1305Padded;
/// The tag's length, in both formats.
pub const TAG_LEN: usize = 16;
/// The prefix of a field's associated data.
pub const FIELD_DOMAIN: &[u8] = b"owt-crypt/field/v1\0";
/// The prefix of a data key's wrap context.
pub const WRAP_DOMAIN: &[u8] = b"owt-crypt/key/v1\0";
/// The prefix of a blind index's input.
pub const INDEX_DOMAIN: &[u8] = b"owt-crypt/index/v1\0";

/// The bucket a padded seal rounds a plaintext's length up to, so values whose lengths
/// differ within one bucket have ciphertexts of one length. For a field whose length
/// says something (a short code against a long one, a name, a diagnosis' wording).
/// A padded value costs at least one byte and at most a bucket more than an unpadded
/// one. It hides the length within a bucket only: choose the bucket to cover the
/// lengths that must not be told apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Padding(NonZeroUsize);

impl Padding {
    /// 64-byte buckets.
    pub const DEFAULT: Self = Self(NonZeroUsize::new(64).expect("64 is not zero"));

    /// Buckets of `bucket` bytes.
    #[must_use]
    pub const fn new(bucket: NonZeroUsize) -> Self {
        Self(bucket)
    }

    /// The bucket, in bytes.
    #[must_use]
    pub const fn bucket(self) -> usize {
        self.0.get()
    }

    /// The length a plaintext of `len` bytes has once padded: the next multiple of the
    /// bucket above `len` (a `len` already on a boundary takes a whole bucket more,
    /// for the `0x80` byte).
    #[must_use]
    pub const fn padded_len(self, len: usize) -> usize {
        (len / self.bucket() + 1) * self.bucket()
    }
}

impl Default for Padding {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// `plaintext` padded to `padding`'s bucket: `plaintext || 0x80 || 0x00*`, of
/// [`Padding::padded_len`] bytes.
#[must_use]
pub fn pad(plaintext: &[u8], padding: Padding) -> Zeroizing<Vec<u8>> {
    let len = padding.padded_len(plaintext.len());
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(len, 0);
    out
}

/// The plaintext [`pad`] padded, or `None` when `padded` does not end in `0x80` and
/// then only `0x00` bytes. It runs only on authenticated bytes, so its timing tells
/// nothing an attacker could not learn from the length.
#[must_use]
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let end = padded.iter().rposition(|&b| b != 0)?;
    (padded[end] == 0x80).then(|| &padded[..end])
}

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

        for byte in [0, 4, 255] {
            let mut other = ct.clone();
            other[0] = byte;
            assert!(Sealed::parse(&other).is_none(), "{byte}");
        }
        assert!(Sealed::parse(b"").is_none());
        assert_eq!(CURRENT, Format::XChaCha20Poly1305);
        for f in [
            Format::AesGcm,
            Format::XChaCha20Poly1305,
            Format::XChaCha20Poly1305Padded,
        ] {
            assert_eq!(Format::from_byte(f.byte()), Some(f));
        }
        let mut padded = ct.clone();
        padded[0] = 3;
        assert_eq!(
            Sealed::parse(&padded).unwrap().format,
            Format::XChaCha20Poly1305Padded
        );
        assert_eq!(PADDED, Format::XChaCha20Poly1305Padded);
    }

    /// The bucket edges: one short of a boundary fills it with the `0x80` alone; on a
    /// boundary takes a whole bucket more; every length in a bucket pads alike.
    #[test]
    fn padding_rounds_up_to_the_bucket_and_comes_off_exactly() {
        let p = Padding::new(NonZeroUsize::new(16).unwrap());
        assert_eq!(Padding::default(), Padding::DEFAULT);
        assert_eq!(Padding::DEFAULT.bucket(), 64);
        for (len, padded) in [
            (0, 16),
            (1, 16),
            (15, 16),
            (16, 32),
            (17, 32),
            (31, 32),
            (32, 48),
        ] {
            assert_eq!(p.padded_len(len), padded, "{len}");
            // Trailing zeros and 0x80s in the value itself survive.
            let value: Vec<u8> = (0..len).map(|i| [0x00, 0x80, 0x41][i % 3]).collect();
            let out = pad(&value, p);
            assert_eq!(out.len(), padded, "{len}");
            assert_eq!(out[len], 0x80);
            assert!(out[len + 1..].iter().all(|&b| b == 0));
            assert_eq!(unpad(&out), Some(&value[..]), "{len}");
        }
        // Not padding: no marker, a marker followed by something else, nothing at all.
        assert_eq!(unpad(b""), None);
        assert_eq!(unpad(&[0, 0, 0]), None);
        assert_eq!(unpad(b"abc\x00\x00"), None);
        assert_eq!(unpad(b"abc\x80\x01"), None);
        assert_eq!(unpad(b"\x80"), Some(&b""[..]));
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
