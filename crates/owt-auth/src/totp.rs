//! Time-based one-time passwords (RFC 6238 over RFC 4226): the six-digit codes
//! authenticator apps show.
//!
//! The parameters are the ones every authenticator app implements: HMAC-SHA1, six
//! digits, a 30-second step. (SHA-1 is safe here: HMAC does not depend on collision
//! resistance, and the apps ignore any other algorithm named in the URI.)
//!
//! A [`Secret`] is 20 random bytes from the operating system's generator, wrapped in
//! `Zeroizing` so the memory is wiped when it drops (as are the copies made decoding
//! base32 and the HMAC key schedule), a constant-time `==`, and a `Debug` that prints
//! nothing of it. Show the person [`Secret::to_base32`] or [`otpauth_uri`] (for a QR code) once,
//! at enrollment; store the bytes sealed at rest.
//!
//! [`verify`] accepts the current step and one either side (clock skew), compares in
//! constant time, and refuses any step at or before the last one accepted: a code seen
//! once, even by an eavesdropper who replays it within its 90 seconds, signs in no
//! second time. It returns the step that matched, which the caller must store (in the
//! same transaction that completes the sign-in) as the next call's `last_used_step`.
//!
//! Guessing six digits is a one in a million chance an attempt: the caller throttles
//! attempts per account ([`crate::throttle`]) so that 90 seconds of guessing stays hopeless.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Digits in a code.
pub const DIGITS: u32 = 6;
/// Seconds a code lasts.
pub const PERIOD: u64 = 30;
/// Bytes in a generated secret (RFC 4226 recommends 160 bits).
pub const SECRET_BYTES: usize = 20;

/// The shortest and longest secret [`Secret::from_bytes`] takes: RFC 4226 §4 requires
/// 128 bits at least; 64 bytes is the HMAC block size, beyond which a key is only hashed.
const KEY_LEN: std::ops::RangeInclusive<usize> = 16..=64;

/// A TOTP shared secret. Dropping it zeroes its memory; `Debug` redacts it.
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl PartialEq for Secret {
    /// In constant time for secrets of one length.
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Secret {}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// A new secret of [`SECRET_BYTES`] random bytes from the operating system.
    ///
    /// # Errors
    /// The system's random source failed.
    pub fn generate() -> anyhow::Result<Self> {
        let mut bytes = Zeroizing::new(vec![0u8; SECRET_BYTES]);
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("reading random bytes: {e}"))?;
        Ok(Self(bytes))
    }

    /// A secret from stored bytes. `None` unless there are 16 to 64 of them.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        KEY_LEN
            .contains(&bytes.len())
            .then(|| Self(Zeroizing::new(bytes.to_vec())))
    }

    /// The bytes, to store (sealed) or to hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret in RFC 4648 base32 without padding, the form an authenticator app
    /// takes when a person types it in.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(base32_encode(&self.0))
    }

    /// A secret from the base32 an authenticator app shows: case, spaces, hyphens and
    /// trailing `=` are ignored. `None` for anything else or a bad length.
    #[must_use]
    pub fn from_base32(text: &str) -> Option<Self> {
        Self::from_bytes(&base32_decode(text)?)
    }
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').chars() {
        if c == ' ' || c == '-' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
            buf &= (1 << bits) - 1;
        }
    }
    // Leftover bits are padding; they must be zero in a canonical encoding.
    (buf == 0).then_some(out)
}

/// `s` with everything but RFC 3986 unreserved characters percent-encoded.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The `otpauth://totp/` URI an authenticator app reads from a QR code:
/// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`.
/// `issuer` and `account` are percent-encoded. The app shows `account` in the
/// authenticator's list, so use an email or display name, not an internal id.
/// The URI holds the secret: show it once, over TLS, and never log it.
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret: &Secret) -> Zeroizing<String> {
    let (issuer, account) = (percent_encode(issuer), percent_encode(account));
    Zeroizing::new(format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        *secret.to_base32(),
    ))
}

/// The step (counter) a moment falls in; `None` before 1970.
#[must_use]
pub fn step_at(now: SystemTime) -> Option<u64> {
    Some(now.duration_since(UNIX_EPOCH).ok()?.as_secs() / PERIOD)
}

/// HOTP (RFC 4226 §5.3) with dynamic truncation, `digits` digits long.
fn hotp(key: &[u8], counter: u64, digits: u32) -> u32 {
    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let word = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    word % 10u32.pow(digits)
}

/// The code for `step`: `digits` digits, zero-padded.
fn code_for(key: &[u8], step: u64, digits: u32) -> String {
    format!(
        "{:0width$}",
        hotp(key, step, digits),
        width = digits as usize
    )
}

/// The six-digit code for `step`. For tests, and for an app that shows a code in a
/// demo; sign-in uses [`verify`].
#[must_use]
pub fn code(secret: &Secret, step: u64) -> String {
    code_for(&secret.0, step, DIGITS)
}

/// The code as typed, or `None`: exactly [`DIGITS`] ASCII digits once spaces at either
/// end are trimmed (a pasted code often carries one). Spaces in the middle, other
/// digits (full-width, Arabic-Indic) and signs are refused.
fn clean(input: &str, digits: u32) -> Option<&str> {
    let code = input.trim_matches(|c: char| c.is_ascii_whitespace());
    (code.len() == digits as usize && code.bytes().all(|b| b.is_ascii_digit())).then_some(code)
}

fn verify_digits(
    key: &[u8],
    input: &str,
    now: SystemTime,
    last_used_step: Option<u64>,
    digits: u32,
) -> Option<u64> {
    let code = clean(input, digits)?;
    let current = step_at(now)?;
    let mut matched = None;
    // All three candidates are always computed and compared, whichever matches.
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        let expected = code_for(key, step, digits);
        let equal: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
        if equal && last_used_step.is_none_or(|last| step > last) {
            matched = Some(step);
        }
    }
    matched
}

/// Whether `code` is valid at `now`: the step of `now`, or one either side. A step at
/// or before `last_used_step` is refused, so each code works once. Returns the matched
/// step; store it as the account's new `last_used_step`.
///
/// Surrounding ASCII whitespace is trimmed; the code must otherwise be exactly six
/// ASCII digits.
#[must_use]
pub fn verify(
    secret: &Secret,
    code: &str,
    now: SystemTime,
    last_used_step: Option<u64>,
) -> Option<u64> {
    verify_digits(&secret.0, code, now, last_used_step, DIGITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const RFC_KEY: &[u8] = b"12345678901234567890";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// RFC 6238 Appendix B, the SHA-1 column (eight digits).
    #[test]
    fn rfc_6238_appendix_b_vectors() {
        for (t, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(code_for(RFC_KEY, t / PERIOD, 8), expected, "T={t}");
            assert_eq!(
                verify_digits(RFC_KEY, expected, at(t), None, 8),
                Some(t / PERIOD)
            );
        }
    }

    /// RFC 4226 Appendix D, the HOTP values the TOTP construction rests on.
    #[test]
    fn rfc_4226_appendix_d_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(code_for(RFC_KEY, counter as u64, 6), *want);
        }
    }

    fn secret() -> Secret {
        Secret::from_bytes(RFC_KEY).unwrap()
    }

    #[test]
    fn the_adjacent_steps_are_accepted_and_no_others() {
        let s = secret();
        let now = at(1_111_111_111);
        let step = step_at(now).unwrap();
        for ok in [step - 1, step, step + 1] {
            assert_eq!(verify(&s, &code(&s, ok), now, None), Some(ok));
        }
        for bad in [step - 2, step + 2] {
            assert_eq!(verify(&s, &code(&s, bad), now, None), None);
        }
    }

    #[test]
    fn a_step_is_accepted_once() {
        let s = secret();
        let now = at(1_111_111_111);
        let step = step_at(now).unwrap();
        let c = code(&s, step);
        let used = verify(&s, &c, now, None).unwrap();
        assert_eq!(verify(&s, &c, now, Some(used)), None, "replayed");
        // An earlier step than the last used is refused too, even inside the window.
        assert_eq!(verify(&s, &code(&s, step - 1), now, Some(used)), None);
        // The next step is fine.
        assert_eq!(
            verify(&s, &code(&s, step + 1), now, Some(used)),
            Some(step + 1)
        );
    }

    #[test]
    fn malformed_codes_are_refused() {
        let s = secret();
        let now = at(59);
        let good = code(&s, 1);
        assert_eq!(verify(&s, &good, now, None), Some(1));
        assert_eq!(verify(&s, &format!("  {good}\n"), now, None), Some(1));
        let spaced = format!("{} {}", &good[..3], &good[3..]);
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "+12345",
            "-12345",
            "１２３４５６", // full-width digits
            "١٢٣٤٥٦",       // Arabic-Indic digits
            spaced.as_str(),
            "\u{0}123456",
        ] {
            assert_eq!(verify(&s, bad, now, None), None, "{bad:?}");
        }
    }

    #[test]
    fn time_before_the_epoch_and_the_first_steps_do_not_wrap() {
        let s = secret();
        assert_eq!(
            verify(&s, "000000", UNIX_EPOCH - Duration::from_secs(5), None),
            None
        );
        // Step 0: step - 1 saturates rather than wrapping to u64::MAX.
        let c0 = code(&s, 0);
        assert_eq!(verify(&s, &c0, at(0), None), Some(0));
    }

    #[test]
    fn base32_round_trips_and_matches_rfc_4648() {
        for (raw, enc) in [
            (&b""[..], ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(raw), enc);
            assert_eq!(*base32_decode(enc).unwrap(), raw);
        }
        assert_eq!(*base32_decode("mzxw 6ytb-OI====").unwrap(), b"foobar");
        assert_eq!(base32_decode("MZXW1"), None, "1 is not in the alphabet");
        assert_eq!(base32_decode("MZ"), None, "non-zero trailing bits");
        let s = secret();
        assert_eq!(Secret::from_base32(&s.to_base32()).unwrap(), s);
        assert!(Secret::from_base32("MZXW6YTB").is_none(), "too short a key");
    }

    #[test]
    fn a_generated_secret_is_20_random_bytes_and_hides_itself() {
        let (a, b) = (Secret::generate().unwrap(), Secret::generate().unwrap());
        assert_eq!(a.as_bytes().len(), SECRET_BYTES);
        assert_ne!(a, b);
        let shown = format!("{a:?}");
        assert_eq!(shown, "Secret(<redacted>)");
        assert_eq!(a.to_base32().len(), 32);
        assert!(Secret::from_bytes(&[0; 15]).is_none() && Secret::from_bytes(&[0; 65]).is_none());
    }

    #[test]
    fn the_uri_names_the_parameters_and_encodes_the_names() {
        let s = secret();
        let uri = otpauth_uri("Acme Health", "ann+x@example.com", &s);
        assert_eq!(
            *uri,
            format!(
                "otpauth://totp/Acme%20Health:ann%2Bx%40example.com?secret={}\
                 &issuer=Acme%20Health&algorithm=SHA1&digits=6&period=30",
                *s.to_base32()
            )
        );
        assert_eq!(percent_encode("a:b/c?d&e=é"), "a%3Ab%2Fc%3Fd%26e%3D%C3%A9");
    }
}
