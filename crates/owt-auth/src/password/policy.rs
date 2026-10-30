//! The password policy: NIST SP 800-63B-4 (revision 4, 2025) §3.1.1.2, "Password
//! Verifiers".
//!
//! What it requires, and what it deliberately does not:
//!
//! * **Length, in characters.** Revision 4 sets the minimum by how the password is
//!   used: **15** when it is the only authenticator, **8** only when it is one factor of
//!   a multi-factor pair. The default [`Policy::new`] is 8, so use it only where a second
//!   factor is *required* of every account the policy covers; for a password that can
//!   sign in alone use [`Policy::single_factor`] (15). [`Policy::min_len`] raises either.
//!   The maximum is 128 ([`Policy::max_len`], never below 64, the least the standard
//!   says to permit). Characters are Unicode code points after NFKC normalization
//!   ("Unicode normalization … SHOULD be applied"), and [`hash`](super::hash) and
//!   [`verify`](super::verify) normalize the same way, so a password counts and opens
//!   the same however a keyboard composed it. Callers bound the request body; `check`
//!   refuses anything over four bytes per permitted character before it normalizes or
//!   hashes a thing.
//! * **Every printable character, spaces included.** No character is refused.
//! * **No composition rules.** The standard says verifiers "SHOULD NOT impose other
//!   composition rules (e.g., requiring mixtures of different character types)":
//!   they push people to `Password1!`, which every cracking dictionary tries first,
//!   and add no entropy a longer password does not.
//! * **No periodic expiry.** "Verifiers SHOULD NOT require memorized secrets to be
//!   changed arbitrarily (e.g., periodically)"; change is forced only on evidence of
//!   compromise. Forced rotation yields `Summer2026`, then `Autumn2026`. This type
//!   has no age check, and an app should not add one.
//! * **A blocklist is part of the minimum.** Revision 4 makes it a requirement, not an
//!   option: give the policy a corpus ([`Policy::breached`]) in production. Without one it
//!   checks length and context only.
//! * **A blocklist, not a pattern.** A password is refused if it is in a corpus of
//!   breached passwords, equals or contains the account's username or the local part
//!   of its email, or contains a context word the app passes (the service's name, the
//!   person's name): the standard's "context-specific words" and "values obtained from
//!   previous breach corpuses". Names shorter than [`MIN_NEEDLE_LEN`] are not checked: a
//!   short username inside a longer password is not caught, and the password is not
//!   refused for being equal to one (it is too short already).
//!
//! The breach check is offline: the corpus is a file the app ships ([`SortedHashes`]
//! or the smaller [`Bloom`]), and **no network request is ever made**: the Pwned
//! Passwords range API sends a hash prefix of every password to a third party, which a
//! health-records system should not do.
//!
//! ```
//! use owt_auth::password::{Context, Policy, Refusal};
//!
//! let policy = Policy::new().min_len(12);
//! let ctx = Context::new().username("annlee").email("ann.lee@example.com");
//! assert!(policy.check("correct horse battery staple", &ctx).is_ok());
//! let refusals = policy.check("annlee-2026", &ctx).unwrap_err();
//! assert!(refusals.contains(&Refusal::TooShort { min: 12 }));
//! assert!(refusals.contains(&Refusal::ContainsUsername));
//! ```

use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use sha1::{Digest, Sha1};
use unicode_normalization::UnicodeNormalization;

/// The shortest minimum length a [`Policy`] takes (NIST SP 800-63B §5.1.1.2).
pub const MIN_LEN_FLOOR: usize = 8;
/// The smallest maximum length a [`Policy`] takes: a verifier must permit at least 64.
pub const MAX_LEN_FLOOR: usize = 64;
/// The minimum for a password that is the only authenticator (SP 800-63B-4 §3.1.1.2).
pub const SINGLE_FACTOR_MIN_LEN: usize = 15;
/// The shortest username, email local part or context word that a password is refused
/// for containing. Shorter ones (`al`, `ed`) would refuse a great many good passwords;
/// a password that is only such a name is refused for being too short anyway.
pub const MIN_NEEDLE_LEN: usize = 4;

/// A corpus of breached passwords: asked about the SHA-1 of a candidate.
pub trait Breached: Send + Sync {
    /// Whether the password whose SHA-1 is `sha1_upper_hex` (40 upper-case hex digits)
    /// is in the corpus. A [`Bloom`] may answer `true` for a password that is not, never
    /// `false` for one that is.
    fn contains(&self, sha1_upper_hex: &str) -> bool;
}

/// What a password is checked against besides its own shape: facts about the account.
#[derive(Clone, Debug, Default)]
pub struct Context<'a> {
    username: Option<&'a str>,
    email: Option<&'a str>,
    words: Vec<&'a str>,
}

impl<'a> Context<'a> {
    /// No context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The account's username.
    #[must_use]
    pub fn username(mut self, username: &'a str) -> Self {
        self.username = Some(username);
        self
    }

    /// The account's email address; its local part (before the last `@`) is checked.
    #[must_use]
    pub fn email(mut self, email: &'a str) -> Self {
        self.email = Some(email);
        self
    }

    /// A word the password must not contain: the service's name, the person's name.
    #[must_use]
    pub fn word(mut self, word: &'a str) -> Self {
        self.words.push(word);
        self
    }

    /// Words the password must not contain.
    #[must_use]
    pub fn words(mut self, words: impl IntoIterator<Item = &'a str>) -> Self {
        self.words.extend(words);
        self
    }
}

/// Why a password was refused. [`Display`](std::fmt::Display) is text a form can show.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// Fewer than `min` characters.
    #[error("Use at least {min} characters.")]
    TooShort {
        /// The minimum.
        min: usize,
    },
    /// More than `max` characters.
    #[error("Use at most {max} characters.")]
    TooLong {
        /// The maximum.
        max: usize,
    },
    /// Equal to or containing the username.
    #[error("Do not use your username in your password.")]
    ContainsUsername,
    /// Equal to or containing the email address's name part.
    #[error("Do not use your email address in your password.")]
    ContainsEmail,
    /// Containing a word the app listed.
    #[error("Do not use the name of this service or your own name in your password.")]
    ContainsContextWord,
    /// In the corpus of breached passwords.
    #[error("That password has appeared in a data breach. Choose another.")]
    Breached,
}

/// The rules a new password must satisfy. See the [module](self) for the choices.
#[derive(Clone)]
pub struct Policy {
    min_len: usize,
    max_len: usize,
    breached: Option<Arc<dyn Breached>>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("min_len", &self.min_len)
            .field("max_len", &self.max_len)
            .field("breached", &self.breached.is_some())
            .finish()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_len: MIN_LEN_FLOOR,
            max_len: 128,
            breached: None,
        }
    }
}

impl Policy {
    /// The defaults: 8 to 128 characters, no breach corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The policy for a password that can sign in on its own: at least 15 characters
    /// (SP 800-63B-4), otherwise [`new`](Self::new)'s.
    #[must_use]
    pub fn single_factor() -> Self {
        Self::default().min_len(SINGLE_FACTOR_MIN_LEN)
    }

    /// At least `n` characters (never fewer than 8).
    #[must_use]
    pub fn min_len(mut self, n: usize) -> Self {
        self.min_len = n.max(MIN_LEN_FLOOR);
        self
    }

    /// At most `n` characters (never fewer than 64).
    #[must_use]
    pub fn max_len(mut self, n: usize) -> Self {
        self.max_len = n.max(MAX_LEN_FLOOR);
        self
    }

    /// Refuse passwords the corpus holds.
    #[must_use]
    pub fn breached(mut self, corpus: impl Breached + 'static) -> Self {
        self.breached = Some(Arc::new(corpus));
        self
    }

    /// Check a new password.
    ///
    /// # Errors
    /// Every rule it breaks, in a fixed order, for a form to list.
    pub fn check(&self, password: &str, context: &Context<'_>) -> Result<(), Vec<Refusal>> {
        // The longest `max_len` characters can be in UTF-8 is four bytes each; beyond that
        // nothing needs normalizing, scanning or hashing to be refused.
        if password.len() > self.max_len.saturating_mul(4) {
            return Err(vec![Refusal::TooLong { max: self.max_len }]);
        }
        let normalized: String = password.nfkc().collect();
        let len = normalized.chars().count();
        let mut refusals = Vec::new();
        if len < self.min_len {
            refusals.push(Refusal::TooShort { min: self.min_len });
        }
        if len > self.max_len {
            refusals.push(Refusal::TooLong { max: self.max_len });
        }
        let folded = fold(&normalized);
        let contains = |needle: &str| {
            let needle = fold(needle);
            needle.chars().count() >= MIN_NEEDLE_LEN && folded.contains(&needle)
        };
        if context.username.is_some_and(contains) {
            refusals.push(Refusal::ContainsUsername);
        }
        if context.email.is_some_and(|email| {
            let local = email.rsplit_once('@').map_or(email, |(local, _)| local);
            contains(local) || contains(local.split('+').next().unwrap_or(local))
        }) {
            refusals.push(Refusal::ContainsEmail);
        }
        if context.words.iter().any(|w| contains(w)) {
            refusals.push(Refusal::ContainsContextWord);
        }
        if let Some(corpus) = &self.breached {
            // HIBP hashes the password as typed; the normalized form is checked too.
            let mut forms = vec![password];
            if normalized != password {
                forms.push(&normalized);
            }
            if forms.into_iter().any(|p| corpus.contains(&sha1_hex(p))) {
                refusals.push(Refusal::Breached);
            }
        }
        if refusals.is_empty() {
            Ok(())
        } else {
            Err(refusals)
        }
    }
}

/// NFKC and lower case: what names and passwords are compared as.
fn fold(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase()
}

fn sha1_hex(password: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha1::digest(password.as_bytes());
    digest.iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

/// 20 bytes from 40 hex digits (either case), or `None`.
fn parse_hash(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.as_bytes();
    if hex.len() != 40 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut out = [0u8; 20];
    for (slot, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
        *slot = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

/// The hash on a corpus line: `HASH` or `HASH:count`, as the Pwned Passwords downloads
/// write it. Blank lines are skipped by the callers.
fn line_hash(line: &str) -> anyhow::Result<[u8; 20]> {
    let line = line.strip_prefix('\u{feff}').unwrap_or(line);
    let hash = line.split(':').next().unwrap_or(line).trim();
    parse_hash(hash).with_context(|| {
        let shown: String = hash.chars().take(60).collect();
        format!(
            "not a SHA-1 hash: {shown:?}; expected 40 hexadecimal digits per line, optionally \
             followed by `:count` (the Pwned Passwords download), not the 35-character suffixes \
             of its range API"
        )
    })
}

/// The longest line read: a hash is 40 digits and `:count` a dozen more. A longer one
/// is not a corpus, and is refused before it is held (a file with no newlines would
/// otherwise be read whole into one line).
const MAX_LINE: usize = 128;

/// Call `f(number, line)` for each non-blank line of `reader`, trimmed, holding one line
/// at a time.
fn each_line(
    reader: impl BufRead,
    mut f: impl FnMut(usize, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut reader = reader;
    let mut line = String::new();
    let mut number = 0usize;
    loop {
        line.clear();
        // One byte more than the longest line and its newline: no newline in them means
        // the line is too long.
        let read = (&mut reader)
            .take(MAX_LINE as u64 + 2)
            .read_line(&mut line)?;
        if read == 0 {
            return Ok(());
        }
        number += 1;
        anyhow::ensure!(
            line.ends_with('\n') || read <= MAX_LINE,
            "line {number} is longer than {MAX_LINE} bytes: this is not a file of SHA-1 hashes, \
             one per line"
        );
        let text = line.trim();
        if !text.is_empty() {
            f(number, text)?;
        }
    }
}

/// The hashes in `reader`, one per line. `reserve` is a guess at how many, from the
/// file's size.
fn read_hashes(reader: impl BufRead, reserve: usize) -> anyhow::Result<Vec<[u8; 20]>> {
    let mut hashes = Vec::with_capacity(reserve);
    each_line(reader, |number, text| {
        hashes.push(line_hash(text).with_context(|| format!("line {number}"))?);
        Ok(())
    })?;
    Ok(hashes)
}

/// A corpus held in memory as sorted 20-byte hashes, searched by binary search.
///
/// Built from a file of SHA-1 hex lines, `HASH` or `HASH:count`, in any order (the
/// Pwned Passwords download is sorted already, which makes the sort free). Each hash
/// takes 20 bytes of memory: the full Pwned Passwords corpus (about 1 billion hashes)
/// would take 20 GB, so load a subset (its most-used 10 to 100 million passwords is 200 MB
/// to 2 GB) or use a [`Bloom`], which is 3 to 4 bytes a hash.
#[derive(Clone, Debug, Default)]
pub struct SortedHashes(Vec<[u8; 20]>);

impl SortedHashes {
    /// From lines of hex hashes, each `HASH` or `HASH:count`; blank lines are skipped.
    ///
    /// # Errors
    /// A line that is not a SHA-1 hash.
    pub fn from_lines<I, S>(lines: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hashes = Vec::new();
        for line in lines {
            let line = line.as_ref().trim();
            if !line.is_empty() {
                hashes.push(line_hash(line)?);
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        Ok(Self(hashes))
    }

    /// Read a file of hash lines into memory, a line at a time: the memory used is
    /// the 20 bytes a hash and nothing more (the sort is in place). A leading UTF-8 byte
    /// order mark is ignored.
    ///
    /// # Errors
    /// The file cannot be read, or a line (named) is not a SHA-1 hash.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        // A line is 40 hex digits and a newline at least: 41 bytes (more with `:count`).
        let reserve = file
            .metadata()
            .map_or(0, |m| usize::try_from(m.len() / 41).unwrap_or(0));
        let mut hashes = read_hashes(std::io::BufReader::new(file), reserve)
            .with_context(|| format!("reading {}", path.display()))?;
        hashes.sort_unstable();
        hashes.dedup();
        hashes.shrink_to_fit();
        Ok(Self(hashes))
    }

    /// How many hashes are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Breached for SortedHashes {
    fn contains(&self, sha1_upper_hex: &str) -> bool {
        parse_hash(sha1_upper_hex).is_some_and(|h| self.0.binary_search(&h).is_ok())
    }
}

const BLOOM_MAGIC: &[u8; 8] = b"OWTBLOOM";
const BLOOM_VERSION: u32 = 1;
/// magic, version, bits (m), hashes (k), seed.
const BLOOM_HEADER: usize = 8 + 4 + 8 + 4 + 8;
/// The largest filter [`Bloom::load`] accepts: 8 GiB of bits.
const BLOOM_MAX_BITS: u64 = 1 << 36;

/// A bloom filter over a corpus: a few bytes a hash instead of 20.
///
/// A password it holds is always found; one it does not hold is wrongly reported as
/// breached with probability about the `fp_rate` it was built for (a person is asked to
/// choose another password, a harmless error). At `fp_rate` 1e-6 it takes 3.6 bytes
/// per hash, so 100 million hashes need 360 MB.
///
/// # File format
///
/// All integers little-endian: the bytes `OWTBLOOM`, a `u32` version (1), `m` (`u64`,
/// the bits), `k` (`u32`, the hash functions), the `seed` (`u64`), then `ceil(m / 8)`
/// bytes of bits. The two 64-bit hashes of an entry are taken from its SHA-1 (already
/// uniform), mixed with the seed, and combined as `h1 + i * h2 mod m` for `i < k`
/// (Kirsch and Mitzenmacher, "Less Hashing, Same Performance").
#[derive(Clone, Debug)]
pub struct Bloom {
    m: u64,
    k: u32,
    seed: u64,
    bits: Vec<u8>,
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(a)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(a)
}

fn mix(mut x: u64) -> u64 {
    // SplitMix64's finalizer.
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl Bloom {
    fn indexes(&self, hash: &[u8; 20]) -> impl Iterator<Item = u64> + use<> {
        let (a, b) = (u64_at(hash, 0), u64_at(hash, 8));
        let h1 = mix(a ^ self.seed);
        let h2 = mix(b ^ self.seed.rotate_left(32)) | 1;
        let m = self.m;
        (0..u64::from(self.k)).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % m)
    }

    fn insert(&mut self, hash: &[u8; 20]) {
        for i in self.indexes(hash).collect::<Vec<_>>() {
            self.bits[(i / 8) as usize] |= 1 << (i % 8);
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )] // the sizes are bounded by BLOOM_MAX_BITS, far under f64's exact integers
    fn empty(entries: usize, fp_rate: f64, seed: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            fp_rate > 0.0 && fp_rate < 1.0,
            "the false-positive rate is between 0 and 1: {fp_rate}"
        );
        let n = entries.max(1) as f64;
        let ln2 = std::f64::consts::LN_2;
        let m = (-n * fp_rate.ln() / (ln2 * ln2)).ceil().max(64.0);
        anyhow::ensure!(
            m <= BLOOM_MAX_BITS as f64,
            "a filter of {m} bits is too large"
        );
        let m = m as u64;
        let k = ((m as f64 / n) * ln2).round().clamp(1.0, 32.0) as u32;
        Ok(Self {
            m,
            k,
            seed,
            bits: vec![0; usize::try_from(m.div_ceil(8))?],
        })
    }

    /// A filter holding `lines` (each `HASH` or `HASH:count`; blank lines skipped),
    /// sized for `fp_rate` (between 0 and 1, such as `1e-6`). The iterator is walked
    /// twice, first to count: pass a clonable one (a slice's, a `Vec`'s), or use
    /// [`build_from_file`](Self::build_from_file). The seed is random.
    ///
    /// # Errors
    /// A line that is not a SHA-1 hash, a bad `fp_rate`, or a filter too large.
    pub fn build<I, S>(lines: I, fp_rate: f64) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        I::IntoIter: Clone,
        S: AsRef<str>,
    {
        let lines = lines.into_iter();
        let entries = lines
            .clone()
            .filter(|l| !l.as_ref().trim().is_empty())
            .count();
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("reading random bytes: {e}"))?;
        let mut bloom = Self::empty(entries, fp_rate, u64::from_le_bytes(seed))?;
        for line in lines {
            let line = line.as_ref().trim();
            if !line.is_empty() {
                bloom.insert(&line_hash(line)?);
            }
        }
        Ok(bloom)
    }

    /// [`build`](Self::build) from a file of hash lines, reading it twice and never
    /// holding the corpus in memory.
    ///
    /// # Errors
    /// As [`build`](Self::build), or the file cannot be read.
    pub fn build_from_file(path: impl AsRef<Path>, fp_rate: f64) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let open = || {
            std::fs::File::open(path)
                .map(std::io::BufReader::new)
                .with_context(|| format!("opening {}", path.display()))
        };
        let mut entries = 0usize;
        each_line(open()?, |_, _| {
            entries += 1;
            Ok(())
        })?;
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("reading random bytes: {e}"))?;
        let mut bloom = Self::empty(entries, fp_rate, u64::from_le_bytes(seed))?;
        each_line(open()?, |number, text| {
            bloom.insert(&line_hash(text).with_context(|| format!("line {number}"))?);
            Ok(())
        })?;
        Ok(bloom)
    }

    /// The false-positive rate expected with `entries` hashes inserted:
    /// `(1 - e^(-k n / m))^k`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // an estimate
    pub fn expected_fp_rate(&self, entries: usize) -> f64 {
        let (k, n, m) = (f64::from(self.k), entries as f64, self.m as f64);
        (1.0 - (-k * n / m).exp()).powf(k)
    }

    /// Bits in the filter.
    #[must_use]
    pub fn bits(&self) -> u64 {
        self.m
    }

    /// Hash functions per entry.
    #[must_use]
    pub fn hashes(&self) -> u32 {
        self.k
    }

    /// Write the filter in the format described on the type.
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        let mut out = std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        );
        out.write_all(BLOOM_MAGIC)?;
        out.write_all(&BLOOM_VERSION.to_le_bytes())?;
        out.write_all(&self.m.to_le_bytes())?;
        out.write_all(&self.k.to_le_bytes())?;
        out.write_all(&self.seed.to_le_bytes())?;
        out.write_all(&self.bits)?;
        out.flush()
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Read a filter [`save`](Self::save) wrote.
    ///
    /// # Errors
    /// The file cannot be read, is not a filter, or is truncated or has trailing bytes.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let mut file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut header = [0u8; BLOOM_HEADER];
        file.read_exact(&mut header)
            .with_context(|| format!("{} is too short to be a bloom filter", path.display()))?;
        anyhow::ensure!(
            &header[..8] == BLOOM_MAGIC,
            "{} is not a bloom filter",
            path.display()
        );
        let version = u32_at(&header, 8);
        anyhow::ensure!(version == BLOOM_VERSION, "bloom filter version {version}");
        let (m, k, seed) = (
            u64_at(&header, 12),
            u32_at(&header, 20),
            u64_at(&header, 24),
        );
        anyhow::ensure!(m > 0 && m <= BLOOM_MAX_BITS, "bloom filter of {m} bits");
        anyhow::ensure!((1..=64).contains(&k), "bloom filter with {k} hashes");
        let expected = m.div_ceil(8);
        // The size is checked before any allocation of it.
        let actual = file.metadata()?.len().saturating_sub(BLOOM_HEADER as u64);
        anyhow::ensure!(
            actual == expected,
            "{} holds {actual} bytes of bits, its header says {expected}",
            path.display()
        );
        let mut bits = vec![0u8; usize::try_from(expected)?];
        file.read_exact(&mut bits)?;
        Ok(Self { m, k, seed, bits })
    }
}

impl Breached for Bloom {
    fn contains(&self, sha1_upper_hex: &str) -> bool {
        parse_hash(sha1_upper_hex).is_some_and(|h| {
            self.indexes(&h)
                .all(|i| self.bits[(i / 8) as usize] & (1 << (i % 8)) != 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<String> {
        // HIBP lines: hash, a colon, a count.
        ["password", "123456", "qwerty123", "letmein!!", "iloveyou1"]
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{}:{}", sha1_hex(p), 1000 - i))
            .collect()
    }

    #[test]
    fn sha1_hex_is_the_pwned_passwords_form() {
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn a_sorted_corpus_finds_its_hashes_and_nothing_else() {
        let mut lines = corpus();
        lines.push(String::new());
        lines.push(sha1_hex("password").to_lowercase());
        let c = SortedHashes::from_lines(&lines).unwrap();
        assert_eq!(c.len(), 5, "deduplicated, blanks skipped");
        for p in ["password", "123456", "qwerty123", "letmein!!", "iloveyou1"] {
            assert!(c.contains(&sha1_hex(p)), "{p}");
        }
        assert!(!c.contains(&sha1_hex("a long and unusual passphrase")));
        assert!(!c.contains("nonsense") && !c.contains(""));
        assert!(SortedHashes::from_lines(["not-a-hash"]).is_err());
    }

    #[test]
    fn a_corpus_opens_from_a_file() {
        let dir = std::env::temp_dir().join(format!("owt-policy-{}", crate::random_token(8)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("hashes.txt");
        std::fs::write(&path, corpus().join("\r\n")).unwrap();
        let c = SortedHashes::open(&path).unwrap();
        assert!(c.contains(&sha1_hex("123456")));
        let bloom = Bloom::build_from_file(&path, 1e-6).unwrap();
        assert!(bloom.contains(&sha1_hex("123456")));
        assert!(SortedHashes::open(dir.join("missing")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_file_with_a_byte_order_mark_opens_and_a_bad_line_is_named() {
        let dir = std::env::temp_dir().join(format!("owt-bom-{}", crate::random_token(8)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("hashes.txt");
        let mut text = String::from("\u{feff}");
        text.push_str(&corpus().join("\n"));
        std::fs::write(&path, text).unwrap();
        assert_eq!(SortedHashes::open(&path).unwrap().len(), 5);
        assert!(
            Bloom::build_from_file(&path, 1e-6)
                .unwrap()
                .contains(&sha1_hex("password"))
        );
        // The range API's 35-character suffixes are not this format.
        std::fs::write(&path, format!("{}\n{}\n", corpus()[0], &sha1_hex("x")[5..])).unwrap();
        let e = format!("{:#}", SortedHashes::open(&path).unwrap_err());
        assert!(
            e.contains("line 2") && e.contains("40 hexadecimal digits"),
            "{e}"
        );
        // A file with no newlines is refused at 128 bytes, not read whole.
        std::fs::write(&path, "a".repeat(10_000)).unwrap();
        let e = format!("{:#}", SortedHashes::open(&path).unwrap_err());
        assert!(e.contains("longer than 128 bytes"), "{e}");
        assert!(Bloom::build_from_file(&path, 1e-6).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_single_factor_password_needs_15_and_oversized_input_is_refused_at_once() {
        let none = Context::new();
        let p = Policy::single_factor();
        assert_eq!(
            p.check("12345678901234", &none),
            Err(vec![Refusal::TooShort { min: 15 }])
        );
        assert!(p.check("123456789012345", &none).is_ok());
        let huge = "a".repeat(5 * 128);
        assert_eq!(
            Policy::new().check(&huge, &none),
            Err(vec![Refusal::TooLong { max: 128 }])
        );
        // Four-byte characters at the maximum are not oversized.
        assert!(Policy::new().check(&"\u{1f511}".repeat(128), &none).is_ok());
    }

    #[test]
    fn a_bloom_filter_has_no_false_negatives_and_few_false_positives() {
        let lines: Vec<String> = (0..2000)
            .map(|i| sha1_hex(&format!("breached-{i}")))
            .collect();
        let bloom = Bloom::build(lines.iter(), 0.01).unwrap();
        assert!(lines.iter().all(|l| bloom.contains(l)));
        let false_positives = (0..20_000)
            .filter(|i| bloom.contains(&sha1_hex(&format!("fine-{i}"))))
            .count();
        // 1% asked for; 3% is slack for the variance of one seed.
        assert!(false_positives < 600, "{false_positives} of 20000");
        assert!(bloom.expected_fp_rate(2000) < 0.02);
        let tiny = Bloom::build(corpus().iter(), 1e-6).unwrap();
        assert!(tiny.contains(&sha1_hex("password")));
        assert!(!tiny.contains(&sha1_hex("a long and unusual passphrase")));
    }

    #[test]
    fn a_bloom_filter_saves_and_loads_and_refuses_damage() {
        let dir = std::env::temp_dir().join(format!("owt-bloom-{}", crate::random_token(8)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("bloom.bin");
        let bloom = Bloom::build(corpus().iter(), 1e-4).unwrap();
        bloom.save(&path).unwrap();
        let loaded = Bloom::load(&path).unwrap();
        assert_eq!(
            (loaded.bits(), loaded.hashes()),
            (bloom.bits(), bloom.hashes())
        );
        assert!(loaded.contains(&sha1_hex("qwerty123")));
        assert!(!loaded.contains(&sha1_hex("a long and unusual passphrase")));

        let bytes = std::fs::read(&path).unwrap();
        let bad = |name: &str, data: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, data).unwrap();
            assert!(Bloom::load(&p).is_err(), "{name}");
        };
        bad("truncated", &bytes[..bytes.len() - 1]);
        bad("trailing", &[&bytes[..], &[0]].concat());
        bad("short", &bytes[..10]);
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        bad("magic", &magic);
        let mut zero_k = bytes.clone();
        zero_k[20..24].copy_from_slice(&0u32.to_le_bytes());
        bad("zero-k", &zero_k);
        let mut huge = bytes.clone();
        huge[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        bad("huge", &huge);
        std::fs::remove_dir_all(dir).unwrap();
        assert!(Bloom::build(["x"], 0.0).is_err() && Bloom::build(["x"], 1.0).is_err());
    }

    #[test]
    fn length_counts_code_points_after_nfkc() {
        let p = Policy::new();
        let none = Context::new();
        assert_eq!(
            p.check("1234567", &none),
            Err(vec![Refusal::TooShort { min: 8 }])
        );
        assert!(p.check("12345678", &none).is_ok());
        // Eight code points but sixteen bytes.
        assert!(p.check("ééééééé€", &none).is_ok());
        // `ﬁ` (one ligature code point) is two letters after NFKC: 7 -> 8.
        assert!(p.check("ﬁ12345\u{20}", &none).is_ok());
        assert!(p.check("ﬁ1234 ", &none).is_err());
        // A decomposed `é` is one code point once composed.
        assert!(
            p.check(
                "e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}",
                &none
            )
            .is_err()
        );
        assert!(
            p.check(
                "e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}",
                &none
            )
            .is_ok()
        );
        // Spaces and symbols are allowed.
        assert!(p.check("correct horse battery staple", &none).is_ok());
        assert!(p.check("        ", &none).is_ok(), "no composition rules");
        assert!(
            p.check("password", &none).is_ok(),
            "no corpus, no breach check"
        );
        // Configurable, with floors.
        assert_eq!(
            Policy::new().min_len(12).check("12345678901", &none),
            Err(vec![Refusal::TooShort { min: 12 }])
        );
        assert!(Policy::new().min_len(3).check("1234567", &none).is_err());
        let long = "a".repeat(128);
        assert!(p.check(&long, &none).is_ok());
        assert_eq!(
            p.check(&format!("{long}a"), &none),
            Err(vec![Refusal::TooLong { max: 128 }])
        );
        assert!(
            Policy::new()
                .max_len(10)
                .check(&"a".repeat(64), &none)
                .is_ok()
        );
        assert!(
            Policy::new()
                .max_len(10)
                .check(&"a".repeat(65), &none)
                .is_err()
        );
    }

    #[test]
    fn names_and_context_words_are_refused_in_any_case() {
        let p = Policy::new();
        let ctx = Context::new()
            .username("Ann.Lee")
            .email("Robert+work@example.com")
            .words(["Sunrise Clinic", "ab"]);
        assert_eq!(
            p.check("xxANN.leexx", &ctx),
            Err(vec![Refusal::ContainsUsername])
        );
        assert_eq!(
            p.check("my-robert-1", &ctx),
            Err(vec![Refusal::ContainsEmail])
        );
        assert_eq!(
            p.check("RoBeRt+WoRk!", &ctx),
            Err(vec![Refusal::ContainsEmail])
        );
        assert_eq!(
            p.check("the SUNRISE clinic 99", &ctx),
            Err(vec![Refusal::ContainsContextWord])
        );
        // The domain is not part of the local name; a two-letter word is too short to ban.
        assert!(p.check("example.com tab 12", &ctx).is_ok());
        // Several at once, in a fixed order.
        assert_eq!(
            p.check("ann.lee robert", &ctx),
            Err(vec![Refusal::ContainsUsername, Refusal::ContainsEmail])
        );
        // Full-width letters fold to the same name.
        assert!(p.check("ＡＮＮ．ＬＥＥ-1", &ctx).is_err());
    }

    #[test]
    fn the_breach_corpus_is_consulted_for_the_typed_and_the_normalized_form() {
        let p = Policy::new().breached(SortedHashes::from_lines(corpus()).unwrap());
        let none = Context::new();
        assert_eq!(p.check("password", &none), Err(vec![Refusal::Breached]));
        assert!(p.check("qwerty123", &none).is_err());
        assert!(p.check("a long and unusual passphrase", &none).is_ok());
        // `ｐassword` with a full-width p normalizes to a breached password.
        assert_eq!(p.check("ｐassword", &none), Err(vec![Refusal::Breached]));
        let p = Policy::new().breached(Bloom::build(corpus().iter(), 1e-9).unwrap());
        assert_eq!(p.check("123456 !!", &none), Ok(()));
        assert_eq!(p.check("letmein!!", &none), Err(vec![Refusal::Breached]));
    }

    #[test]
    fn refusals_read_as_sentences() {
        for r in [
            Refusal::TooShort { min: 12 },
            Refusal::TooLong { max: 128 },
            Refusal::ContainsUsername,
            Refusal::ContainsEmail,
            Refusal::ContainsContextWord,
            Refusal::Breached,
        ] {
            let text = r.to_string();
            assert!(text.ends_with('.') && text.len() > 15, "{text}");
        }
        assert_eq!(
            Refusal::TooShort { min: 12 }.to_string(),
            "Use at least 12 characters."
        );
        assert!(format!("{:?}", Policy::new()).contains("min_len"));
    }
}
