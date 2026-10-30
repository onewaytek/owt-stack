//! Recovery codes: the single-use codes a person keeps for the day the authenticator
//! is lost.
//!
//! A code is ten characters of the Crockford base32 alphabet (`0-9` and `A-Z` without
//! `I`, `L`, `O`, `U`), shown as `XXXXX-XXXXX`: 50 bits of entropy from the operating
//! system's generator. [`generate`] returns each with the hash to store; the code
//! itself is shown once and kept nowhere.
//!
//! # Why Argon2id and not a peppered HMAC
//!
//! Fifty bits is too little to store a bare fast hash, but plenty against a slow,
//! memory-hard one: an attacker who copies the table pays 19 MiB and tens of
//! milliseconds a guess, and 2^49 expected guesses per code is out of reach. A keyed
//! HMAC-SHA256 would be cheaper per check and allow an indexed lookup, but only while
//! its pepper stays secret, which makes it one more secret to hold, rotate and lose
//! (the pepper and the table leaking together, as in one backup, leaves 50 bits). Argon2id
//! needs nothing but the table, reuses [`password`](crate::password)'s hasher with its
//! bound on concurrent hashes, and its `needs_rehash` raises old hashes when the cost
//! is raised. The price is that [`find_match`] hashes against each unused code in turn
//! (at most [`DEFAULT_COUNT`] checks, each on the blocking pool); an attempt is
//! throttled before this, as a password is.
//!
//! # Single use
//!
//! [`find_match`] only says which stored hash matches. The caller makes the code
//! single-use, by deleting the row or marking it used, in the transaction that
//! completes the sign-in, and passes only unused codes to [`find_match`]. Two requests
//! racing with one code must not both succeed: make the update conditional
//! (`UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL`) and sign in only
//! when it changed a row.

use anyhow::Context as _;

/// Codes [`generate`] makes unless asked for another number.
pub const DEFAULT_COUNT: usize = 10;

/// Characters in a code, hyphen excluded.
pub const CODE_LEN: usize = 10;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A new recovery code and the hash to store for it.
#[derive(Clone)]
pub struct Recovery {
    /// The code to show the person once, as `XXXXX-XXXXX`. Keep it nowhere.
    pub code: String,
    /// The Argon2id PHC string to store.
    pub hash: String,
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovery")
            .field("code", &"<redacted>")
            .field("hash", &self.hash)
            .finish()
    }
}

/// `count` new codes, each with its hash (Argon2id, on the blocking pool).
///
/// # Errors
/// The system's random source or hashing failed.
pub async fn generate(count: usize) -> anyhow::Result<Vec<Recovery>> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut raw = [0u8; CODE_LEN];
        getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("reading random bytes: {e}"))?;
        // 32 symbols: the low five bits are uniform, with no modulo bias.
        let canonical: String = raw
            .iter()
            .map(|b| ALPHABET[usize::from(b & 31)] as char)
            .collect();
        let hash = crate::password::hash(&canonical)
            .await
            .context("hashing a recovery code")?;
        out.push(Recovery {
            code: format!("{}-{}", &canonical[..5], &canonical[5..]),
            hash,
        });
    }
    Ok(out)
}

/// The canonical form of what a person typed: upper case, hyphens and whitespace
/// dropped, `I` and `L` read as `1`, `O` as `0` (Crockford's rules). `None` unless that
/// is [`CODE_LEN`] characters of the alphabet, so a malformed guess costs no hash.
#[must_use]
pub fn normalize(input: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' | '\t' | '\n' | '\r' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) || out.len() == CODE_LEN {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// The index in `hashes` of the one that `input` matches, or `None`. Pass only the
/// hashes of unused codes. A malformed input returns at once; otherwise each hash is
/// checked in turn until one matches.
pub async fn find_match<S: AsRef<str>>(input: &str, hashes: &[S]) -> Option<usize> {
    let code = normalize(input)?;
    for (i, stored) in hashes.iter().enumerate() {
        if crate::password::verify(&code, stored.as_ref()).await {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_codes_are_normalized() {
        assert_eq!(normalize("abcde-fghjk").unwrap(), "ABCDEFGHJK");
        assert_eq!(normalize(" ABCDE FGHJK\n").unwrap(), "ABCDEFGHJK");
        // I and L read as 1; O reads as 0.
        assert_eq!(normalize("il1o0-0O1Ll").unwrap(), "1110000111");
        for bad in [
            "",
            "ABCDE",
            "ABCDE-FGHJK1",
            "ABCDE-FGHJU",
            "ABCDE-FGHJ!",
            "ＡＢＣＤＥ-ＦＧＨＪＫ",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn generated_codes_match_their_own_hash_only() {
        let codes = generate(3).await.unwrap();
        assert_eq!(codes.len(), 3);
        for c in &codes {
            assert_eq!(c.code.len(), 11);
            assert_eq!(c.code.as_bytes()[5], b'-');
            assert_eq!(normalize(&c.code).unwrap().len(), CODE_LEN);
            assert!(c.hash.starts_with("$argon2id$"));
            assert!(!format!("{c:?}").contains(&c.code));
        }
        assert_ne!(codes[0].code, codes[1].code);
        let hashes: Vec<&str> = codes.iter().map(|c| c.hash.as_str()).collect();
        // Typed lower case, without the hyphen, and with the look-alike letters.
        let typed = codes[1].code.to_lowercase().replace('-', " ");
        assert_eq!(find_match(&typed, &hashes).await, Some(1));
        assert_eq!(find_match(&codes[2].code, &hashes).await, Some(2));
        assert_eq!(find_match("ZZZZZ-ZZZZZ", &hashes).await, None);
        assert_eq!(find_match("nonsense", &hashes).await, None);
        // A used code is passed no more, and then matches nothing.
        assert_eq!(find_match(&codes[1].code, &hashes[..1]).await, None);
        assert_eq!(
            find_match(&codes[0].code, &Vec::<String>::new()).await,
            None
        );
    }
}
