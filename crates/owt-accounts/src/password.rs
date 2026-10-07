//! The rules a new password meets. Hashing and checking are [`owt_auth::password`];
//! this is what a sign-up or a password change refuses before hashing.

use std::fmt;

/// The fewest characters a password has.
pub const MIN_CHARS: usize = 8;

/// The most bytes a password has: Argon2 is run on it, and a request's worth of
/// text passed off as a password must not be hashed.
pub const MAX_BYTES: usize = 1024;

/// A rule a password breaks. Its `Display` is the sentence the person reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Fewer than [`MIN_CHARS`] characters.
    TooShort,
    /// More than [`MAX_BYTES`] bytes.
    TooLong,
    /// Digits only.
    Numeric,
    /// Contains the username, or the local part of the email.
    Similar,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "This password is too short: use at least 8 characters.",
            Self::TooLong => "This password is too long.",
            Self::Numeric => "This password is entirely numeric.",
            Self::Similar => "This password is too similar to your username or email.",
        })
    }
}

/// The problems joined into one message, for [`crate::Refused::Password`].
#[must_use]
pub fn describe(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every rule `password` breaks, given what it must not resemble: the username, the
/// email (its local part is what counts). Empty when it passes.
#[must_use]
pub fn check(password: &str, like: &[&str]) -> Vec<Problem> {
    let mut problems = Vec::new();
    if password.chars().count() < MIN_CHARS {
        problems.push(Problem::TooShort);
    }
    if password.len() > MAX_BYTES {
        problems.push(Problem::TooLong);
    }
    if !password.is_empty() && password.chars().all(|c| c.is_ascii_digit()) {
        problems.push(Problem::Numeric);
    }
    let lower = password.to_lowercase();
    let similar = like.iter().any(|name| {
        let name = name.split('@').next().unwrap_or("").trim().to_lowercase();
        // A fragment of one or two characters is in most passwords; it says nothing.
        name.chars().count() >= 3 && lower.contains(&name)
    });
    if similar {
        problems.push(Problem::Similar);
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_rule_fires_on_its_own() {
        assert_eq!(check("short", &[]), vec![Problem::TooShort]);
        assert_eq!(check("12345678901", &[]), vec![Problem::Numeric]);
        assert_eq!(check("alice-secret", &["Alice"]), vec![Problem::Similar]);
        assert_eq!(
            check("alice-secret", &["alice@example.com"]),
            vec![Problem::Similar]
        );
        assert_eq!(
            check(&"x".repeat(MAX_BYTES + 1), &[]),
            vec![Problem::TooLong]
        );
        assert_eq!(
            check("a good passphrase", &["bob", "b@x.com"]),
            Vec::<Problem>::new()
        );
    }

    #[test]
    fn a_short_name_is_not_a_similarity() {
        assert_eq!(
            check("abracadabra", &["ab", "a@x.com"]),
            Vec::<Problem>::new()
        );
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // Eight two-byte characters: long enough.
        assert_eq!(check("ééééééééé", &[]), Vec::<Problem>::new());
    }

    #[test]
    fn the_message_lists_every_problem() {
        let text = describe(&check("1234567", &[]));
        assert!(
            text.contains("too short") && text.contains("numeric"),
            "{text}"
        );
    }
}
