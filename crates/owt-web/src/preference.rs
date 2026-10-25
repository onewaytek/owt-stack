//! Preference cookies: a language, a theme, a reading mode.
//!
//! A preference is not a session. It is unsealed, long-lived and readable by the
//! page's scripts, so it holds a choice from a closed set and nothing else. The
//! attributes are where one goes wrong, so a [`Preference`] fixes them: `Secure`,
//! `SameSite=Lax`, `Path=/`, a `Max-Age` capped at 400 days (the longest a browser
//! keeps one), and no `Domain`, so a sibling host does not receive it.
//!
//! * **Reading** answers only with a member of the allowed set; a value outside it,
//!   markup or a smuggled second cookie included, reads as unset.
//! * **Setting** refuses a value outside the set, and encodes the one it accepts.
//! * **The name** is checked once, in [`Preference::new`]: a cookie-name token that is
//!   not the session's cookie (with or without its `__Host-` prefix), because a
//!   preference that shares the session's name overwrites the session or is read as one.
//!
//! Name it `__Host-<name>`: browsers then refuse a copy set over plain HTTP or by a
//! sibling subdomain.
//!
//! ```
//! use std::time::Duration;
//! use owt_web::preference::Preference;
//! # let session_cookie = "__Host-session";
//!
//! let theme = Preference::new(
//!     "__Host-theme",
//!     &["light", "dark"],
//!     Duration::from_secs(365 * 86_400),
//!     session_cookie,
//! )
//! .unwrap();
//! let set = theme.set("dark").unwrap(); // a Set-Cookie value
//! # let _ = set;
//! ```

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};
use cookie::{Cookie, SameSite};

/// The longest a browser keeps a cookie: 400 days.
pub const MAX_AGE: Duration = Duration::from_hours(400 * 24);

/// A name [`Preference::new`] refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BadName {
    /// Empty, or with a character a cookie name cannot carry (a separator, a space, a
    /// control character, anything outside ASCII).
    #[error("{0:?} is not a cookie name")]
    NotAToken(String),
    /// No allowed value, or one that is not a cookie value: printable ASCII without
    /// space, `"`, `,`, `;` or `\\`, which `set` writes as is and `read` compares as is.
    #[error("the allowed values must be a non-empty set of plain cookie values")]
    Allowed,
    /// The session's cookie, or the same name without its `__Host-`/`__Secure-` prefix.
    #[error("{0:?} is the session cookie's name")]
    Session(String),
}

/// A preference cookie: its name, the values it may hold, and how long it lasts.
#[derive(Clone, Debug)]
pub struct Preference {
    name: String,
    allowed: Vec<&'static str>,
    max_age: Duration,
}

/// The name without a `__Host-` or `__Secure-` prefix, in lower case: the bare name a
/// browser would let the prefixed one shadow.
fn bare(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    ["__host-", "__secure-"]
        .iter()
        .find_map(|p| lower.strip_prefix(p))
        .unwrap_or(&lower)
        .to_owned()
}

/// RFC 6265 `token`: the characters a cookie name may use.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A cookie value that needs no encoding (RFC 6265 `cookie-octet`, and not empty).
fn is_value(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E))
}

impl Preference {
    /// A preference cookie `name` that holds one of `allowed`, kept for `max_age`
    /// (at most [`MAX_AGE`], at least a second). `session_cookie` is the session's
    /// cookie name (`Sessions::cookie_name`); the name must differ from it. `allowed`
    /// is not empty and holds plain cookie values (letters, digits, `-`, `_`, ...).
    pub fn new(
        name: &str,
        allowed: &[&'static str],
        max_age: Duration,
        session_cookie: &str,
    ) -> Result<Self, BadName> {
        if !is_token(name) {
            return Err(BadName::NotAToken(name.to_owned()));
        }
        if allowed.is_empty() || !allowed.iter().all(|v| is_value(v)) {
            return Err(BadName::Allowed);
        }
        if bare(name) == bare(session_cookie) {
            return Err(BadName::Session(name.to_owned()));
        }
        Ok(Self {
            name: name.to_owned(),
            allowed: allowed.to_vec(),
            max_age: max_age.clamp(Duration::from_secs(1), MAX_AGE),
        })
    }

    /// The cookie's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The request's value: the first cookie of this name that holds an allowed value,
    /// else `None`.
    #[must_use]
    pub fn read(&self, headers: &HeaderMap) -> Option<&'static str> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|raw| Cookie::split_parse_encoded(raw.to_owned()).flatten())
            .filter(|c| c.name() == self.name)
            .find_map(|c| self.allowed.iter().find(|a| **a == c.value()).copied())
    }

    /// The `Set-Cookie` value that stores `value`, or `None` for one outside the
    /// allowed set.
    #[must_use]
    pub fn set(&self, value: &str) -> Option<HeaderValue> {
        let value = self.allowed.iter().find(|a| **a == value)?;
        Some(self.cookie(value, self.max_age))
    }

    /// The `Set-Cookie` value that removes the cookie.
    #[must_use]
    pub fn clear(&self) -> HeaderValue {
        self.cookie("", Duration::ZERO)
    }

    fn cookie(&self, value: &str, max_age: Duration) -> HeaderValue {
        let secs = i64::try_from(max_age.as_secs()).unwrap_or(i64::MAX);
        let c = Cookie::build((self.name.as_str(), value))
            .path("/")
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(secs))
            .build();
        // A token name and a percent-encoded value are always a valid header value.
        HeaderValue::from_str(&c.encoded().to_string()).expect("a cookie is a header value")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn theme() -> Preference {
        Preference::new(
            "__Host-theme",
            &["light", "dark"],
            Duration::from_hours(24),
            "__Host-session",
        )
        .unwrap()
    }

    fn request(cookies: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for c in cookies {
            h.append(header::COOKIE, HeaderValue::from_str(c).unwrap());
        }
        h
    }

    #[test]
    fn reads_only_the_allowed_set() {
        let p = theme();
        assert_eq!(p.read(&request(&["__Host-theme=dark"])), Some("dark"));
        assert_eq!(
            p.read(&request(&["a=b; __Host-theme=light; c=d"])),
            Some("light")
        );
        assert_eq!(p.read(&request(&["__Host-theme=solarized"])), None);
        assert_eq!(p.read(&request(&["__Host-theme=<b>"])), None);
        assert_eq!(p.read(&request(&["__Host-theme=dark%3B%20x=y"])), None);
        assert_eq!(p.read(&request(&["theme=dark"])), None, "another name");
        assert_eq!(p.read(&HeaderMap::new()), None);
    }

    #[test]
    fn a_duplicate_does_not_hide_an_allowed_value() {
        let p = theme();
        let h = request(&["__Host-theme=junk; __Host-theme=dark"]);
        assert_eq!(p.read(&h), Some("dark"));
        let h = request(&["__Host-theme=junk", "__Host-theme=light"]);
        assert_eq!(p.read(&h), Some("light"));
    }

    #[test]
    fn set_writes_every_protective_attribute() {
        let v = theme().set("dark").unwrap();
        let s = v.to_str().unwrap();
        assert!(s.starts_with("__Host-theme=dark;"), "{s}");
        for attr in ["Secure", "SameSite=Lax", "Path=/", "Max-Age=86400"] {
            assert!(s.contains(attr), "{attr} in {s}");
        }
        assert!(!s.contains("Domain"), "{s}");
        assert!(!s.contains("HttpOnly"), "scripts may read a theme: {s}");
        assert_eq!(theme().set("solarized"), None);
        assert_eq!(theme().set("dark; Domain=x"), None);
    }

    #[test]
    fn the_lifetime_is_bounded() {
        let long = Preference::new("p", &["a"], Duration::from_secs(u64::MAX), "s").unwrap();
        let s = long.set("a").unwrap();
        assert!(s.to_str().unwrap().contains("Max-Age=34560000"), "{s:?}");
        let none = Preference::new("p", &["a"], Duration::ZERO, "s").unwrap();
        assert!(
            none.set("a")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=1")
        );
    }

    #[test]
    fn clear_expires_it_with_the_same_scope() {
        let v = theme().clear();
        let s = v.to_str().unwrap();
        assert!(s.starts_with("__Host-theme=;"), "{s}");
        for attr in ["Secure", "SameSite=Lax", "Path=/", "Max-Age=0"] {
            assert!(s.contains(attr), "{attr} in {s}");
        }
    }

    #[test]
    fn a_name_must_be_a_token_apart_from_the_session() {
        let ok = |n: &str, s: &str| Preference::new(n, &["a"], Duration::ZERO, s);
        for bad in ["", "a b", "a;b", "a=b", "a\nb", "é", "a,b"] {
            assert!(
                matches!(ok(bad, "s"), Err(BadName::NotAToken(_))),
                "{bad:?}"
            );
        }
        for same in ["session", "__Host-session", "Session"] {
            assert!(
                matches!(ok(same, "__Host-session"), Err(BadName::Session(_))),
                "{same}"
            );
        }
        assert!(matches!(ok("__Host-sid", "sid"), Err(BadName::Session(_))));
        assert!(ok("__Host-theme", "__Host-session").is_ok());
    }

    #[test]
    fn the_allowed_set_is_not_empty_and_holds_plain_values() {
        let with = |allowed: &[&'static str]| Preference::new("p", allowed, Duration::ZERO, "s");
        assert!(matches!(with(&[]), Err(BadName::Allowed)));
        for bad in ["", "a b", "a;b", "a,b", "a\"b", "a\\b", "é", "a\nb"] {
            assert!(
                matches!(with(&["ok", bad]), Err(BadName::Allowed)),
                "{bad:?}"
            );
        }
        assert!(with(&["en", "pt-BR", "dark_2"]).is_ok());
    }
}
