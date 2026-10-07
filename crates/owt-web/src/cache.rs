//! HTTP cache policies, typed.
//!
//! Every response falls in one class, and the class is a decision, not a string:
//!
//! * [`CachePolicy::immutable`]: the bytes are fully determined by the URL (a content
//!   hash, a fingerprint); cache forever, everywhere.
//! * [`CachePolicy::public`]: the same for everyone for a while: a browser lifetime,
//!   optionally a longer edge (CDN) lifetime, optionally stale-while-revalidate.
//! * [`CachePolicy::public_until`]: the same for everyone until a known moment (the
//!   next simulation tick, the next scheduled publish); the edge keeps it until then,
//!   browsers only briefly, so a person sees the change soon after it happens.
//! * [`CachePolicy::no_store`]: anything that differs per person or per session.
//!   Unset, `headers::private_by_default` and `headers::no_store_by_default` decide.
//!
//! A public policy must never be set on a response that carries per-person content
//! or a `Set-Cookie`: the edge would serve it to everyone. Pages and their htmx
//! fragments get distinct URLs ([`crate::fragment`]), never one URL varying by a
//! request header.
//!
//! A policy is a response part (`(policy, body).into_response()`) and converts into
//! the header value [`crate::fragment::Fragment`] takes.

use std::time::Duration;

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponseParts, ResponseParts};

/// A `Cache-Control` decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CachePolicy(Kind);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Immutable,
    NoStore,
    Public {
        browser: Duration,
        edge: Option<Duration>,
        stale: Option<Duration>,
    },
}

impl CachePolicy {
    /// Bytes fully determined by the URL: `public, max-age=31536000, immutable`.
    pub const fn immutable() -> Self {
        Self(Kind::Immutable)
    }

    /// Per-person or per-session content: `no-store`.
    pub const fn no_store() -> Self {
        Self(Kind::NoStore)
    }

    /// The same for everyone, for `max_age` in browsers and at the edge alike.
    pub const fn public(max_age: Duration) -> Self {
        Self(Kind::Public {
            browser: max_age,
            edge: None,
            stale: None,
        })
    }

    /// The same for everyone until `remaining` from now: the edge keeps it that long,
    /// a browser at most `browser_cap` of it, so a person sees the change within the
    /// cap of it happening and the edge never serves it past the moment.
    pub fn public_until(remaining: Duration, browser_cap: Duration) -> Self {
        Self(Kind::Public {
            browser: remaining.min(browser_cap),
            edge: Some(remaining),
            stale: None,
        })
    }

    /// A longer (or shorter) lifetime at the edge than in browsers: `s-maxage`.
    /// No effect on [`immutable`](Self::immutable) or [`no_store`](Self::no_store).
    pub fn edge(self, s_maxage: Duration) -> Self {
        match self.0 {
            Kind::Public { browser, stale, .. } => Self(Kind::Public {
                browser,
                edge: Some(s_maxage),
                stale,
            }),
            other => Self(other),
        }
    }

    /// Serve a stale copy for up to `window` while fetching a fresh one in the
    /// background. No effect on [`immutable`](Self::immutable) or
    /// [`no_store`](Self::no_store).
    pub fn stale_while_revalidate(self, window: Duration) -> Self {
        match self.0 {
            Kind::Public { browser, edge, .. } => Self(Kind::Public {
                browser,
                edge,
                stale: Some(window),
            }),
            other => Self(other),
        }
    }

    /// Whether a shared cache may keep the response.
    #[must_use]
    pub fn is_public(self) -> bool {
        !matches!(self.0, Kind::NoStore)
    }

    /// The `Cache-Control` value.
    #[must_use]
    pub fn header_value(self) -> HeaderValue {
        use std::fmt::Write;
        match self.0 {
            Kind::Immutable => HeaderValue::from_static("public, max-age=31536000, immutable"),
            Kind::NoStore => HeaderValue::from_static("no-store"),
            Kind::Public {
                browser,
                edge,
                stale,
            } => {
                let mut v = format!("public, max-age={}", browser.as_secs());
                if let Some(e) = edge {
                    let _ = write!(v, ", s-maxage={}", e.as_secs());
                }
                if let Some(w) = stale {
                    let _ = write!(v, ", stale-while-revalidate={}", w.as_secs());
                }
                // Digits, letters, commas and spaces only, so this never falls back.
                HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static("no-store"))
            }
        }
    }
}

impl From<CachePolicy> for HeaderValue {
    fn from(p: CachePolicy) -> Self {
        p.header_value()
    }
}

impl IntoResponseParts for CachePolicy {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.headers_mut()
            .insert(header::CACHE_CONTROL, self.header_value());
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use axum::response::{Html, IntoResponse};

    use super::*;

    const fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn header_values() {
        assert_eq!(
            CachePolicy::immutable().header_value(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(CachePolicy::no_store().header_value(), "no-store");
        assert_eq!(
            CachePolicy::public(s(60)).header_value(),
            "public, max-age=60"
        );
        assert_eq!(
            CachePolicy::public(s(0))
                .edge(s(600))
                .stale_while_revalidate(s(30))
                .header_value(),
            "public, max-age=0, s-maxage=600, stale-while-revalidate=30"
        );
    }

    /// The edge keeps it to the moment; browsers at most the cap of it.
    #[test]
    fn until_a_moment() {
        assert_eq!(
            CachePolicy::public_until(s(30), s(60)).header_value(),
            "public, max-age=30, s-maxage=30"
        );
        assert_eq!(
            CachePolicy::public_until(s(43_200), s(60)).header_value(),
            "public, max-age=60, s-maxage=43200"
        );
    }

    #[test]
    fn modifiers_leave_the_fixed_classes_alone() {
        assert_eq!(
            CachePolicy::no_store()
                .edge(s(600))
                .stale_while_revalidate(s(5)),
            CachePolicy::no_store()
        );
        assert_eq!(
            CachePolicy::immutable().edge(s(1)),
            CachePolicy::immutable()
        );
        assert!(!CachePolicy::no_store().is_public() && CachePolicy::public(s(1)).is_public());
    }

    #[test]
    fn a_policy_is_a_response_part() {
        let r = (CachePolicy::public(s(60)), Html("<p>")).into_response();
        assert_eq!(r.headers()[header::CACHE_CONTROL], "public, max-age=60");
    }
}
