//! htmx fragments at URLs of their own.
//!
//! A page and the fragment that updates part of it live at distinct URLs, never one
//! URL negotiated on `HX-Request`: a CDN that ignores `Vary` (Cloudflare, beyond
//! encoding) caches whichever variant it saw first and serves it for the other. So
//! every header here is the same for every client, and both URLs stay cacheable.
//!
//! * [`Fragment`] answers the fragment URL. It names the page the fragment belongs to
//!   ([`Fragment::page`] pushes a history entry, [`Fragment::replace`] rewrites the
//!   current one), so history, reload and shared links land on the whole page, never
//!   the bare fragment. It is `noindex`, and it takes its cache policy as an argument:
//!   a fragment cannot ship without one. Push for a step a person would want Back
//!   to undo (a page, a tab, opening an item); replace for refining what is already
//!   on screen (typing in a search box, a filter), or Back walks through every
//!   keystroke. htmx reads these headers before the element's `hx-push-url` and
//!   `hx-replace-url`, so the choice is the handler's.
//! * The handler re-paths its request to the page once
//!   ([`RequestInfo::for_page`]) and renders from that: pagination links, navigation
//!   and the push URL then all name the page, with nothing else to keep in step.
//! * [`reselect`] goes on the page: should a stale client htmx-request the page URL,
//!   htmx swaps only the fragment's element out of it instead of nesting a page.
//! * Render both from one loader and have the page include the fragment's partial;
//!   `owt_test::fragment` checks they agree.
//!
//! Someone who opens a fragment URL directly sees the bare fragment. Redirecting them
//! would mean answering by request header, which is the hazard above.

use std::fmt::Write as _;

use askama::Template;
use axum::http::{HeaderName, HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};

use crate::request::RequestInfo;

const HX_PUSH_URL: HeaderName = HeaderName::from_static("hx-push-url");
const HX_REPLACE_URL: HeaderName = HeaderName::from_static("hx-replace-url");
const HX_RESELECT: HeaderName = HeaderName::from_static("hx-reselect");
const X_ROBOTS_TAG: HeaderName = HeaderName::from_static("x-robots-tag");

/// A fragment response. Build it with [`Fragment::render`], then name its page with
/// [`Fragment::page`] or [`Fragment::replace`] if swapping it should move the
/// address bar.
#[derive(Debug)]
#[must_use]
pub struct Fragment {
    body: String,
    cache: HeaderValue,
    history: Option<(HeaderName, HeaderValue)>,
}

impl Fragment {
    /// `body`, cached as `cache_control` says (`no-store` for anything per-person).
    pub fn new(body: impl Into<String>, cache_control: HeaderValue) -> Self {
        Self {
            body: body.into(),
            cache: cache_control,
            history: None,
        }
    }

    /// `t` rendered, cached as `cache_control` says.
    pub fn render(t: &impl Template, cache_control: HeaderValue) -> crate::Result<Self> {
        Ok(Self::new(crate::render(t)?.0, cache_control))
    }

    /// The page this fragment shows a state of: htmx records its path and query as a
    /// new history entry (`HX-Push-Url`), so Back returns to the state before. `page`
    /// is the fragment's request re-pathed to the page, [`RequestInfo::for_page`], the
    /// same value the fragment rendered from, so the URL pushed is the one its links
    /// name. Non-ASCII characters (a decoded path segment, say) are percent-encoded;
    /// a control character is an error.
    pub fn page(self, page: &RequestInfo) -> crate::Result<Self> {
        self.history(HX_PUSH_URL, page)
    }

    /// Like [`Fragment::page`], but htmx rewrites the current history entry
    /// (`HX-Replace-Url`) instead of adding one: for a fragment fetched while someone
    /// types or adjusts a filter, so Back leaves the page rather than retracing every
    /// request. The later of `page` and `replace` wins.
    pub fn replace(self, page: &RequestInfo) -> crate::Result<Self> {
        self.history(HX_REPLACE_URL, page)
    }

    fn history(mut self, header: HeaderName, page: &RequestInfo) -> crate::Result<Self> {
        let url = page.full_path.as_str();
        let mut encoded = String::with_capacity(url.len());
        for c in url.chars() {
            if c.is_ascii() {
                encoded.push(c);
            } else {
                let mut buf = [0; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    let _ = write!(encoded, "%{b:02X}");
                }
            }
        }
        let v = HeaderValue::from_str(&encoded).map_err(|_| {
            crate::Error::Internal(anyhow::anyhow!("page URL is not a header value: {url:?}"))
        })?;
        self.history = Some((header, v));
        Ok(self)
    }
}

impl IntoResponse for Fragment {
    fn into_response(self) -> Response {
        let mut r = Html(self.body).into_response();
        let h = r.headers_mut();
        h.insert(header::CACHE_CONTROL, self.cache);
        h.insert(X_ROBOTS_TAG, HeaderValue::from_static("noindex"));
        if let Some((name, url)) = self.history {
            h.insert(name, url);
        }
        r
    }
}

/// The page's `HX-Reselect: <selector>` header, for a tuple response:
/// `([reselect("#viewport"), cache], Html(body))`.
///
/// # Panics
/// If `selector` is not visible ASCII, on every response that carries it: name a
/// literal selector, which the first test of the page catches.
#[must_use]
pub fn reselect(selector: &'static str) -> (HeaderName, HeaderValue) {
    (HX_RESELECT, HeaderValue::from_static(selector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_name_their_page_and_carry_one_set_of_headers() {
        let r = Fragment::new(
            "<div id=v></div>",
            HeaderValue::from_static("public, max-age=60"),
        )
        .page(&RequestInfo::at("/worlds/1/view?x=2&y=3").for_page("/worlds/1"))
        .unwrap()
        .into_response();
        let h = r.headers();
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=60");
        assert_eq!(h["hx-push-url"], "/worlds/1?x=2&y=3");
        assert_eq!(h["x-robots-tag"], "noindex");
        assert!(h.get(header::VARY).is_none(), "nothing varies by request");
        assert!(
            Fragment::new("", HeaderValue::from_static("no-store"))
                .page(&RequestInfo::at("/bad\nurl"))
                .is_err()
        );
        let r = Fragment::new("", HeaderValue::from_static("no-store"))
            .page(&RequestInfo::at("/worlds/Zürich?q=é"))
            .unwrap()
            .into_response();
        assert_eq!(r.headers()["hx-push-url"], "/worlds/Z%C3%BCrich?q=%C3%A9");
        let plain = Fragment::new("x", HeaderValue::from_static("no-store")).into_response();
        assert!(plain.headers().get("hx-push-url").is_none());
        assert!(plain.headers().get("hx-replace-url").is_none());
    }

    #[test]
    fn a_fragment_may_replace_the_history_entry_instead() {
        let typed = RequestInfo::at("/search/results?q=psal").for_page("/search");
        let r = Fragment::new("<ol id=r></ol>", HeaderValue::from_static("no-store"))
            .replace(&typed)
            .unwrap()
            .into_response();
        let h = r.headers();
        assert_eq!(h["hx-replace-url"], "/search?q=psal");
        assert!(
            h.get("hx-push-url").is_none(),
            "one history header, never both"
        );
        assert_eq!(h["x-robots-tag"], "noindex");
        assert_eq!(h["cache-control"], "no-store");
        // The later call decides.
        let r = Fragment::new("", HeaderValue::from_static("no-store"))
            .page(&typed)
            .unwrap()
            .replace(&typed)
            .unwrap()
            .into_response();
        assert!(r.headers().get("hx-push-url").is_none());
        assert_eq!(r.headers()["hx-replace-url"], "/search?q=psal");
        assert!(
            Fragment::new("", HeaderValue::from_static("no-store"))
                .replace(&RequestInfo::at("/bad\nurl"))
                .is_err()
        );
    }

    #[test]
    fn reselect_header() {
        assert_eq!(
            reselect("#viewport"),
            (HX_RESELECT, HeaderValue::from_static("#viewport"))
        );
    }
}
