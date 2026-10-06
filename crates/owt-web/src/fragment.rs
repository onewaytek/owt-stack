//! htmx fragments at URLs of their own.
//!
//! A page and the fragment that updates part of it live at distinct URLs, never one
//! URL negotiated on `HX-Request`: a CDN that ignores `Vary` (Cloudflare, beyond
//! encoding) caches whichever variant it saw first and serves it for the other. So
//! every header here is the same for every client, and both URLs stay cacheable.
//!
//! * [`Fragment`] answers the fragment URL. It names the page the fragment belongs to
//!   (`HX-Push-Url`), so history, reload and shared links land on the whole page,
//!   never the bare fragment. It is `noindex`, and it takes its cache policy as an
//!   argument: a fragment cannot ship without one.
//! * [`reselect`] goes on the page: should a stale client htmx-request the page URL,
//!   htmx swaps only the fragment's element out of it instead of nesting a page.
//! * Render both from one loader and have the page include the fragment's partial;
//!   `owt_test::fragment` checks they agree.
//!
//! Someone who opens a fragment URL directly sees the bare fragment. Redirecting them
//! would mean answering by request header, which is the hazard above.

use askama::Template;
use axum::http::{HeaderName, HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};

const HX_PUSH_URL: HeaderName = HeaderName::from_static("hx-push-url");
const HX_RESELECT: HeaderName = HeaderName::from_static("hx-reselect");
const X_ROBOTS_TAG: HeaderName = HeaderName::from_static("x-robots-tag");

/// A fragment response. Build it with [`Fragment::render`], then name its page with
/// [`Fragment::page`] if swapping it should move the address bar.
#[derive(Debug)]
#[must_use]
pub struct Fragment {
    body: String,
    cache: HeaderValue,
    page: Option<HeaderValue>,
}

impl Fragment {
    /// `body`, cached as `cache_control` says (`no-store` for anything per-person).
    pub fn new(body: impl Into<String>, cache_control: HeaderValue) -> Self {
        Self {
            body: body.into(),
            cache: cache_control,
            page: None,
        }
    }

    /// `t` rendered, cached as `cache_control` says.
    pub fn render(t: &impl Template, cache_control: HeaderValue) -> crate::Result<Self> {
        Ok(Self::new(crate::render(t)?.0, cache_control))
    }

    /// The page this fragment shows a state of: htmx records it in history
    /// (`HX-Push-Url`). A URL that is not a valid header value is an error.
    pub fn page(mut self, url: &str) -> crate::Result<Self> {
        let v = HeaderValue::from_str(url).map_err(|_| {
            crate::Error::Internal(anyhow::anyhow!("page URL is not a header value: {url:?}"))
        })?;
        self.page = Some(v);
        Ok(self)
    }
}

impl IntoResponse for Fragment {
    fn into_response(self) -> Response {
        let mut r = Html(self.body).into_response();
        let h = r.headers_mut();
        h.insert(header::CACHE_CONTROL, self.cache);
        h.insert(X_ROBOTS_TAG, HeaderValue::from_static("noindex"));
        if let Some(url) = self.page {
            h.insert(HX_PUSH_URL, url);
        }
        r
    }
}

/// The page's `HX-Reselect: <selector>` header, for a tuple response:
/// `([reselect("#viewport"), cache], Html(body))`.
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
        .page("/worlds/1?x=2&y=3")
        .unwrap()
        .into_response();
        let h = r.headers();
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=60");
        assert_eq!(h["hx-push-url"], "/worlds/1?x=2&y=3");
        assert_eq!(h["x-robots-tag"], "noindex");
        assert!(h.get(header::VARY).is_none(), "nothing varies by request");
        assert!(
            Fragment::new("", HeaderValue::from_static("no-store"))
                .page("/bad\nurl")
                .is_err()
        );
        let plain = Fragment::new("x", HeaderValue::from_static("no-store")).into_response();
        assert!(plain.headers().get("hx-push-url").is_none());
    }

    #[test]
    fn reselect_header() {
        assert_eq!(
            reselect("#viewport"),
            (HX_RESELECT, HeaderValue::from_static("#viewport"))
        );
    }
}
