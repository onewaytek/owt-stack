//! What a page knows about the request that asked for it.
//!
//! Every full page draws the same chrome (navigation that marks the current section,
//! links that keep the query, a sign-in link that returns here), and all of it reads
//! the request. [`RequestInfo`] is that, extracted once and typed, for an app's own
//! page context to carry. An app's context struct can `Deref` to it, so templates
//! write `layout.path` whatever else the context holds.
//!
//! Pages and htmx fragments should live at distinct URLs rather than be negotiated on
//! `HX-Request`: a CDN that ignores `Vary` (Cloudflare, beyond encoding) would cache
//! one variant and serve it for the other (see [`crate::fragment`]).
//! [`RequestInfo::is_htmx`] is for chrome decisions, never for choosing between a
//! page and a fragment at one URL.

use std::convert::Infallible;

use axum::extract::{FromRequestParts, OriginalUri};
use axum::http::request::Parts;

/// The request, as page templates read it.
#[derive(Clone, Debug, Default)]
pub struct RequestInfo {
    /// The path, without the query: `/games/`.
    pub path: String,
    /// The path and query: `/games/?page=2`.
    pub full_path: String,
    /// The query's pairs, in order, decoded.
    pub query: Vec<(String, String)>,
    /// Sent by htmx (`HX-Request`).
    pub is_htmx: bool,
    /// An htmx-boosted navigation (`HX-Boosted`): a full page, swapped in.
    pub is_boosted: bool,
}

impl RequestInfo {
    /// The request at `uri` (a path with an optional query), as no client sent it:
    /// error pages, tests, and pages rendered outside a request.
    #[must_use]
    pub fn at(uri: &str) -> Self {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        Self {
            path: path.to_owned(),
            full_path: uri.to_owned(),
            query: url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect(),
            is_htmx: false,
            is_boosted: false,
        }
    }

    /// The last value the query gives `key`.
    #[must_use]
    pub fn query_value(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// This request's query with `key` set to `value` (or removed, for `None`), as
    /// `?...`: pagination and filter links that keep the rest of the query.
    #[must_use]
    pub fn query_with(&self, key: &str, value: Option<&str>) -> String {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in self.query.iter().filter(|(k, _)| k != key) {
            ser.append_pair(k, v);
        }
        if let Some(v) = value {
            ser.append_pair(key, v);
        }
        format!("?{}", ser.finish())
    }

    /// The current path is `prefix` or below it: navigation's "you are here".
    #[must_use]
    pub fn is_under(&self, prefix: &str) -> bool {
        self.path == prefix
            || self
                .path
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestInfo {
    type Rejection = Infallible;

    /// Reads the URI the client sent (`OriginalUri`, so a router nested under a prefix
    /// still sees the whole path).
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let uri = parts
            .extensions
            .get::<OriginalUri>()
            .map_or_else(|| parts.uri.clone(), |u| u.0.clone());
        let flag = |name: &str| {
            parts
                .headers
                .get(name)
                .is_some_and(|v| v.as_bytes() == b"true")
        };
        let mut info = Self::at(&uri.to_string());
        info.is_htmx = flag("hx-request");
        info.is_boosted = flag("hx-boosted");
        std::future::ready(Ok(info))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;

    #[tokio::test]
    async fn reads_path_query_and_htmx_headers() {
        let (mut parts, ()) = Request::get("/games/?state=active&page=3&state=done")
            .header("hx-request", "true")
            .body(())
            .unwrap()
            .into_parts();
        let r = RequestInfo::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(
            (r.path.as_str(), r.full_path.as_str()),
            ("/games/", "/games/?state=active&page=3&state=done")
        );
        assert!(r.is_htmx && !r.is_boosted);
        assert_eq!(r.query_value("state"), Some("done"));
        assert_eq!(
            r.query_with("page", Some("4")),
            "?state=active&state=done&page=4"
        );
        assert_eq!(r.query_with("page", None), "?state=active&state=done");
    }

    #[test]
    fn sections() {
        let r = RequestInfo::at("/admin/events/3/");
        assert!(r.is_under("/admin/") && r.is_under("/admin/events") && !r.is_under("/adm"));
        assert!(!RequestInfo::at("/administer/").is_under("/admin"));
    }
}
