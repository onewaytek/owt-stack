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
    ///
    /// Leading slashes collapse to one. `GET //elsewhere.example/` is a path to the
    /// server and another host to a browser, so a link built from it (the 404 page's
    /// "sign in and come back") would leave the site.
    #[must_use]
    pub fn at(uri: &str) -> Self {
        let uri = match uri.strip_prefix("//") {
            Some(rest) => &format!("/{}", rest.trim_start_matches('/')),
            None => uri,
        };
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
    /// still sees the whole path). Only its path and query: a request target in
    /// absolute form (`GET http://elsewhere/games/`) must not put a host of the
    /// client's choosing into links built from `full_path`.
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let uri = parts
            .extensions
            .get::<OriginalUri>()
            .map_or(&parts.uri, |u| &u.0);
        let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
        let flag = |name: &str| {
            parts
                .headers
                .get(name)
                .is_some_and(|v| v.as_bytes() == b"true")
        };
        let mut info = Self::at(path_and_query);
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

    #[tokio::test]
    async fn an_absolute_form_target_yields_only_its_path() {
        let (mut parts, ()) = Request::get("http://evil.example/games/?page=2")
            .body(())
            .unwrap()
            .into_parts();
        let r = RequestInfo::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(
            (r.path.as_str(), r.full_path.as_str()),
            ("/games/", "/games/?page=2")
        );
    }

    #[tokio::test]
    async fn a_nested_router_sees_the_whole_path() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new().nest(
            "/admin",
            Router::new().route("/events", get(|r: RequestInfo| async move { r.full_path })),
        );
        let res = app
            .oneshot(
                Request::get("/admin/events?x=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"/admin/events?x=1");
    }

    #[test]
    fn sections() {
        let r = RequestInfo::at("/admin/events/3/");
        assert!(r.is_under("/admin/") && r.is_under("/admin/events") && !r.is_under("/adm"));
        assert!(!RequestInfo::at("/administer/").is_under("/admin"));
    }

    #[tokio::test]
    async fn a_path_cannot_read_as_another_host() {
        // `GET //evil.example/x`: a link built from the path would be
        // protocol-relative, and leave the site.
        for target in ["//evil.example/x?y=1", "///evil.example/x?y=1"] {
            let (mut parts, ()) = Request::get(target).body(()).unwrap().into_parts();
            let r = RequestInfo::from_request_parts(&mut parts, &())
                .await
                .unwrap();
            assert_eq!(
                (r.path.as_str(), r.full_path.as_str()),
                ("/evil.example/x", "/evil.example/x?y=1"),
                "{target}"
            );
        }
        assert_eq!(RequestInfo::at("//evil.example").path, "/evil.example");
    }
}
