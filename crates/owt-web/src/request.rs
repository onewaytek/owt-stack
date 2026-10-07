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
    /// `?...`: the rest of the query kept. Always begins with `?`, so it appends to a
    /// path; `?` alone when nothing is left. For a link, see [`Self::url_with`].
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

    /// A link to this page with `key` set to `value` (or removed, for `None`): the
    /// path and the rest of the query, `/items?q=cats&page=4`. When nothing is left of
    /// the query, the path alone, so an unfiltered page has one URL (and one cache
    /// entry), not `/items` and `/items?`. Pagination and filter links.
    ///
    /// Root-relative, so it means the same wherever it is rendered, a page or a
    /// fragment swapped into one; a fragment handler calls [`Self::for_page`] first.
    /// With no path known (a `RequestInfo` built by hand), the query alone, `?`
    /// keeping the current path.
    #[must_use]
    pub fn url_with(&self, key: &str, value: Option<&str>) -> String {
        let query = self.query_with(key, value);
        if self.path.is_empty() {
            query
        } else if query == "?" {
            self.path.clone()
        } else {
            format!("{}{query}", self.path)
        }
    }

    /// This request, as the page at `path` sees it: the path swapped, the query and
    /// the htmx flags kept. A fragment handler (`GET /items/rows?page=2`) re-paths the
    /// request to its page (`/items`) once and renders from that, so pagination links,
    /// navigation's "you are here" and [`Fragment::page`](crate::fragment::Fragment::page)
    /// all speak of the page, never the bare fragment. Leading slashes collapse to one,
    /// as in [`Self::at`]; a query in `path` is dropped.
    #[must_use]
    pub fn for_page(&self, path: &str) -> Self {
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        let uri = match self.full_path.split_once('?') {
            Some((_, query)) => format!("{path}?{query}"),
            None => path.to_owned(),
        };
        Self {
            is_htmx: self.is_htmx,
            is_boosted: self.is_boosted,
            ..Self::at(&uri)
        }
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
        assert_eq!(
            r.url_with("page", Some("4")),
            "/games/?state=active&state=done&page=4"
        );
    }

    #[test]
    fn a_link_with_nothing_left_of_the_query_is_the_path() {
        let r = RequestInfo::at("/games/?page=2");
        assert_eq!(
            r.query_with("page", None),
            "?",
            "a query always begins with `?`"
        );
        assert_eq!(
            r.url_with("page", None),
            "/games/",
            "nothing left: the path, not `?`"
        );
        assert_eq!(r.url_with("page", Some("3")), "/games/?page=3");
        assert_eq!(
            RequestInfo::default().url_with("page", None),
            "?",
            "no path known: never an empty href, which would keep the query"
        );
        assert_eq!(
            RequestInfo::default().url_with("page", Some("2")),
            "?page=2"
        );
    }

    #[tokio::test]
    async fn a_fragment_request_re_pathed_to_its_page() {
        let (mut parts, ()) = Request::get("/items/rows?q=cats&page=2")
            .header("hx-request", "true")
            .body(())
            .unwrap()
            .into_parts();
        let fragment = RequestInfo::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let page = fragment.for_page("/items");
        assert_eq!(
            (page.path.as_str(), page.full_path.as_str()),
            ("/items", "/items?q=cats&page=2")
        );
        assert_eq!(page.query, fragment.query);
        assert!(page.is_htmx && !page.is_boosted, "the htmx flags stay");
        assert_eq!(page.url_with("page", None), "/items?q=cats");
        assert_eq!(page.url_with("page", Some("3")), "/items?q=cats&page=3");
        assert!(page.is_under("/items") && !page.is_under("/items/rows"));
        assert_eq!(
            RequestInfo::at("/rows").for_page("/items").full_path,
            "/items"
        );
        assert_eq!(
            RequestInfo::at("/rows?a=1")
                .for_page("/items?b=2")
                .full_path,
            "/items?a=1",
            "a query in the page path is dropped"
        );
        assert_eq!(
            RequestInfo::at("/rows").for_page("//evil.example/x").path,
            "/evil.example/x"
        );
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
