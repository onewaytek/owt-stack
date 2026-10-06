//! Cross-origin request protection without tokens.
//!
//! A cross-site request forgery is a state-changing request the browser sends on a
//! hostile page's behalf. Browsers label every request with where it came from, so
//! the server can refuse the cross-origin ones outright instead of round-tripping a
//! secret through every form. This is the algorithm of Go 1.25's
//! `http.CrossOriginProtection`:
//!
//! 1. `GET`, `HEAD` and `OPTIONS` pass: they must not change state. A `WebSocket`
//!    upgrade is the exception: it is a `GET` that opens a channel acting with the
//!    page's cookies, so it is checked like an unsafe request.
//! 2. `Sec-Fetch-Site: same-origin` or `none` (typed URL, bookmark) passes; any other
//!    value (`same-site`, `cross-site`) is refused unless its `Origin` is trusted.
//! 3. Without `Sec-Fetch-Site` (browsers before 2023): no `Origin` passes, since
//!    non-browser clients send neither and are not a CSRF vector; an `Origin` whose
//!    host is the request's `Host` passes; anything else is refused unless trusted.
//!
//! `same-site` is refused on purpose: a sibling subdomain is another application.
//! Cookies should still be `SameSite=Lax`, which this complements rather than
//! replaces.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The protection's configuration: origins trusted in addition to the request's own,
/// and path prefixes it does not apply to. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct CrossOrigin {
    trusted: Arc<[String]>,
    bypass: Arc<[String]>,
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The browser said the request came from another site.
    CrossSite,
    /// The `Origin` names another host than the one addressed.
    OriginMismatch,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::CrossSite => "cross-origin request",
            Self::OriginMismatch => "Origin does not match Host",
        }
    }
}

impl CrossOrigin {
    /// Only same-origin requests (and non-browser clients) may change state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Also accept unsafe requests from these origins (`scheme://host[:port]`; a
    /// trailing slash is ignored).
    #[must_use]
    pub fn trust<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut all: Vec<String> = self.trusted.to_vec();
        all.extend(
            origins
                .into_iter()
                .map(|o| o.as_ref().trim_end_matches('/').to_owned()),
        );
        self.trusted = all.into();
        self
    }

    /// Don't check requests to one of `prefixes` or below it (webhooks signed another
    /// way, say). A prefix matches whole path segments: `/hooks` covers `/hooks` and
    /// `/hooks/github`, not `/hooks-admin`.
    #[must_use]
    pub fn bypass<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut all: Vec<String> = self.bypass.to_vec();
        all.extend(prefixes.into_iter().map(Into::into));
        self.bypass = all.into();
        self
    }

    fn trusted(&self, origin: Option<&str>) -> bool {
        origin.is_some_and(|o| self.trusted.iter().any(|t| t == o.trim_end_matches('/')))
    }

    fn bypassed(&self, path: &str) -> bool {
        self.bypass.iter().any(|p| {
            let p = p.trim_end_matches('/');
            path.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }

    /// Whether a request with this method, path and headers may proceed.
    pub fn check(&self, method: &Method, path: &str, headers: &HeaderMap) -> Result<(), Refusal> {
        let safe = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
        if (safe && !is_websocket_upgrade(headers)) || self.bypassed(path) {
            return Ok(());
        }
        self.same_origin(headers)
    }

    /// The origin test alone, whatever the method and path.
    pub fn same_origin(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        let origin = get(header::ORIGIN.as_str());
        if let Some(site) = get("sec-fetch-site") {
            return if matches!(site, "same-origin" | "none") || self.trusted(origin) {
                Ok(())
            } else {
                Err(Refusal::CrossSite)
            };
        }
        let Some(origin) = origin else { return Ok(()) };
        if self.trusted(Some(origin)) {
            return Ok(());
        }
        let host = get(header::HOST.as_str()).unwrap_or_default();
        match url::Url::parse(origin) {
            Ok(u) if !host.is_empty() && authority(&u).eq_ignore_ascii_case(host) => Ok(()),
            _ => Err(Refusal::OriginMismatch),
        }
    }

    /// Middleware body, for `from_fn_with_state(cross_origin, CrossOrigin::layer)`.
    pub async fn layer(State(this): State<Self>, req: Request, next: Next) -> Response {
        match this.check(req.method(), req.uri().path(), req.headers()) {
            Ok(()) => next.run(req).await,
            Err(refusal) => {
                tracing::warn!(
                    reason = refusal.reason(),
                    method = %req.method(),
                    path = req.uri().path(),
                    "refused a cross-origin request"
                );
                (
                    StatusCode::FORBIDDEN,
                    format!("Forbidden: {}.", refusal.reason()),
                )
                    .into_response()
            }
        }
    }
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// `host[:port]` as a `Host` header carries it (default ports omitted).
fn authority(u: &url::Url) -> String {
    let host = u.host_str().unwrap_or_default();
    match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    fn post(c: &CrossOrigin, pairs: &[(&'static str, &'static str)]) -> Result<(), Refusal> {
        c.check(&Method::POST, "/x", &headers(pairs))
    }

    #[test]
    fn fetch_metadata_decides_when_present() {
        let c = CrossOrigin::new();
        assert_eq!(post(&c, &[("sec-fetch-site", "same-origin")]), Ok(()));
        assert_eq!(post(&c, &[("sec-fetch-site", "none")]), Ok(()));
        assert_eq!(
            post(&c, &[("sec-fetch-site", "cross-site")]),
            Err(Refusal::CrossSite)
        );
        // A sibling subdomain is another application.
        assert_eq!(
            post(&c, &[("sec-fetch-site", "same-site")]),
            Err(Refusal::CrossSite)
        );
        // Fetch metadata wins over a matching Origin: it cannot be forged by a page.
        assert_eq!(
            post(
                &c,
                &[
                    ("sec-fetch-site", "cross-site"),
                    ("origin", "https://a.test"),
                    ("host", "a.test")
                ]
            ),
            Err(Refusal::CrossSite)
        );
    }

    #[test]
    fn origin_is_compared_with_host_without_fetch_metadata() {
        let c = CrossOrigin::new();
        assert_eq!(
            post(&c, &[("origin", "https://a.test"), ("host", "a.test")]),
            Ok(())
        );
        assert_eq!(
            post(
                &c,
                &[("origin", "http://a.test:8000"), ("host", "a.test:8000")]
            ),
            Ok(())
        );
        assert_eq!(
            post(&c, &[("origin", "https://evil.test"), ("host", "a.test")]),
            Err(Refusal::OriginMismatch)
        );
        assert_eq!(
            post(&c, &[("origin", "null"), ("host", "a.test")]),
            Err(Refusal::OriginMismatch)
        );
        // Neither header: curl, a test client, a server-to-server call.
        assert_eq!(post(&c, &[]), Ok(()));
    }

    #[test]
    fn trusted_origins_and_bypassed_paths() {
        let c = CrossOrigin::new()
            .trust(["https://partner.test/"])
            .bypass(["/hooks/"]);
        assert_eq!(
            post(
                &c,
                &[
                    ("sec-fetch-site", "cross-site"),
                    ("origin", "https://partner.test")
                ]
            ),
            Ok(())
        );
        let h = headers(&[("sec-fetch-site", "cross-site")]);
        assert_eq!(c.check(&Method::POST, "/hooks/github", &h), Ok(()));
        assert_eq!(c.check(&Method::GET, "/anything", &h), Ok(()));
        assert_eq!(
            c.check(&Method::DELETE, "/anything", &h),
            Err(Refusal::CrossSite)
        );
    }

    #[test]
    fn websocket_upgrades_are_checked_though_they_are_gets() {
        let c = CrossOrigin::new();
        let h = headers(&[("origin", "https://evil.test"), ("host", "a.test")]);
        assert_eq!(c.check(&Method::GET, "/page", &h), Ok(()));
        assert_eq!(c.same_origin(&h), Err(Refusal::OriginMismatch));
        let upgrade = |origin: &'static str| {
            headers(&[
                ("upgrade", "WebSocket"),
                ("origin", origin),
                ("host", "a.test"),
            ])
        };
        assert_eq!(
            c.check(&Method::GET, "/ws", &upgrade("https://evil.test")),
            Err(Refusal::OriginMismatch)
        );
        assert_eq!(
            c.check(&Method::GET, "/ws", &upgrade("https://a.test")),
            Ok(())
        );
        // A native client sends no Origin.
        let native = headers(&[("upgrade", "websocket"), ("host", "a.test")]);
        assert_eq!(c.check(&Method::GET, "/ws", &native), Ok(()));
    }

    #[test]
    fn bypass_prefixes_match_whole_segments() {
        let c = CrossOrigin::new().bypass(["/mcp", "/hooks/"]);
        let h = headers(&[("sec-fetch-site", "cross-site")]);
        for path in ["/mcp", "/mcp/", "/mcp/tools", "/hooks", "/hooks/github"] {
            assert_eq!(c.check(&Method::POST, path, &h), Ok(()), "{path}");
        }
        for path in ["/mcp-admin", "/mcpx", "/hooksy", "/x/mcp"] {
            assert_eq!(
                c.check(&Method::POST, path, &h),
                Err(Refusal::CrossSite),
                "{path}"
            );
        }
    }
}
