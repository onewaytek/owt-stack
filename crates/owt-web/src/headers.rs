//! Response-shaping middleware.
//!
//! Every function here only *adds* a header a response lacks: a handler that set its
//! own (a public page's `Cache-Control`, an SSE stream's) is left alone.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// `Cache-Control` for responses no cache may keep.
pub const NEVER_CACHE: &str = "max-age=0, no-cache, no-store, must-revalidate, private";

/// `Cache-Control: no-store`.
pub const NO_STORE: &str = "no-store";

/// `Strict-Transport-Security`: a year of HTTPS only. Browsers ignore it over plain
/// HTTP, so development is unaffected. Subdomains are not included, because that
/// reaches hosts this app does not own; an app that owns its whole domain sets
/// `includeSubDomains` itself.
pub const HSTS: &str = "max-age=31536000";

/// `Permissions-Policy`: the device and payment features no page here uses.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

fn is_html(resp: &Response) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"))
}

/// An HTML response that says nothing about caching is never cached. HTML is where
/// per-person content lives; a CDN rule that caches everything would otherwise serve
/// one person's page to the next.
pub async fn private_by_default(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    if !resp.headers().contains_key(header::CACHE_CONTROL) && is_html(&resp) {
        let h = resp.headers_mut();
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(NEVER_CACHE));
        h.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    resp
}

/// Any response that says nothing about caching is `no-store`: a new handler is
/// uncacheable until it opts into a policy.
pub async fn no_store_by_default(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static(NO_STORE));
    resp
}

/// HTTPS only, referrer policy, opener isolation, MIME sniffing, framing and device
/// features. The content security policy is [`Csp`], which needs configuring.
pub async fn security(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static(HSTS));
    h.entry("permissions-policy")
        .or_insert(HeaderValue::from_static(PERMISSIONS_POLICY));
    h.entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin"));
    h.entry("cross-origin-opener-policy")
        .or_insert(HeaderValue::from_static("same-origin-allow-popups"));
    h.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    resp
}

/// A content security policy with a nonce per request.
///
/// The default allows only this origin's scripts, styles, images, forms and
/// connections, plus inline `<script>` and `<style>` elements carrying the request's
/// [`Nonce`]; nothing may frame the page. `{nonce}` in a directive's value stands for
/// that nonce. Change a directive with [`Csp::directive`]:
///
/// ```
/// # use owt_web::headers::Csp;
/// let csp = Csp::new()
///     .directive("img-src", "'self' data: https://cdn.example")
///     // Chrome applies form-action to the redirect a form's POST answers with.
///     .directive("form-action", "'self' https://accounts.google.com")
///     .report_only(true);
/// ```
///
/// Start with [`Csp::report_only`] and read the browser console before enforcing.
/// htmx needs `htmx.config.includeIndicatorStyles = false` (or its
/// `inlineStyleNonce`) and no `hx-on:*` attributes or `eval`-based features, which a
/// nonce cannot cover. A page cached for many viewers replays one nonce; give such a
/// page no inline scripts.
#[derive(Clone, Debug)]
pub struct Csp(Arc<CspInner>);

#[derive(Clone, Debug)]
struct CspInner {
    directives: Vec<(String, String)>,
    report_only: bool,
}

impl Default for Csp {
    fn default() -> Self {
        Self::new()
    }
}

impl Csp {
    /// The default policy.
    #[must_use]
    pub fn new() -> Self {
        let directives = [
            ("default-src", "'self'"),
            ("script-src", "'self' 'nonce-{nonce}'"),
            ("style-src", "'self' 'nonce-{nonce}'"),
            ("img-src", "'self' data:"),
            ("object-src", "'none'"),
            ("base-uri", "'self'"),
            ("form-action", "'self'"),
            ("frame-ancestors", "'none'"),
        ];
        Self(Arc::new(CspInner {
            directives: directives
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            report_only: false,
        }))
    }

    /// Set (or replace) the directive `name`; an empty `value` removes it.
    #[must_use]
    pub fn directive(mut self, name: &str, value: &str) -> Self {
        let inner = Arc::make_mut(&mut self.0);
        inner.directives.retain(|(k, _)| k != name);
        if !value.is_empty() {
            inner.directives.push((name.to_owned(), value.to_owned()));
        }
        self
    }

    /// Send `Content-Security-Policy-Report-Only`: violations are reported in the
    /// browser's console and nothing is blocked.
    #[must_use]
    pub fn report_only(mut self, on: bool) -> Self {
        Arc::make_mut(&mut self.0).report_only = on;
        self
    }

    fn render(&self, nonce: &str) -> String {
        self.0
            .directives
            .iter()
            .map(|(k, v)| format!("{k} {}", v.replace("{nonce}", nonce)))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Middleware body, for `from_fn_with_state(csp, Csp::layer)`: mint the request's
    /// [`Nonce`] and send the policy with any response that carries none.
    pub async fn layer(State(this): State<Self>, mut req: Request, next: Next) -> Response {
        let nonce = Nonce::new();
        req.extensions_mut().insert(nonce.clone());
        let mut resp = next.run(req).await;
        let name = if this.0.report_only {
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            header::CONTENT_SECURITY_POLICY
        };
        if !resp.headers().contains_key(&name)
            && let Ok(v) = HeaderValue::from_str(&this.render(&nonce.0))
        {
            resp.headers_mut().insert(name, v);
        }
        resp
    }
}

/// The request's CSP nonce, for `<script nonce="{{ nonce }}">`. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Nonce(Arc<str>);

impl Nonce {
    fn new() -> Self {
        use base64::Engine;
        let bytes: [u8; 16] = rand::random();
        Self(
            base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into(),
        )
    }

    /// The nonce's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Nonce {
    type Rejection = std::convert::Infallible;

    /// The layer's nonce; where no layer ran there is no policy, and a fresh nonce
    /// matches nothing.
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts
            .extensions
            .get::<Nonce>()
            .cloned()
            .unwrap_or_else(Nonce::new)))
    }
}

/// `X-Robots-Tag: noindex, nofollow` on everything: staging hostnames.
pub async fn noindex(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn;
    use axum::response::{Html, IntoResponse};
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    async fn call(app: Router, uri: &str) -> Response {
        app.oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn defaults_only_fill_gaps() {
        let app = Router::new()
            .route("/page", get(|| async { Html("<p>") }))
            .route(
                "/public",
                get(|| async {
                    ([(header::CACHE_CONTROL, "public, max-age=60")], Html("<p>")).into_response()
                }),
            )
            .route("/json", get(|| async { "{}" }))
            .layer(from_fn(private_by_default))
            .layer(from_fn(security));
        let page = call(app.clone(), "/page").await;
        assert_eq!(page.headers()[header::CACHE_CONTROL], NEVER_CACHE);
        assert_eq!(page.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(page.headers()[header::STRICT_TRANSPORT_SECURITY], HSTS);
        assert_eq!(page.headers()["permissions-policy"], PERMISSIONS_POLICY);
        assert_eq!(
            call(app.clone(), "/public").await.headers()[header::CACHE_CONTROL],
            "public, max-age=60"
        );
        assert!(
            call(app, "/json")
                .await
                .headers()
                .get(header::CACHE_CONTROL)
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_policy_carries_the_nonce_handlers_see() {
        let csp = Csp::new().directive("img-src", "'self' https://cdn.test");
        let app = Router::new()
            .route("/", get(|n: Nonce| async move { n.to_string() }))
            .layer(axum::middleware::from_fn_with_state(csp, Csp::layer));
        let res = call(app.clone(), "/").await;
        let policy = res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        let nonce = std::str::from_utf8(&body).unwrap();
        assert!(
            policy.contains(&format!("script-src 'self' 'nonce-{nonce}'")),
            "{policy}"
        );
        assert!(policy.contains("frame-ancestors 'none'") && policy.contains("https://cdn.test"));
        let again = call(app, "/").await;
        assert_ne!(
            again.headers()[header::CONTENT_SECURITY_POLICY],
            policy,
            "a nonce per request"
        );

        let app =
            Router::new()
                .route("/", get(|| async {}))
                .layer(axum::middleware::from_fn_with_state(
                    Csp::new().report_only(true),
                    Csp::layer,
                ));
        let res = call(app, "/").await;
        assert!(
            res.headers()
                .contains_key(header::CONTENT_SECURITY_POLICY_REPORT_ONLY)
        );
        assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }
}
