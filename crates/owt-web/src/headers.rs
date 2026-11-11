//! Response-shaping middleware.
//!
//! The cache and security functions here only *add* a header a response lacks: a
//! handler that set its own (a public page's `Cache-Control`, an SSE stream's) is left
//! alone. [`noindex`] overwrites.

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

/// A route layer that makes a route's pages cacheable by everyone, browsers and shared
/// caches alike, for `max_age`: `Cache-Control: public, max-age=N` on a `200` response
/// that sets no cookie and says nothing about caching itself. Default absent: put it
/// only on routes whose pages are the same for every viewer.
///
/// It runs inside the session layer, which still marks a response that carries a
/// cookie or a signed-in person's idle time [`NEVER_CACHE`]; any other status, and a
/// handler's own `Cache-Control`, are left to [`private_by_default`].
///
/// ```
/// # use std::time::Duration;
/// # use axum::{Router, routing::get};
/// let public = Router::<()>::new()
///     .route("/about", get(|| async { axum::response::Html("<h1>About</h1>") }))
///     .route_layer(owt_web::headers::public(Duration::from_mins(5)));
/// ```
#[must_use]
pub fn public(
    max_age: std::time::Duration,
) -> tower_http::set_header::SetResponseHeaderLayer<PublicCache> {
    public_with(crate::cache::CachePolicy::public(max_age))
}

/// [`public`] with a whole policy: an edge lifetime longer than the browser's, or
/// stale-while-revalidate. A policy that is not public
/// ([`CachePolicy::no_store`](crate::cache::CachePolicy::no_store)) sets that instead.
#[must_use]
pub fn public_with(
    policy: crate::cache::CachePolicy,
) -> tower_http::set_header::SetResponseHeaderLayer<PublicCache> {
    tower_http::set_header::SetResponseHeaderLayer::if_not_present(
        header::CACHE_CONTROL,
        PublicCache(policy.header_value()),
    )
}

/// The `Cache-Control` value [`public`] sets, and when.
#[derive(Clone, Debug)]
pub struct PublicCache(HeaderValue);

impl<B> tower_http::set_header::MakeHeaderValue<axum::http::Response<B>> for PublicCache {
    fn make_header_value(&mut self, resp: &axum::http::Response<B>) -> Option<HeaderValue> {
        (resp.status() == axum::http::StatusCode::OK
            && !resp.headers().contains_key(header::SET_COOKIE))
        .then(|| self.0.clone())
    }
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
/// nonce cannot cover. A nonce never covers a `style="…"` attribute either, so the
/// default policy blocks every one, including those a page writes on purpose (a
/// progress bar's width, a colour swatch); [`Csp::allow_style_attributes`] allows
/// them. A page cached for many viewers replays one nonce; give such a page no inline
/// scripts, or use [`Csp::static_policy`], which has no nonce at all.
///
/// The header is rendered once, when the policy is built: a request costs one join of
/// the precomputed text around its nonce, or nothing beyond a clone under
/// [`Csp::static_policy`].
#[derive(Clone, Debug)]
pub struct Csp(Arc<CspInner>);

#[derive(Clone, Debug)]
struct CspInner {
    directives: Vec<(String, String)>,
    report_only: bool,
    static_policy: bool,
    rendered: Rendered,
}

/// The policy's header, rendered from the directives whenever they change.
#[derive(Clone, Debug)]
enum Rendered {
    /// The text between `{nonce}`s: the header is these joined by the request's nonce.
    Segments(Vec<String>),
    /// No nonce: the whole header, ready to send.
    Static(HeaderValue),
}

impl CspInner {
    fn text(&self) -> String {
        self.directives
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn rerender(&mut self) {
        let text = self.text();
        self.rendered = if self.static_policy {
            // Values are checked printable ASCII, so this never falls back.
            Rendered::Static(
                HeaderValue::from_str(&text)
                    .unwrap_or(HeaderValue::from_static("default-src 'self'")),
            )
        } else {
            Rendered::Segments(text.split("{nonce}").map(str::to_owned).collect())
        };
    }
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
        let mut inner = CspInner {
            directives: directives
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            report_only: false,
            static_policy: false,
            rendered: Rendered::Segments(Vec::new()),
        };
        inner.rerender();
        Self(Arc::new(inner))
    }

    /// Set (or replace) the directive `name`; an empty `value` removes it.
    ///
    /// # Panics
    /// If `name` is not a directive name (letters and `-`) or `value` holds a `;`, a
    /// `,` or anything a header cannot carry: a policy that could not be sent would
    /// otherwise leave every page with none. Under [`static_policy`](Self::static_policy),
    /// also if `value` holds `{nonce}`: there is no nonce to put there.
    #[must_use]
    pub fn directive(mut self, name: &str, value: &str) -> Self {
        assert!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-'),
            "CSP directive name {name:?}"
        );
        assert!(
            value
                .bytes()
                .all(|b| (b' '..=b'~').contains(&b) && b != b';' && b != b','),
            "CSP directive value for {name}: {value:?}"
        );
        let inner = Arc::make_mut(&mut self.0);
        assert!(
            !(inner.static_policy && value.contains("{nonce}")),
            "CSP directive value for {name} uses {{nonce}}, and a static policy has none: {value:?}"
        );
        inner.directives.retain(|(k, _)| k != name);
        if !value.is_empty() {
            inner.directives.push((name.to_owned(), value.to_owned()));
        }
        inner.rerender();
        self
    }

    /// A policy with no nonce: every source naming `{nonce}` (the default
    /// `'nonce-{nonce}'` in `script-src` and `style-src`) is dropped, a directive left
    /// empty goes with it, and the layer mints no [`Nonce`]. The header is the same on
    /// every response, so a page cached for everyone carries a policy that is true for
    /// every viewer. Inline `<script>` and `<style>` elements are then blocked, nonce or
    /// not: scripts and styles come from files. The policy is still sent, enforced
    /// unless [`report_only`](Self::report_only) says otherwise.
    #[must_use]
    pub fn static_policy(mut self) -> Self {
        let inner = Arc::make_mut(&mut self.0);
        inner.static_policy = true;
        for (_, value) in &mut inner.directives {
            *value = value
                .split(' ')
                .filter(|source| !source.is_empty() && !source.contains("{nonce}"))
                .collect::<Vec<_>>()
                .join(" ");
        }
        inner.directives.retain(|(_, v)| !v.is_empty());
        inner.rerender();
        self
    }

    /// Allow `style="…"` attributes (`style-src-attr 'unsafe-inline'`), which a nonce
    /// cannot cover. `<style>` elements and stylesheets still answer to `style-src`:
    /// injected markup can restyle the element it lands on, but cannot bring a
    /// stylesheet that reaches the rest of the page.
    #[must_use]
    pub fn allow_style_attributes(self) -> Self {
        self.directive("style-src-attr", "'unsafe-inline'")
    }

    /// Send `Content-Security-Policy-Report-Only`: violations are reported in the
    /// browser's console and nothing is blocked.
    #[must_use]
    pub fn report_only(mut self, on: bool) -> Self {
        Arc::make_mut(&mut self.0).report_only = on;
        self
    }

    #[cfg(test)]
    fn render(&self, nonce: &str) -> String {
        match &self.0.rendered {
            Rendered::Segments(parts) => parts.join(nonce),
            Rendered::Static(v) => v.to_str().unwrap_or_default().to_owned(),
        }
    }

    /// The header for a request with `nonce` (none under a static policy).
    fn header(&self, nonce: Option<&Nonce>) -> Option<HeaderValue> {
        match (&self.0.rendered, nonce) {
            (Rendered::Static(v), _) => Some(v.clone()),
            (Rendered::Segments(parts), Some(nonce)) => {
                HeaderValue::try_from(parts.join(nonce.as_str())).ok()
            }
            (Rendered::Segments(_), None) => None,
        }
    }

    /// Middleware body, for `from_fn_with_state(csp, Csp::layer)`: mint the request's
    /// [`Nonce`] (none under [`static_policy`](Self::static_policy)) and send the policy
    /// with any response that carries none.
    pub async fn layer(State(this): State<Self>, mut req: Request, next: Next) -> Response {
        let nonce = (!this.0.static_policy).then(Nonce::new);
        if let Some(nonce) = &nonce {
            req.extensions_mut().insert(nonce.clone());
        }
        let mut resp = next.run(req).await;
        let name = if this.0.report_only {
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            header::CONTENT_SECURITY_POLICY
        };
        if !resp.headers().contains_key(&name)
            && let Some(v) = this.header(nonce.as_ref())
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

    #[test]
    fn style_attributes_are_allowed_only_when_asked() {
        assert!(!Csp::new().render("n").contains("style-src-attr"));
        let policy = Csp::new().allow_style_attributes().render("n");
        assert!(
            policy.contains("; style-src-attr 'unsafe-inline'"),
            "{policy}"
        );
        assert!(policy.contains("style-src 'self' 'nonce-n';"), "{policy}");
    }

    #[test]
    #[should_panic(expected = "CSP directive value")]
    fn a_directive_that_would_inject_another_is_refused() {
        let _ = Csp::new().directive("img-src", "'self'; script-src *");
    }

    #[tokio::test]
    async fn public_marks_only_plain_ok_pages() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::StatusCode;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/page", get(|| async { axum::response::Html("x") }))
            .route(
                "/cookie",
                get(|| async { ([(header::SET_COOKIE, "a=b")], axum::response::Html("x")) }),
            )
            .route(
                "/own",
                get(|| async { ([(header::CACHE_CONTROL, "public, max-age=9")], "x") }),
            )
            .route("/gone", get(|| async { StatusCode::NOT_FOUND }))
            .route_layer(public(std::time::Duration::from_secs(300)))
            .layer(axum::middleware::from_fn(private_by_default));
        let get = |path: &'static str| {
            let app = app.clone();
            async move {
                let res = app
                    .oneshot(Request::get(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                res.headers()
                    .get(header::CACHE_CONTROL)
                    .map(|v| v.to_str().unwrap().to_owned())
            }
        };
        assert_eq!(get("/page").await.as_deref(), Some("public, max-age=300"));
        assert_eq!(
            get("/cookie").await.as_deref(),
            Some(NEVER_CACHE),
            "a cookie stays private"
        );
        assert_eq!(
            get("/own").await.as_deref(),
            Some("public, max-age=9"),
            "the handler wins"
        );
        assert_eq!(get("/gone").await, None, "only a 200");
    }

    #[test]
    fn the_precomputed_header_matches_a_fresh_render() {
        let csp = Csp::new().directive("img-src", "'self' data: https://cdn.test");
        assert_eq!(
            csp.render("abc"),
            "default-src 'self'; script-src 'self' 'nonce-abc'; style-src 'self' 'nonce-abc'; \
             object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; \
             img-src 'self' data: https://cdn.test"
        );
    }

    #[test]
    fn a_static_policy_has_no_nonce_and_keeps_every_other_source() {
        let csp = Csp::new()
            .directive("script-src", "'self' 'nonce-{nonce}' https://cdn.test")
            .directive("style-src", "'nonce-{nonce}'")
            .static_policy()
            .allow_style_attributes();
        let policy = csp.render("unused");
        assert!(!policy.contains("nonce"), "{policy}");
        assert!(
            policy.contains("script-src 'self' https://cdn.test"),
            "{policy}"
        );
        assert!(
            !policy.contains("style-src "),
            "an emptied directive goes: {policy}"
        );
        assert!(
            policy.contains("style-src-attr 'unsafe-inline'"),
            "{policy}"
        );
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    }

    #[tokio::test]
    async fn a_static_policy_is_sent_and_mints_no_nonce() {
        let app = Router::new()
            .route(
                "/",
                get(|req: Request| async move {
                    assert!(req.extensions().get::<Nonce>().is_none());
                    Html("x")
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Csp::new().static_policy(),
                Csp::layer,
            ));
        let res = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let policy = res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(
            policy.starts_with("default-src 'self'; script-src 'self';"),
            "{policy}"
        );
    }

    #[test]
    #[should_panic(expected = "static policy")]
    fn a_static_policy_refuses_a_nonce() {
        let _ = Csp::new()
            .static_policy()
            .directive("script-src", "'nonce-{nonce}'");
    }
}
