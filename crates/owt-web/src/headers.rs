//! Response-shaping middleware.
//!
//! Every function here only *adds* a header a response lacks: a handler that set its
//! own (a public page's `Cache-Control`, an SSE stream's) is left alone.

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// `Cache-Control` for responses no cache may keep.
pub const NEVER_CACHE: &str = "max-age=0, no-cache, no-store, must-revalidate, private";

/// `Cache-Control: no-store`.
pub const NO_STORE: &str = "no-store";

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

/// Referrer policy, opener isolation, MIME sniffing and framing.
pub async fn security(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
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
}
