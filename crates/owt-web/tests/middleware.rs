//! The response-shaping middleware, each through a router: the parts mutation
//! testing found no test would notice breaking.

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use owt_web::assets::{Assets, IMMUTABLE};
use owt_web::csrf::CrossOrigin;
use owt_web::flash::Level;
use owt_web::headers::{self, Nonce};
use owt_web::{Error, error::error_pages};
use tower::ServiceExt;

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let res: Response = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

fn get_req(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn static_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("owt-mw-{name}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("css")).unwrap();
    std::fs::write(dir.join("css/app.css"), "body{}").unwrap();
    dir
}

/// A static service standing in for `ServeDir`: the file's bytes, or 404.
fn static_app(assets: &Assets) -> Router {
    let dir = assets.dir().to_owned();
    Router::new().nest(
        "/static",
        Router::new()
            .fallback(move |req: Request<Body>| {
                let path = dir.join(req.uri().path().trim_start_matches('/'));
                async move {
                    match std::fs::read(path) {
                        Ok(bytes) => bytes.into_response(),
                        Err(_) => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            })
            .layer(from_fn_with_state(assets.clone(), Assets::cache_policy)),
    )
}

#[tokio::test]
async fn only_a_url_with_the_files_own_hash_is_immutable() {
    let assets = Assets::new(static_dir("assets"), "/static");
    let app = static_app(&assets);
    let url = assets.url("css/app.css");
    let hash = assets.hash("css/app.css").unwrap();

    let (status, headers, body) = call(&app, get_req(&url)).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "body{}"));
    assert_eq!(headers[header::CACHE_CONTROL], IMMUTABLE);

    // Anything else must not be pinned in a cache for a year: no hash, another
    // hash, the hash under another key, or a hash on a file that is not there.
    for uri in [
        "/static/css/app.css".to_owned(),
        "/static/css/app.css?v=0000000000000000".to_owned(),
        format!("/static/css/app.css?v={hash}0"),
        format!("/static/css/app.css?x={hash}"),
        format!("/static/css/app.css?vv={hash}"),
        format!("/static/css/missing.css?v={hash}"),
        format!("/static/css/../css/app.css?v={hash}"),
    ] {
        let (_, headers, _) = call(&app, get_req(&uri)).await;
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{uri}");
    }
    // The hash among other parameters still pins it.
    let (_, headers, _) = call(&app, get_req(&format!("/static/css/app.css?a=1&v={hash}"))).await;
    assert_eq!(headers[header::CACHE_CONTROL], IMMUTABLE);
}

#[tokio::test]
async fn a_file_that_changes_is_never_served_immutable_under_its_old_hash() {
    let dir = static_dir("rebuild");
    let assets = Assets::new(&dir, "/static").watch(true);
    let app = static_app(&assets);
    let old = assets.url("css/app.css");
    std::fs::write(dir.join("css/app.css"), "body{color:red}").unwrap();
    let (_, headers, body) = call(&app, get_req(&old)).await;
    assert_eq!(body, "body{color:red}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
    assert_ne!(assets.url("css/app.css"), old);
}

#[tokio::test]
async fn error_pages_replace_marked_bodies_and_only_those() {
    let draw = |status: StatusCode| {
        (status == StatusCode::NOT_FOUND).then(|| Html("<h1>Nothing here</h1>".to_owned()))
    };
    let app = Router::new()
        .route("/gone", get(|| async { Err::<(), _>(Error::NotFound) }))
        .route(
            "/broken",
            get(|| async { Err::<(), _>(Error::Internal(anyhow::anyhow!("secret detail"))) }),
        )
        .route(
            "/refused",
            get(|| async { Err::<(), _>(Error::forbidden()) }),
        )
        .route(
            "/plain404",
            get(|| async { (StatusCode::NOT_FOUND, "an API's own 404") }),
        )
        .layer(from_fn(move |req, next| error_pages(req, next, draw)));

    let (status, headers, body) = call(&app, get_req("/gone")).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::NOT_FOUND, "<h1>Nothing here</h1>")
    );
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    // No page drawn for 500: the bare body, which tells the client nothing.
    let (status, _, body) = call(&app, get_req("/broken")).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, "Server error")
    );
    assert!(!body.contains("secret"));

    let (status, _, body) = call(&app, get_req("/refused")).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::FORBIDDEN, "Forbidden")
    );
    let (_, _, body) = call(&app, get_req("/plain404")).await;
    assert_eq!(
        body, "an API's own 404",
        "an unmarked response is the handler's"
    );
}

#[tokio::test]
async fn caching_defaults_and_noindex() {
    let app = Router::new()
        .route("/json", get(|| async { "{}" }))
        .route(
            "/public",
            get(|| async { ([(header::CACHE_CONTROL, "public, max-age=60")], "{}") }),
        )
        .layer(from_fn(headers::no_store_by_default))
        .layer(from_fn(headers::noindex));
    let (status, h, body) = call(&app, get_req("/json")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "{}"));
    assert_eq!(h[header::CACHE_CONTROL], headers::NO_STORE);
    assert_eq!(h["x-robots-tag"], "noindex, nofollow");
    let (_, h, body) = call(&app, get_req("/public")).await;
    assert_eq!(body, "{}");
    assert_eq!(h[header::CACHE_CONTROL], "public, max-age=60");
    assert_eq!(h["x-robots-tag"], "noindex, nofollow");
}

#[tokio::test]
async fn a_refusal_says_why_and_passes_what_it_should() {
    let app = Router::new()
        .route("/x", post(|| async { "done" }))
        .layer(from_fn_with_state(CrossOrigin::new(), CrossOrigin::layer));
    let post_with = |name: &'static str, value: &'static str| {
        Request::post("/x")
            .header(header::HOST, "app.example")
            .header(name, value)
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, body) = call(&app, post_with("sec-fetch-site", "cross-site")).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::FORBIDDEN, "Forbidden: cross-origin request.")
    );
    let (status, _, body) = call(&app, post_with("origin", "https://evil.example")).await;
    assert_eq!(
        (status, body.as_str()),
        (
            StatusCode::FORBIDDEN,
            "Forbidden: Origin does not match Host."
        )
    );
    let (status, _, body) = call(&app, post_with("sec-fetch-site", "same-origin")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "done"));
}

#[tokio::test]
async fn names_templates_read() {
    assert_eq!(
        [Level::Success, Level::Info, Level::Warning, Level::Error].map(Level::as_str),
        ["success", "info", "warning", "error"]
    );
    let app = Router::new().route(
        "/",
        get(|nonce: Nonce| async move { format!("{}|{nonce}", nonce.as_str()) }),
    );
    let (_, _, body) = call(&app, get_req("/")).await;
    let (as_str, shown) = body.split_once('|').unwrap();
    assert!(as_str.len() >= 22 && as_str == shown);
}
