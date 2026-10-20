//! `Stack` applies the layers in the order whose consequences a request can see.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, Response};
use axum::routing::{get, post};
use owt_web::Error;
use owt_web::assets::{Assets, IMMUTABLE};
use owt_web::limits::Limits;
use owt_web::session::{Session, Sessions};
use owt_web::stack::Stack;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Data {
    #[serde(default)]
    visits: u32,
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

fn sessions() -> Sessions<Data> {
    Sessions::new(
        cookie::Key::generate(),
        "session",
        Duration::from_secs(3600),
        false,
    )
}

fn assets() -> Assets {
    let dir = std::env::temp_dir().join(format!("owt-stack-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.css"), "body{}").unwrap();
    Assets::new(dir, "/static")
}

/// Routes that touch the session and then succeed, fail or stall.
fn routes() -> Router {
    let touch = |session: Session<Data>| session.update(|d| d.visits += 1);
    Router::new()
        .route(
            "/",
            get(move |session: Session<Data>| async move {
                touch(session);
                Html("<p>home</p>")
            }),
        )
        .route(
            "/fail",
            get(move |session: Session<Data>| async move {
                touch(session);
                Error::Internal(anyhow::anyhow!("broken"))
            }),
        )
        .route(
            "/slow",
            get(move |session: Session<Data>| async move {
                touch(session);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }),
        )
        .route(
            "/signout-then-stall",
            get(|session: Session<Data>| async move {
                session.flush();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }),
        )
        .route(
            "/later",
            get(move |session: Session<Data>| async move {
                touch(session);
                Error::unavailable("later")
            }),
        )
        .route("/transfer", post(|| async {}))
}

fn stack() -> Stack<Data> {
    Stack::new(sessions())
        .limits(Limits {
            request_timeout: Duration::from_millis(100),
            body_bytes: 1024,
        })
        .error_pages(|status| Some(Html(format!("<h1>{}</h1>", status.as_u16()))))
        .assets(assets())
}

async fn send(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> Got {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res: Response = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = res.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .unwrap()
        .to_bytes();
    Got {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn nonce_of(csp: &str) -> &str {
    csp.split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("the policy names a nonce")
}

#[tokio::test]
async fn a_page_sets_the_session_cookie_and_the_headers() {
    let app = stack().apply(routes());
    let got = send(&app, "GET", "/", &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    assert!(
        got.header("set-cookie")
            .is_some_and(|c| c.starts_with("session="))
    );
    assert!(got.header("strict-transport-security").is_some());
    assert!(got.header("content-security-policy").is_some());
    assert_eq!(got.header("x-robots-tag"), None);
    assert_eq!(
        got.header("cache-control"),
        Some(owt_web::headers::NEVER_CACHE)
    );
}

#[tokio::test]
async fn error_pages_are_drawn_and_carry_the_policy_with_its_nonce() {
    let app = stack().apply(routes());
    for (uri, status) in [
        ("/nowhere", StatusCode::NOT_FOUND),
        ("/fail", StatusCode::INTERNAL_SERVER_ERROR),
        ("/slow", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let got = send(&app, "GET", uri, &[]).await;
        assert_eq!(got.status, status, "{uri}");
        if status != StatusCode::SERVICE_UNAVAILABLE {
            // The timeout's 503 is the library's, not a marked error.
            assert_eq!(got.body, format!("<h1>{}</h1>", status.as_u16()), "{uri}");
        }
        let csp = got.header("content-security-policy").expect(uri);
        assert!(nonce_of(csp).len() >= 22, "{uri}: {csp}");
        assert!(got.header("x-frame-options").is_some(), "{uri}");
    }
}

#[tokio::test]
async fn a_server_error_sets_no_session_cookie() {
    let app = stack().apply(routes());
    for uri in ["/fail", "/slow", "/later"] {
        let got = send(&app, "GET", uri, &[]).await;
        assert!(got.status.is_server_error(), "{uri}");
        assert_eq!(got.header("set-cookie"), None, "{uri}");
    }
}

#[tokio::test]
async fn static_files_are_outside_the_session_and_under_the_cache_policy() {
    let assets = assets();
    let app = stack().assets(assets.clone()).apply(routes());
    let url = assets.url("app.css");
    let got = send(&app, "GET", &url, &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.header("cache-control"), Some(IMMUTABLE));
    assert_eq!(got.header("set-cookie"), None);
    assert!(got.header("content-security-policy").is_some());

    let bare = send(&app, "GET", "/static/app.css", &[]).await;
    assert_eq!(bare.header("cache-control"), Some("no-cache"));

    // A missing file is the static service's plain 404, not the app's page.
    let missing = send(&app, "GET", "/static/gone.css", &[]).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_ne!(missing.body, "<h1>404</h1>");
}

#[tokio::test]
async fn the_account_loader_runs_inside_the_session_and_after_the_cross_origin_check() {
    let saw_session = Arc::new(AtomicUsize::new(0));
    let ran = Arc::new(AtomicUsize::new(0));
    let (saw, count) = (saw_session.clone(), ran.clone());
    let app = stack()
        .accounts(move |r| {
            r.layer(from_fn_with_state(
                (saw, count),
                |State((saw, count)): State<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
                 req: Request,
                 next: Next| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    if req.extensions().get::<Session<Data>>().is_some() {
                        saw.fetch_add(1, Ordering::SeqCst);
                    }
                    next.run(req).await
                },
            ))
        })
        .apply(routes());
    send(&app, "GET", "/", &[]).await;
    assert_eq!(
        (
            saw_session.load(Ordering::SeqCst),
            ran.load(Ordering::SeqCst)
        ),
        (1, 1)
    );

    let foreign = send(
        &app,
        "POST",
        "/transfer",
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert!(foreign.header("content-security-policy").is_some());
    assert!(foreign.header("x-frame-options").is_some());
    assert_eq!(ran.load(Ordering::SeqCst), 1, "refused before the loader");
}

#[tokio::test]
async fn the_timer_sits_outside_the_limits() {
    let seen: Arc<Mutex<Vec<u16>>> = Arc::default();
    let log = seen.clone();
    let app = stack()
        .timer(move |r| {
            r.layer(from_fn_with_state(
                log,
                |State(log): State<Arc<Mutex<Vec<u16>>>>, req: Request, next: Next| async move {
                    let res = next.run(req).await;
                    log.lock().unwrap().push(res.status().as_u16());
                    res
                },
            ))
        })
        .apply(routes());
    send(&app, "GET", "/slow", &[]).await;
    assert_eq!(*seen.lock().unwrap(), [503]);
}

#[tokio::test]
async fn options_are_off_until_asked_for() {
    let app = stack().noindex(true).no_store_by_default().apply(routes());
    let got = send(&app, "GET", "/nowhere", &[]).await;
    assert_eq!(got.header("x-robots-tag"), Some("noindex, nofollow"));
    assert_eq!(
        got.header(header::CACHE_CONTROL.as_str()),
        Some(owt_web::headers::NO_STORE)
    );
}

#[tokio::test]
async fn the_default_fallback_replaces_the_apps_and_keep_fallback_preserves_it() {
    let own = || {
        Router::new()
            .route("/", get(|| async { "x" }))
            .fallback(|| async { (StatusCode::IM_A_TEAPOT, "own") })
    };
    let replaced = Stack::new(sessions()).apply(own());
    assert_eq!(
        send(&replaced, "GET", "/nope", &[]).await.status,
        StatusCode::NOT_FOUND
    );
    let kept = Stack::new(sessions()).keep_fallback().apply(own());
    assert_eq!(
        send(&kept, "GET", "/nope", &[]).await.status,
        StatusCode::IM_A_TEAPOT
    );
}

/// A sign-out that then stalls past the deadline still clears the cookie: the session
/// layer sees the timeout's 503 and seals the emptied session. With the layer inside
/// `Limits` the timeout would drop it mid-request and no cookie would be set.
#[tokio::test]
async fn the_session_layer_sits_outside_the_limits() {
    let app = stack().apply(routes());
    let got = send(&app, "GET", "/signout-then-stall", &[]).await;
    assert_eq!(got.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        got.header("set-cookie")
            .is_some_and(|c| c.starts_with("session=")),
        "a sign-out stands through the timeout"
    );
}
