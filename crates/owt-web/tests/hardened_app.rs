//! The layers composed as the README composes them, exercised as one app.
//!
//! Each module's own tests show the layer works. These show the composition does:
//! that the order is right, that an inner layer's refusal still leaves through the
//! outer ones, and that the sign-in story holds end to end (fixation, revocation, an
//! outage, a replayed cookie).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{Html, Response};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use owt_web::csrf::CrossOrigin;
use owt_web::headers::{self, Csp, Nonce};
use owt_web::limits::Limits;
use owt_web::session::{Presented, Session, Sessions, Verdict};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const COOKIE: &str = "__Host-session";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Data {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<i64>,
    #[serde(default)]
    epoch: i32,
}

/// The "database": one account's epoch, and whether it answers.
#[derive(Clone, Default)]
struct App {
    epoch: Arc<AtomicI32>,
    db_down: Arc<AtomicBool>,
    /// Times a state-changing handler (or the socket handler) ran.
    reached: Arc<AtomicUsize>,
}

#[derive(Deserialize)]
struct Touch {
    touch: Option<String>,
}

#[expect(clippy::too_many_lines, reason = "one app, its routes side by side")]
fn app(state: &App) -> Router {
    let db = state.clone();
    let sessions = Sessions::<Data>::new(
        cookie::Key::generate(),
        COOKIE,
        Duration::from_secs(3600),
        false,
    )
    .validate_with(move |s: Presented<Data>| {
        let db = db.clone();
        async move {
            if s.data.user.is_none() {
                return Verdict::Valid;
            }
            if db.db_down.load(Ordering::SeqCst) {
                return Verdict::Unknown;
            }
            (db.epoch.load(Ordering::SeqCst) == s.data.epoch).into()
        }
    });
    let routes = Router::new()
        .route(
            "/",
            get(|nonce: Nonce| async move { Html(format!("<script nonce=\"{nonce}\"></script>")) }),
        )
        .route(
            "/public",
            get(
                |session: Session<Data>, Query(q): Query<Touch>| async move {
                    if q.touch.is_some() {
                        let _ = session.ensure_id();
                    }
                    (
                        [(header::CACHE_CONTROL, "public, s-maxage=600")],
                        Html("<p>for everyone</p>"),
                    )
                },
            ),
        )
        .route(
            "/id",
            get(|session: Session<Data>| async move { session.id().unwrap_or_default() }),
        )
        .route(
            "/me",
            get(|session: Session<Data>| async move {
                session
                    .read(|d| d.user)
                    .map_or("nobody".to_owned(), |u| u.to_string())
            }),
        )
        .route(
            "/login",
            post(
                |State(app): State<App>, session: Session<Data>| async move {
                    app.reached.fetch_add(1, Ordering::SeqCst);
                    session.cycle_id();
                    session.update(|d| {
                        d.user = Some(7);
                        d.epoch = app.epoch.load(Ordering::SeqCst);
                    });
                },
            ),
        )
        .route(
            "/logout",
            post(
                |State(app): State<App>, session: Session<Data>| async move {
                    app.epoch.fetch_add(1, Ordering::SeqCst);
                    session.flush();
                },
            ),
        )
        .route(
            "/transfer",
            post(|State(app): State<App>| async move {
                app.reached.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .route(
            "/ws",
            get(|State(app): State<App>| async move {
                app.reached.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .route(
            "/slow",
            get(|| async { tokio::time::sleep(Duration::from_secs(30)).await }),
        )
        .route("/echo", post(|body: String| async move { body }));
    let limits = Limits {
        request_timeout: Duration::from_millis(100),
        body_bytes: 64,
    };
    let pages = limits
        .apply(routes)
        .layer(from_fn_with_state(sessions, Sessions::<Data>::layer))
        .layer(from_fn_with_state(CrossOrigin::new(), CrossOrigin::layer));
    Router::new()
        .merge(pages)
        .layer(from_fn_with_state(Csp::new(), Csp::layer))
        .layer(from_fn(headers::private_by_default))
        .layer(from_fn(headers::security))
        .with_state(state.clone())
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

    /// `name=value` of the session cookie this response set, if it set one.
    fn cookie(&self) -> Option<String> {
        self.header("set-cookie")
            .map(|v| v.split(';').next().unwrap().to_owned())
    }
}

async fn send(app: &Router, req: Request<Body>) -> Got {
    let res: Response = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    Got {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn request(method: &str, uri: &str, cookie: Option<&str>) -> axum::http::request::Builder {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b
}

async fn get_(app: &Router, uri: &str, cookie: Option<&str>) -> Got {
    send(
        app,
        request("GET", uri, cookie).body(Body::empty()).unwrap(),
    )
    .await
}

async fn post_(app: &Router, uri: &str, cookie: Option<&str>) -> Got {
    send(
        app,
        request("POST", uri, cookie).body(Body::empty()).unwrap(),
    )
    .await
}

async fn sign_in(app: &Router) -> String {
    let got = post_(app, "/login", None).await;
    assert_eq!(got.status, StatusCode::OK);
    got.cookie().expect("signing in sets the cookie")
}

#[tokio::test]
async fn every_response_carries_the_security_headers_refusals_included() {
    let state = App::default();
    let app = app(&state);
    let cross_site = request("POST", "/transfer", None)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let too_large = request("POST", "/echo", None)
        .body(Body::from("x".repeat(65)))
        .unwrap();
    let cases = [
        (get_(&app, "/", None).await, StatusCode::OK),
        (
            get_(&app, "/no-such-page", None).await,
            StatusCode::NOT_FOUND,
        ),
        (send(&app, cross_site).await, StatusCode::FORBIDDEN),
        (send(&app, too_large).await, StatusCode::PAYLOAD_TOO_LARGE),
        (
            get_(&app, "/slow", None).await,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (post_(&app, "/", None).await, StatusCode::METHOD_NOT_ALLOWED),
    ];
    for (got, status) in cases {
        assert_eq!(got.status, status);
        for name in [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "content-security-policy",
        ] {
            assert!(got.header(name).is_some(), "{status}: no {name}");
        }
        let csp = got.header("content-security-policy").unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("object-src 'none'"));
    }
}

#[tokio::test]
async fn the_policy_names_the_nonce_the_page_was_given_and_never_twice() {
    let app = app(&App::default());
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let got = get_(&app, "/", None).await;
        let nonce = got
            .body
            .split('"')
            .nth(1)
            .expect("the page's nonce")
            .to_owned();
        let csp = got.header("content-security-policy").unwrap();
        assert!(csp.contains(&format!("'nonce-{nonce}'")), "{csp}");
        assert!(nonce.len() >= 22, "128 bits, base64");
        assert!(seen.insert(nonce), "a nonce was reused");
        // A page with a nonce is per-request: it must not be cached.
        assert_eq!(got.header("cache-control"), Some(headers::NEVER_CACHE));
    }
}

#[tokio::test]
async fn a_request_from_another_site_never_reaches_the_handler() {
    let state = App::default();
    let app = app(&state);
    for (name, value) in [
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-site", "same-site"),
        ("origin", "https://evil.example"),
        ("origin", "null"),
    ] {
        let req = request("POST", "/transfer", None)
            .header(header::HOST, "app.example")
            .header(name, value)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(&app, req).await.status,
            StatusCode::FORBIDDEN,
            "{name}: {value}"
        );
    }
    assert_eq!(state.reached.load(Ordering::SeqCst), 0);

    for (name, value) in [
        ("sec-fetch-site", "same-origin"),
        ("origin", "https://app.example"),
    ] {
        let req = request("POST", "/transfer", None)
            .header(header::HOST, "app.example")
            .header(name, value)
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, req).await.status, StatusCode::OK);
    }
    assert_eq!(state.reached.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_socket_from_another_site_is_refused_before_the_upgrade() {
    let state = App::default();
    let app = app(&state);
    let upgrade = |origin: &'static str| {
        request("GET", "/ws", None)
            .header(header::HOST, "app.example")
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .unwrap()
    };
    let refused = send(&app, upgrade("https://evil.example")).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(state.reached.load(Ordering::SeqCst), 0);
    assert_eq!(
        send(&app, upgrade("https://app.example")).await.status,
        StatusCode::OK
    );
    assert_eq!(state.reached.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_session_cookie_is_locked_down_and_never_cacheable() {
    let app = app(&App::default());
    let got = post_(&app, "/login", None).await;
    let set = got.header("set-cookie").unwrap();
    for attribute in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=3600",
    ] {
        assert!(set.contains(attribute), "{attribute} missing from {set}");
    }
    assert!(set.starts_with("__Host-session="));
    assert!(!set.contains("Domain"), "__Host- forbids Domain");
    assert_eq!(got.header("cache-control"), Some(headers::NEVER_CACHE));
}

#[tokio::test]
async fn a_public_page_stays_public_until_it_sets_a_cookie() {
    let app = app(&App::default());
    let plain = get_(&app, "/public", None).await;
    assert_eq!(plain.header("cache-control"), Some("public, s-maxage=600"));
    assert!(plain.cookie().is_none());

    let touched = get_(&app, "/public?touch=1", None).await;
    assert!(touched.cookie().is_some());
    assert_eq!(
        touched.header("cache-control"),
        Some(headers::NEVER_CACHE),
        "a shared cache would hand this cookie to the next visitor"
    );

    // With the cookie already held, nothing is set and the page is public again.
    let cookie = touched.cookie().unwrap();
    let again = get_(&app, "/public?touch=1", Some(&cookie)).await;
    assert!(again.cookie().is_none());
    assert_eq!(again.header("cache-control"), Some("public, s-maxage=600"));
}

#[tokio::test]
async fn signing_in_replaces_a_session_id_planted_beforehand() {
    let app = app(&App::default());
    // The attacker obtains a guest session and plants its cookie in the victim's
    // browser; the victim then signs in with it.
    let planted = get_(&app, "/public?touch=1", None).await.cookie().unwrap();
    let planted_id = get_(&app, "/id", Some(&planted)).await.body;
    assert_eq!(planted_id.len(), 32);

    let signed_in = post_(&app, "/login", Some(&planted))
        .await
        .cookie()
        .unwrap();
    let new_id = get_(&app, "/id", Some(&signed_in)).await.body;
    assert_ne!(
        new_id, planted_id,
        "the planted id became a signed-in session"
    );
    // And the cookie the attacker still holds is nobody's.
    assert_eq!(get_(&app, "/me", Some(&planted)).await.body, "nobody");
    assert_eq!(get_(&app, "/me", Some(&signed_in)).await.body, "7");
}

#[tokio::test]
async fn signing_out_revokes_the_cookie_someone_copied() {
    let state = App::default();
    let app = app(&state);
    let cookie = sign_in(&app).await;
    assert_eq!(get_(&app, "/me", Some(&cookie)).await.body, "7");

    let out = post_(&app, "/logout", Some(&cookie)).await;
    let replaced = out.cookie().expect("sign-out replaces the cookie");
    assert_eq!(get_(&app, "/me", Some(&replaced)).await.body, "nobody");

    // The copy taken before sign-out: refused, and told to go away.
    let replay = get_(&app, "/me", Some(&cookie)).await;
    assert_eq!(replay.body, "nobody");
    let cleared = replay
        .header("set-cookie")
        .expect("the revoked cookie is cleared");
    assert!(cleared.starts_with("__Host-session=;") && cleared.contains("Max-Age=0"));
    // A state-changing request with it acts as nobody, too.
    assert_eq!(get_(&app, "/id", Some(&cookie)).await.body, "");
}

#[tokio::test]
async fn an_outage_withholds_sessions_and_signs_no_one_out() {
    let state = App::default();
    let app = app(&state);
    let cookie = sign_in(&app).await;

    state.db_down.store(true, Ordering::SeqCst);
    let during = get_(&app, "/me", Some(&cookie)).await;
    assert_eq!(
        during.body, "nobody",
        "an unchecked session is not believed"
    );
    assert!(during.cookie().is_none(), "and its cookie is left alone");
    // A handler that touches the session it could not see must not overwrite it.
    assert!(
        get_(&app, "/public?touch=1", Some(&cookie))
            .await
            .cookie()
            .is_none()
    );

    state.db_down.store(false, Ordering::SeqCst);
    assert_eq!(
        get_(&app, "/me", Some(&cookie)).await.body,
        "7",
        "the outage signed no one out"
    );

    // Signing out during an outage still takes effect.
    state.db_down.store(true, Ordering::SeqCst);
    let out = post_(&app, "/logout", Some(&cookie)).await;
    assert!(out.cookie().is_some());
    state.db_down.store(false, Ordering::SeqCst);
    assert_eq!(get_(&app, "/me", Some(&cookie)).await.body, "nobody");
}

#[tokio::test]
async fn cookies_that_are_not_ours_are_no_session_and_no_error() {
    let app = app(&App::default());
    let real = sign_in(&app).await;
    let value = real.split_once('=').unwrap().1;
    let mut flipped = value.as_bytes().to_vec();
    let mid = flipped.len() / 2;
    flipped[mid] = if flipped[mid] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).unwrap();
    for cookie in [
        format!("{COOKIE}={flipped}"),
        format!("{COOKIE}="),
        format!("{COOKIE}=%00%ff%zz"),
        format!("{COOKIE}={}", "A".repeat(8000)),
        COOKIE.to_owned(),
        ";;;===;;;".to_owned(),
        format!("session={value}"),
    ] {
        let got = get_(&app, "/me", Some(&cookie)).await;
        assert_eq!(
            (got.status, got.body.as_str()),
            (StatusCode::OK, "nobody"),
            "{cookie:.60}"
        );
    }
    // A forged cookie of the same name ahead of the real one does not mask it.
    let both = format!("{COOKIE}=forged; {real}");
    assert_eq!(get_(&app, "/me", Some(&both)).await.body, "7");
}

#[tokio::test]
async fn limits_refuse_without_running_the_handler_to_the_end() {
    let app = app(&App::default());
    let started = std::time::Instant::now();
    assert_eq!(
        get_(&app, "/slow", None).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let at_limit = request("POST", "/echo", None)
        .body(Body::from("x".repeat(64)))
        .unwrap();
    assert_eq!(send(&app, at_limit).await.status, StatusCode::OK);
}
