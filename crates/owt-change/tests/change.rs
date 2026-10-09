//! The routes against a stub tracker on `127.0.0.1`: who may send, what is
//! forwarded, and what the admin is told. No database: a test extractor stands in
//! for the signed-in admin, except where `Staff`'s own wall is the point.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use owt_change::{Admin, ChangeRequest, ChangeRequests, Config, Requester};
use owt_test::{Client, Server};
use serde_json::{Value, json};

/// "Signed in" as the `x-admin` header names; no header, no admin.
struct TestAdmin(String);

// The trait's method is async; this one has nothing to wait for.
#[allow(clippy::unused_async_trait_impl)]
impl<S: Send + Sync> FromRequestParts<S> for TestAdmin {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get("x-admin")
            .and_then(|v| v.to_str().ok())
            .map(|v| Self(v.to_owned()))
            .ok_or(StatusCode::FORBIDDEN)
    }
}

impl Admin for TestAdmin {
    fn requester(&self) -> Requester {
        Requester {
            username: self.0.clone(),
            email: format!("{}@site.test", self.0),
        }
    }
}

type Seen = Arc<Mutex<Vec<(Option<String>, ChangeRequest)>>>;

/// A tracker that records what it is sent and answers by the title: "refuse" is a
/// 422 with a sentence, "key" a 401, "boom" a 500, "huge" a 422 past the reply cap;
/// anything else is filed.
async fn tracker() -> (Server, Seen) {
    let seen = Seen::default();
    let log = seen.clone();
    let app = Router::new().route(
        "/api/change-requests",
        post(
            move |headers: HeaderMap, Json(request): Json<ChangeRequest>| {
                let log = log.clone();
                async move {
                    let bearer = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let title = request.title.clone();
                    log.lock().unwrap().push((bearer, request));
                    match title.as_str() {
                        "refuse" => (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({"error": "Please fill in 'Your name'."})),
                        ),
                        "key" => (StatusCode::UNAUTHORIZED, Json(json!({"error": "no"}))),
                        "boom" => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))),
                        "huge" => (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(json!({"error": "x".repeat(64 * 1024)})),
                        ),
                        _ => (StatusCode::CREATED, Json(json!({"id": 7}))),
                    }
                }
            },
        ),
    );
    (Server::spawn(app).await, seen)
}

fn feature(endpoint: &str) -> ChangeRequests {
    ChangeRequests::new(
        Config::from_values(Some(endpoint.to_owned()), Some("kys_site-key".into())).unwrap(),
        reqwest::Client::new(),
    )
}

fn app(feature: &ChangeRequests) -> Client {
    Client::new(Router::new().nest("/staff", feature.routes::<TestAdmin, ()>()))
}

async fn send(client: &Client, admin: Option<&str>, body: Value) -> owt_test::Response {
    let mut request = Request::post("/staff/change-requests")
        .header("content-type", "application/json")
        .header("user-agent", "TestBrowser/1.0");
    if let Some(admin) = admin {
        request = request.header("x-admin", admin);
    }
    client
        .send(request.body(Body::from(body.to_string())).unwrap())
        .await
}

fn draft(title: &str) -> Value {
    json!({
        "title": title,
        "description": "The price is too small on phones.",
        "page_url": "https://site.test/menu",
        "element": {"selector": "main > h1", "text": "Opening hours"},
        "viewport": "390x844",
        // A browser naming somebody else is ignored.
        "requested_by": {"username": "mallory"},
    })
}

#[tokio::test]
async fn an_admins_request_is_forwarded_under_the_sites_key_as_them() {
    let (server, seen) = tracker().await;
    let client = app(&feature(&server.url("/api/change-requests")));

    let sent = send(&client, Some("ana"), draft("Bigger prices")).await;
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.text());
    assert_eq!(sent.json::<Value>()["sent"], true);

    let seen = seen.lock().unwrap();
    let (bearer, request) = &seen[0];
    assert_eq!(bearer.as_deref(), Some("Bearer kys_site-key"));
    assert_eq!(request.title, "Bigger prices");
    assert_eq!(request.page_url, "https://site.test/menu");
    assert_eq!(request.element.text, "Opening hours");
    assert_eq!(request.user_agent, "TestBrowser/1.0");
    assert_eq!(
        request.requested_by,
        Requester {
            username: "ana".into(),
            email: "ana@site.test".into()
        },
        "who asked is the session's, not the body's"
    );
}

#[tokio::test]
async fn only_an_admin_may_send() {
    let (server, seen) = tracker().await;
    let client = app(&feature(&server.url("/api/change-requests")));
    assert_eq!(
        send(&client, None, draft("x")).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn staff_is_walled_like_any_staff_page() {
    // Without the accounts layer nobody is signed in, so `Staff` sends the
    // visitor to sign in, naming the nested path.
    let feature = feature("https://tracker.test/api/change-requests");
    let client =
        Client::new(Router::new().nest("/staff", feature.routes::<owt_accounts::Staff, ()>()));
    let refused = send(&client, None, draft("x")).await;
    assert_eq!(refused.status, StatusCode::SEE_OTHER);
    assert!(
        refused
            .location()
            .unwrap()
            .starts_with("/login?next=%2Fstaff")
    );
}

#[tokio::test]
async fn the_trackers_sentence_reaches_the_admin() {
    let (server, _) = tracker().await;
    let client = app(&feature(&server.url("/api/change-requests")));

    let refused = send(&client, Some("ana"), draft("refuse")).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        refused.json::<Value>()["error"],
        "Please fill in 'Your name'."
    );

    let key = send(&client, Some("ana"), draft("key")).await;
    assert_eq!(key.status, StatusCode::BAD_GATEWAY);
    assert!(
        key.json::<Value>()["error"]
            .as_str()
            .unwrap()
            .contains("key for change requests was refused")
    );

    // A reply past the cap is not read, let alone relayed.
    let huge = send(&client, Some("ana"), draft("huge")).await;
    assert_eq!(huge.status, StatusCode::BAD_GATEWAY);
    assert!(huge.text().len() < 1024);

    let boom = send(&client, Some("ana"), draft("boom")).await;
    assert_eq!(boom.status, StatusCode::BAD_GATEWAY);
    assert!(
        boom.json::<Value>()["error"]
            .as_str()
            .unwrap()
            .contains("Try again")
    );
}

#[tokio::test]
async fn an_unreachable_tracker_says_try_again() {
    // Port 9 (discard) on loopback: nothing listens.
    let client = app(&feature("http://127.0.0.1:9/api/change-requests"));
    let sent = send(&client, Some("ana"), draft("Bigger prices")).await;
    assert_eq!(sent.status, StatusCode::BAD_GATEWAY);
    assert!(
        sent.json::<Value>()["error"]
            .as_str()
            .unwrap()
            .contains("Try again")
    );
}

#[tokio::test]
async fn a_request_without_a_title_is_not_forwarded() {
    let (server, seen) = tracker().await;
    let client = app(&feature(&server.url("/api/change-requests")));
    let sent = send(&client, Some("ana"), draft("   ")).await;
    assert_eq!(sent.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        sent.json::<Value>()["error"],
        "Give the request a short title."
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unconfigured_it_is_not_there() {
    let off = ChangeRequests::new(None, reqwest::Client::new());
    let client = app(&off);
    assert_eq!(
        send(&client, Some("ana"), draft("x")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client.get("/staff/change.js").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        askama::Template::render(&off.button("/staff", true)).unwrap(),
        ""
    );
}

#[tokio::test]
async fn the_button_is_for_admins_and_its_script_is_pinned_by_hash() {
    let feature = feature("https://tracker.test/api/change-requests");
    assert_eq!(
        askama::Template::render(&feature.button("/staff", false)).unwrap(),
        "",
        "nothing for anyone else"
    );
    let tag = askama::Template::render(&feature.button("/staff", true)).unwrap();
    assert!(
        tag.contains(r#"data-endpoint="/staff/change-requests""#),
        "{tag}"
    );
    let src = tag
        .split(r#"src=""#)
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(src.starts_with("/staff/change.js?v="));

    let client = app(&feature);
    let pinned = client.get(src).await;
    assert_eq!(pinned.status, StatusCode::OK);
    assert!(
        pinned
            .header("content-type")
            .unwrap()
            .starts_with("text/javascript")
    );
    assert!(
        pinned
            .header("cache-control")
            .unwrap()
            .contains("immutable")
    );
    assert!(pinned.text().contains("Request a change"));
    let stale = client.get("/staff/change.js?v=old").await;
    assert_eq!(stale.header("cache-control"), Some("no-cache"));
}
