//! Test harness for apps on owt-stack.
//!
//! * [`Client`]: requests straight into a [`Router`] (no socket), carrying cookies from
//!   one response to the next as a browser would.
//! * [`Server`]: the router on an ephemeral port, for tests that need a real socket
//!   (`WebSockets`, SSE, an HTTP client of their own).
//! * [`golden`]: rendered pages compared with snapshots on disk, modulo layout and
//!   escaping style.
//! * [`fragment`]: a page and its htmx fragment render one element the same way.
//! * [`accounts`]: account fixtures, a fixed session key, and a [`Client`] signed in
//!   without an Argon2 round.
//! * [`assets`]: the browser fetches nothing from another origin; vendored files match
//!   their pins.
//!
//! Dev-dependency only: [`Client::sign_in_as`] seals a session for any account, so a
//! production build must not link this crate.
//!
//! Requests carry no `Origin` and no `Sec-Fetch-Site`, so cross-origin protection
//! treats them as a non-browser client and lets them through; set the headers on a
//! request to test the protection itself.
//!
//! A [`Client`]'s requests come from [`PEER`], as axum's `MockConnectInfo` layer
//! gives them, so a handler taking `ConnectInfo<SocketAddr>` or `owt_web`'s
//! `ClientIp` answers in-process as it does behind a socket.

#![expect(
    clippy::missing_panics_doc,
    reason = "test harness: a panic is a test failure"
)]

pub mod accounts;
pub mod assets;
pub mod fragment;
pub mod golden;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::connect_info::{ConnectInfo, MockConnectInfo};
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// A response, read in full.
#[derive(Debug)]
pub struct Response {
    /// Its status.
    pub status: StatusCode,
    /// Its headers.
    pub headers: HeaderMap,
    /// Its body.
    pub body: Bytes,
}

impl Response {
    /// The body as text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON.
    #[must_use]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    /// A header's value as text.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Where a redirect points.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.header(header::LOCATION.as_str())
    }
}

/// The peer a [`Client`]'s requests come from unless it was given another:
/// `192.0.2.1:40000`, in TEST-NET-1 (RFC 5737), which no real client has.
pub const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    40_000,
);

/// Requests into a router, with a cookie jar. Clones share the jar.
#[derive(Clone)]
pub struct Client {
    app: Router,
    jar: Arc<Mutex<BTreeMap<String, String>>>,
    peer: Option<SocketAddr>,
}

impl Client {
    /// A client of `app` with an empty jar, whose requests come from [`PEER`].
    #[must_use]
    pub fn new(app: Router) -> Self {
        Self {
            app,
            jar: Arc::default(),
            peer: Some(PEER),
        }
    }

    /// Requests come from `peer` (`None`: from no peer at all, as a bare `oneshot`
    /// sends them). The peer rides as axum's `MockConnectInfo`, so the router's own
    /// `MockConnectInfo` layer, an `Extension(ConnectInfo(..))` layer, or a request
    /// carrying either, still decides.
    #[must_use]
    pub fn with_peer(mut self, peer: Option<SocketAddr>) -> Self {
        self.peer = peer;
        self
    }

    /// Set a cookie as if a response had.
    pub fn set_cookie(&self, name: &str, value: &str) {
        self.jar
            .lock()
            .unwrap()
            .insert(name.to_owned(), value.to_owned());
    }

    /// A cookie's current value.
    #[must_use]
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.jar.lock().unwrap().get(name).cloned()
    }

    /// Sign the client in as `account`: the session cookie `sessions` names, sealed as
    /// [`owt_accounts::session::sign_in`] would set it (a fresh session id, the
    /// account's id and current epoch), without the password check. Build `sessions`
    /// as the app does, with [`accounts::test_key`] for the key.
    pub fn sign_in_as<T: owt_accounts::session::Signed>(
        &self,
        sessions: &owt_web::session::Sessions<T>,
        account: &owt_accounts::Account,
    ) {
        let mut data = T::default();
        data.set_signature(Some(owt_accounts::session::Signature {
            account: account.id,
            epoch: account.session_epoch,
        }));
        self.set_cookie(
            sessions.cookie_name(),
            &sessions.seal(&owt_web::session::new_id(), &data),
        );
    }

    /// [`accounts::create`] an account named `username`, have it agree to the current
    /// policies ([`accounts::agree_to_current`]) and [`sign_in_as`](Self::sign_in_as) it:
    /// the usual start of a test of a page behind the sign-in and the policy gate.
    pub async fn sign_in_new<T: owt_accounts::session::Signed>(
        &self,
        pool: &sqlx::PgPool,
        sessions: &owt_web::session::Sessions<T>,
        username: &str,
    ) -> owt_accounts::Account {
        let account = accounts::create(pool, username).await;
        accounts::agree_to_current(pool, &account).await;
        self.sign_in_as(sessions, &account);
        account
    }

    /// Forget every cookie.
    pub fn clear_cookies(&self) {
        self.jar.lock().unwrap().clear();
    }

    /// Send `req` with the jar's cookies (unless it carries its own) from the client's
    /// peer (unless it carries one), and keep the cookies the response sets.
    pub async fn send(&self, mut req: Request<Body>) -> Response {
        if let Some(peer) = self.peer {
            let ext = req.extensions();
            if ext.get::<ConnectInfo<SocketAddr>>().is_none()
                && ext.get::<MockConnectInfo<SocketAddr>>().is_none()
            {
                req.extensions_mut().insert(MockConnectInfo(peer));
            }
        }
        if !req.headers().contains_key(header::COOKIE) {
            let jar = self.jar.lock().unwrap();
            if !jar.is_empty() {
                let pairs: Vec<String> = jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
                req.headers_mut()
                    .insert(header::COOKIE, pairs.join("; ").parse().unwrap());
            }
        }
        let res = self.app.clone().oneshot(req).await.unwrap();
        {
            let mut jar = self.jar.lock().unwrap();
            for v in res.headers().get_all(header::SET_COOKIE) {
                let Ok(c) =
                    cookie::Cookie::parse_encoded(v.to_str().unwrap_or_default().to_owned())
                else {
                    continue;
                };
                let gone = c.max_age().is_some_and(|a| a.is_zero() || a.is_negative());
                if gone || c.value().is_empty() {
                    jar.remove(c.name());
                } else {
                    jar.insert(c.name().to_owned(), c.value().to_owned());
                }
            }
        }
        let (parts, body) = res.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        Response {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    /// `GET uri`, with no fetch metadata: as a non-browser client, or a test that
    /// does not care what the request is for.
    pub async fn get(&self, uri: &str) -> Response {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    /// `GET uri` as a browser loads a page the user asked for: `Sec-Fetch-Dest:
    /// document`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Site: none`,
    /// `Sec-Fetch-User: ?1` and a browser's `Accept`. A page load is what
    /// `owt_accounts`'s policy gate interrupts, and what tells a page from a fetch or an
    /// image, so a test of such a gate loads pages with this.
    pub async fn get_page(&self, uri: &str) -> Response {
        self.send(
            Request::get(uri)
                .header("sec-fetch-dest", "document")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-site", "none")
                .header("sec-fetch-user", "?1")
                .header(header::ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// `GET uri` as htmx sends it (`HX-Request: true`).
    pub async fn get_htmx(&self, uri: &str) -> Response {
        self.send(
            Request::get(uri)
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// `POST uri` with an urlencoded form.
    pub async fn post_form(&self, uri: &str, fields: &[(&str, &str)]) -> Response {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }
}

/// The router served on `127.0.0.1` at an ephemeral port, with `ConnectInfo`. Stops
/// when dropped.
pub struct Server {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    /// The bound address.
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Serve `app`.
    pub async fn spawn(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            base: format!("http://{addr}"),
            addr,
            task,
        }
    }

    /// `base` + `path`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use axum::Form;
    use axum::http::HeaderValue;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};

    use super::*;

    #[tokio::test]
    async fn requests_come_from_a_fixed_peer() {
        let app = Router::new().route(
            "/",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
        );
        assert_eq!(
            Client::new(app.clone()).get("/").await.text(),
            PEER.to_string()
        );
        let other: SocketAddr = "198.51.100.4:1".parse().unwrap();
        assert_eq!(
            Client::new(app.clone())
                .with_peer(Some(other))
                .get("/")
                .await
                .text(),
            other.to_string()
        );
        // The router's own layer decides.
        let layered = app.clone().layer(MockConnectInfo(other));
        assert_eq!(
            Client::new(layered).get("/").await.text(),
            other.to_string()
        );
        // No peer: axum's extractor refuses, as behind no socket.
        let res = Client::new(app).with_peer(None).get("/").await;
        assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_page_load_says_it_is_one() {
        let seen = |h: HeaderMap| async move {
            [
                "sec-fetch-dest",
                "sec-fetch-mode",
                "sec-fetch-site",
                "sec-fetch-user",
                "accept",
            ]
            .map(|n| h.get(n).map_or("-", |v| v.to_str().unwrap()).to_owned())
            .join(" | ")
        };
        let client = Client::new(Router::new().route("/", get(seen)));
        assert_eq!(client.get("/").await.text(), "- | - | - | - | -");
        assert_eq!(
            client.get_page("/").await.text(),
            "document | navigate | none | ?1 | text/html,application/xhtml+xml,*/*;q=0.8"
        );
    }

    fn app() -> Router {
        Router::new()
            .route(
                "/login",
                post(|Form(f): Form<BTreeMap<String, String>>| async move {
                    let mut r = StatusCode::SEE_OTHER.into_response();
                    let h = r.headers_mut();
                    h.insert(header::LOCATION, HeaderValue::from_static("/me"));
                    h.insert(
                        header::SET_COOKIE,
                        format!("who={}; Path=/; HttpOnly", f["name"])
                            .parse()
                            .unwrap(),
                    );
                    r
                }),
            )
            .route(
                "/logout",
                post(|| async { [(header::SET_COOKIE, "who=; Max-Age=0; Path=/")] }),
            )
            .route(
                "/me",
                get(|h: HeaderMap| async move {
                    h.get(header::COOKIE)
                        .map_or("nobody".into(), |v| v.to_str().unwrap().to_owned())
                }),
            )
    }

    #[tokio::test]
    async fn cookies_carry_between_requests() {
        let c = Client::new(app());
        assert_eq!(c.get("/me").await.text(), "nobody");
        let r = c.post_form("/login", &[("name", "ann")]).await;
        assert_eq!(
            (r.status, r.location()),
            (StatusCode::SEE_OTHER, Some("/me"))
        );
        assert_eq!(c.get("/me").await.text(), "who=ann");
        c.post_form("/logout", &[]).await;
        assert_eq!(c.cookie("who"), None);
    }

    #[tokio::test]
    async fn servers_answer_on_a_real_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let s = Server::spawn(app()).await;
        let mut stream = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        stream
            .write_all(b"GET /me HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(
            out.starts_with("HTTP/1.1 200") && out.ends_with("nobody"),
            "{out}"
        );
    }
}
