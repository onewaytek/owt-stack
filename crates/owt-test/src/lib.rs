//! Test harness for the onewaytek apps.
//!
//! * [`Client`]: requests straight into a [`Router`] (no socket), carrying cookies from
//!   one response to the next as a browser would.
//! * [`Server`]: the router on an ephemeral port, for tests that need a real socket
//!   (`WebSockets`, SSE, an HTTP client of their own).
//! * [`golden`]: rendered pages compared with snapshots on disk, modulo layout and
//!   escaping style.
//! * [`fragment`]: a page and its htmx fragment render one element the same way.
//!
//! Requests carry no `Origin` and no `Sec-Fetch-Site`, so cross-origin protection
//! treats them as a non-browser client and lets them through; set the headers on a
//! request to test the protection itself.

#![expect(
    clippy::missing_panics_doc,
    reason = "test harness: a panic is a test failure"
)]

pub mod fragment;
pub mod golden;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
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

/// Requests into a router, with a cookie jar. Clones share the jar.
#[derive(Clone)]
pub struct Client {
    app: Router,
    jar: Arc<Mutex<BTreeMap<String, String>>>,
}

impl Client {
    /// A client of `app` with an empty jar.
    #[must_use]
    pub fn new(app: Router) -> Self {
        Self {
            app,
            jar: Arc::default(),
        }
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

    /// Forget every cookie.
    pub fn clear_cookies(&self) {
        self.jar.lock().unwrap().clear();
    }

    /// Send `req` with the jar's cookies (unless it carries its own), and keep the
    /// cookies the response sets.
    pub async fn send(&self, mut req: Request<Body>) -> Response {
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

    /// `GET uri`.
    pub async fn get(&self, uri: &str) -> Response {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
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
