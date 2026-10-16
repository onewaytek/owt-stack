//! Bounds on what one request may cost.
//!
//! Without them a handler waiting on a stalled dependency holds its connection for as
//! long as the client cares to wait. [`Limits::apply`] bounds the time to a response
//! and the size of a request body.
//!
//! Two things it does not bound. A response *body* may stream for as long as it
//! likes: the timeout ends when the handler returns, so SSE streams and `WebSocket`
//! upgrades are unaffected. And the time a client takes to *send* its request head is
//! the server's to bound: `owt_runtime::serve` closes a connection whose head takes
//! over 30 seconds (`axum::serve` sets no such timeout).
//!
//! `Limits` is also a [`Layer`], for the few routes that need other bounds: a route
//! layered with its own (`post(handler).layer(slow)`, or `.route_layer(slow)` before
//! [`Limits::apply`]) has those instead of the router's, longer or shorter. The
//! bounds nearest the handler win: an inner layer moves the deadline the outer one is
//! waiting on, still counted from when the request reached the outer one, and sets
//! its own body limit over the outer's.
//!
//! A timeout drops the handler's future where it stands: what it was awaiting is
//! abandoned and a transaction it held rolls back. Work it handed to `tokio::spawn`
//! (or a queue) runs on, so the client sees a 503 for work that completes, and a
//! retry does it again.

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response, StatusCode};
use tokio::sync::Notify;
use tokio::time::Instant;
use tower::{Layer, Service};

/// The bounds. The defaults suit form posts and rendered pages.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How long a handler has to produce its response; a slower one answers 503.
    pub request_timeout: Duration,
    /// The largest request body an extractor will read; a larger one answers 413. A
    /// route that takes uploads raises it with its own `Limits` (or
    /// `DefaultBodyLimit`).
    pub body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            body_bytes: 1024 * 1024,
        }
    }
}

impl Limits {
    /// `router` with these bounds on every route it has so far.
    pub fn apply<S>(&self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router.layer(*self)
    }
}

impl<S> Layer<S> for Limits {
    type Service = Limited<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Limited {
            inner,
            limits: *self,
        }
    }
}

/// A service under [`Limits`].
#[derive(Clone, Debug)]
pub struct Limited<S> {
    inner: S,
    limits: Limits,
}

/// The request's deadline, in its extensions: the outermost bounds wait on it, and
/// any inside them move it.
#[derive(Clone, Debug)]
struct Deadline(Arc<DeadlineInner>);

#[derive(Debug)]
struct DeadlineInner {
    start: Instant,
    at: Mutex<Instant>,
    moved: Notify,
}

impl Deadline {
    fn at(&self) -> Instant {
        *self.0.at.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, timeout: Duration) {
        *self.0.at.lock().unwrap_or_else(PoisonError::into_inner) = self.0.start + timeout;
        // A permit, not a broadcast: the waiter wakes even if it was not yet waiting.
        self.0.moved.notify_one();
    }
}

impl<S, B, ResBody> Service<Request<B>> for Limited<S>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        DefaultBodyLimit::max(self.limits.body_bytes).apply(&mut req);
        if let Some(outer) = req.extensions().get::<Deadline>() {
            outer.set(self.limits.request_timeout);
            return Box::pin(self.inner.call(req));
        }
        let start = Instant::now();
        let deadline = Deadline(Arc::new(DeadlineInner {
            start,
            at: Mutex::new(start + self.limits.request_timeout),
            moved: Notify::new(),
        }));
        req.extensions_mut().insert(deadline.clone());
        let response = self.inner.call(req);
        Box::pin(async move {
            tokio::pin!(response);
            loop {
                let at = deadline.at();
                tokio::select! {
                    biased;
                    r = &mut response => return r,
                    () = deadline.0.moved.notified() => {}
                    () = tokio::time::sleep_until(at) => {
                        if deadline.at() <= at {
                            let mut timed_out = Response::new(ResBody::default());
                            *timed_out.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                            return Ok(timed_out);
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    use super::*;

    async fn status(app: &Router, req: Request<Body>) -> StatusCode {
        app.clone().oneshot(req).await.unwrap().status()
    }

    fn sleeping(d: Duration) -> axum::routing::MethodRouter {
        get(move || tokio::time::sleep(d))
    }

    #[tokio::test]
    async fn slow_handlers_and_large_bodies_are_refused() {
        let limits = Limits {
            request_timeout: Duration::from_millis(50),
            body_bytes: 8,
        };
        let app = limits.apply(
            Router::new()
                .route("/slow", sleeping(Duration::from_secs(5)))
                .route("/echo", post(|body: String| async move { body })),
        );
        let slow = Request::get("/slow").body(Body::empty()).unwrap();
        assert_eq!(status(&app, slow).await, StatusCode::SERVICE_UNAVAILABLE);
        let send = |body: &'static str| Request::post("/echo").body(Body::from(body)).unwrap();
        assert_eq!(status(&app, send("12345678")).await, StatusCode::OK);
        assert_eq!(
            status(&app, send("123456789")).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn a_routes_own_bounds_win_over_the_routers() {
        let router = Limits {
            request_timeout: Duration::from_millis(50),
            body_bytes: 8,
        };
        let generous = Limits {
            request_timeout: Duration::from_secs(5),
            body_bytes: 64,
        };
        let strict = Limits {
            request_timeout: Duration::from_millis(50),
            ..Limits::default()
        };
        let app = router.apply(
            Router::new()
                .route("/fast", sleeping(Duration::from_millis(300)))
                .route(
                    "/batch",
                    sleeping(Duration::from_millis(300)).layer(generous),
                )
                .merge(
                    Router::new()
                        .route("/upload", post(|body: String| async move { body }))
                        .route_layer(generous),
                )
                .route("/quick", sleeping(Duration::from_secs(5)).layer(strict)),
        );
        let get = |uri| Request::get(uri).body(Body::empty()).unwrap();
        // The router's 50 ms stand for a route without its own.
        assert_eq!(
            status(&app, get("/fast")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        // A longer one of its own outlasts the router's.
        assert_eq!(status(&app, get("/batch")).await, StatusCode::OK);
        // So does a larger body limit, from `route_layer` before `apply`.
        let body = Request::post("/upload")
            .body(Body::from("x".repeat(64)))
            .unwrap();
        assert_eq!(status(&app, body).await, StatusCode::OK);
        // A shorter one fires on time, not at the outer deadline.
        let router = Limits {
            request_timeout: Duration::from_secs(10),
            ..Limits::default()
        };
        let app = router.apply(app);
        let started = std::time::Instant::now();
        assert_eq!(
            status(&app, get("/quick")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_route_layer_alone_bounds_its_route() {
        let app = Router::new()
            .route("/slow", sleeping(Duration::from_secs(5)))
            .route_layer(Limits {
                request_timeout: Duration::from_millis(50),
                ..Limits::default()
            });
        let slow = Request::get("/slow").body(Body::empty()).unwrap();
        assert_eq!(status(&app, slow).await, StatusCode::SERVICE_UNAVAILABLE);
    }
}
