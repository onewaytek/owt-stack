//! Bounds on what one request may cost.
//!
//! Without them a handler waiting on a stalled dependency holds its connection for as
//! long as the client cares to wait. [`Limits::apply`] bounds the time to a response
//! and the size of a request body.
//!
//! Two things it does not bound. A response *body* may stream for as long as it
//! likes: the timeout ends when the handler returns, so SSE streams and `WebSocket`
//! upgrades are unaffected. And the time a client takes to *send* its request is the
//! proxy's to bound: `axum::serve` sets no header-read timeout, so serve behind one
//! that does (the `OpenShift` router gives a request ten seconds to arrive).

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use tower_http::timeout::TimeoutLayer;

/// The bounds. The defaults suit form posts and rendered pages.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How long a handler has to produce its response; a slower one answers 503.
    pub request_timeout: Duration,
    /// The largest request body an extractor will read; a larger one answers 413. A
    /// route that takes uploads raises it with its own `DefaultBodyLimit`.
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
        router
            .layer(DefaultBodyLimit::max(self.body_bytes))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::SERVICE_UNAVAILABLE,
                self.request_timeout,
            ))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn slow_handlers_and_large_bodies_are_refused() {
        let limits = Limits {
            request_timeout: Duration::from_millis(50),
            body_bytes: 8,
        };
        let app = limits.apply(
            Router::new()
                .route(
                    "/slow",
                    get(|| async { tokio::time::sleep(Duration::from_secs(5)).await }),
                )
                .route("/echo", post(|body: String| async move { body })),
        );
        let slow = app
            .clone()
            .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(slow.status(), StatusCode::SERVICE_UNAVAILABLE);
        let send = |body: &'static str| {
            app.clone()
                .oneshot(Request::post("/echo").body(Body::from(body)).unwrap())
        };
        assert_eq!(send("12345678").await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            send("123456789").await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
