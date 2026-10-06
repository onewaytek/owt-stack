//! Server-sent events as raw frames.
//!
//! `axum::response::Sse` suits a stream of typed events. These helpers suit a stream
//! that forwards text already rendered once and shared between listeners (an htmx
//! fragment full of `hx-swap-oob` elements): framing is a string operation and the
//! body is any byte stream.

use axum::body::Body;
use axum::http::{HeaderValue, header};
use axum::response::Response;

/// A named heartbeat event. Send one in place of silence so a page can tell a quiet
/// stream from a dead one: a pod killed outright can leave the stream open through a
/// router, and silent, for as long as the route's timeout. Named because
/// `EventSource` hides comment frames from scripts.
pub const HEARTBEAT: &str = "event: heartbeat\ndata: {}\n\n";

/// An unnamed event: `data: ` on every line, a blank line to end it.
#[must_use]
pub fn frame(data: &str) -> String {
    let mut out = String::with_capacity(data.len() + 16);
    let mut any = false;
    for line in data.lines() {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
        any = true;
    }
    if !any {
        out.push_str("data: \n");
    }
    out.push('\n');
    out
}

/// An event stream response: never cached, never buffered by a proxy.
pub fn response(body: Body) -> Response {
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}

#[cfg(test)]
mod tests {
    #[test]
    fn frames() {
        assert_eq!(super::frame("a\nb"), "data: a\ndata: b\n\n");
        assert_eq!(super::frame(""), "data: \n\n");
    }
}
