//! The HTTP layer the onewaytek apps share.
//!
//! Server-rendered Axum: handlers return Askama pages, htmx requests get fragments,
//! and nothing here assumes a particular domain. Each module is independent; an app
//! takes the layers it wants and composes them in its own router.
//!
//! | module | what it gives an app |
//! |---|---|
//! | [`error`] | one handler error type and its HTTP mapping; error pages by marker |
//! | [`csrf`] | tokenless cross-origin protection (`Sec-Fetch-Site`, then `Origin`) |
//! | [`session`] | typed sessions sealed in an encrypted cookie; no server-side store |
//! | [`assets`] | content-fingerprinted static URLs with an `immutable` cache policy |
//! | [`headers`] | security headers, a nonce-based content security policy, private-by-default caching, `noindex` |
//! | [`redirect`] | `?next=` targets that stay on this site |
//! | [`client_ip`] | the client's address behind proxies, by configuration |
//! | [`limits`] | a response deadline and a request body cap |
//! | [`htmx`] | `axum-htmx`'s extractors and responders, re-exported |
//! | [`sse`] | event framing and the stream response |
//! | [`pager`], [`text`] | page arithmetic; slugs, word truncation, paragraphs |

pub mod assets;
pub mod client_ip;
pub mod csrf;
pub mod error;
pub mod headers;
pub mod limits;
pub mod pager;
pub mod redirect;
pub mod session;
pub mod sse;
pub mod text;

pub use error::{Error, ErrorPage, Result};

/// htmx request extractors and response headers (`HX-Request`, `HX-Push-Url`, ...).
pub mod htmx {
    pub use axum_htmx::*;
}

use askama::Template;
use axum::response::Html;

/// Render a compiled template as an HTML body; a failure is an [`Error::Internal`].
pub fn render(t: &impl Template) -> Result<Html<String>> {
    t.render().map(Html).map_err(|e| {
        Error::Internal(anyhow::anyhow!(
            "rendering {}: {e}",
            std::any::type_name_of_val(t)
        ))
    })
}

/// `GET /healthz`: the process answers. Readiness that needs the database belongs to
/// the app, which knows which of its dependencies it cannot serve without.
#[expect(clippy::unused_async, reason = "an axum handler")]
pub async fn healthz() -> &'static str {
    "ok"
}
