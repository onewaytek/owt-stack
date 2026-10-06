//! The error every handler returns, and its HTTP mapping.
//!
//! Messages in the client-facing variants are shown to the person, so write them for
//! a person. Database and internal errors are logged with full fidelity and never
//! leaked: the client sees a bare 500.
//!
//! Site error pages are an app's business. A 404 or 500 built here carries the
//! [`ErrorPage`] marker extension; [`error_pages`] swaps the body of a marked response
//! for whatever the app renders, so a handler never needs the template engine to fail.

use std::borrow::Cow;

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};

/// `Result` with [`Error`] as the default error.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Handler-level error taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 404.
    #[error("not found")]
    NotFound,
    /// 401: who you are is unknown, and this needs it.
    #[error("{0}")]
    Unauthorized(Cow<'static, str>),
    /// 403: who you are is known, and may not do this.
    #[error("{0}")]
    Forbidden(Cow<'static, str>),
    /// 400: the request is malformed.
    #[error("{0}")]
    BadRequest(Cow<'static, str>),
    /// 422: the request is well formed and its content is refused.
    #[error("{0}")]
    Unprocessable(Cow<'static, str>),
    /// 303 to this location: sign-in walls and the like.
    #[error("redirect to {0}")]
    Redirect(String),
    /// A database error; `RowNotFound` maps to 404, anything else to 500.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// 500.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl Error {
    /// 403 with the conventional body.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::Forbidden(Cow::Borrowed("Forbidden"))
    }

    /// 400 with `msg`.
    pub fn bad_request(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// 422 with `msg`.
    pub fn unprocessable(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Unprocessable(msg.into())
    }

    /// 303 to `login` with `?next=<next>`. The sign-in handler must pass what comes
    /// back through [`crate::redirect::local`] before redirecting to it.
    #[must_use]
    pub fn login_required(login: &str, next: &str) -> Self {
        let mut url = String::from(login);
        url.push(if login.contains('?') { '&' } else { '?' });
        url.push_str("next=");
        url.extend(url::form_urlencoded::byte_serialize(next.as_bytes()));
        Self::Redirect(url)
    }

    /// The status this error answers with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotFound | Self::Db(sqlx::Error::RowNotFound) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Redirect(_) => StatusCode::SEE_OTHER,
            Self::Db(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Marker on a response whose body the app's error page should replace.
#[derive(Clone, Copy, Debug)]
pub struct ErrorPage;

fn marked(status: StatusCode, body: &'static str) -> Response {
    let mut r = (status, plain(body)).into_response();
    r.extensions_mut().insert(ErrorPage);
    r
}

fn plain<B>(body: B) -> ([(header::HeaderName, &'static str); 1], B) {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        match self {
            Self::NotFound | Self::Db(sqlx::Error::RowNotFound) => marked(status, "Not found"),
            Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::BadRequest(m)
            | Self::Unprocessable(m) => (status, plain(m.into_owned())).into_response(),
            Self::Redirect(to) => Redirect::to(&to).into_response(),
            Self::Db(e) => {
                tracing::error!(error = ?e, "database error");
                marked(status, "Server error")
            }
            Self::Internal(e) => {
                tracing::error!(error = ?e, "request failed");
                marked(status, "Server error")
            }
        }
    }
}

/// Middleware body: replace a marked response's body with `page(status)`, if the app
/// draws one for that status. Wire it with `from_fn` and a closure:
///
/// ```ignore
/// .layer(from_fn(move |req, next| error_pages(req, next, draw)))
/// ```
pub async fn error_pages<F>(req: Request, next: Next, page: F) -> Response
where
    F: FnOnce(StatusCode) -> Option<Html<String>>,
{
    let resp = next.run(req).await;
    if resp.extensions().get::<ErrorPage>().is_none() {
        return resp;
    }
    let status = resp.status();
    match page(status) {
        Some(html) => (status, html).into_response(),
        None => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses() {
        assert_eq!(Error::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            Error::Db(sqlx::Error::RowNotFound).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            Error::Db(sqlx::Error::PoolTimedOut).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            Error::unprocessable("x").status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn only_404_and_500_are_marked_for_pages() {
        let marked = |e: Error| e.into_response().extensions().get::<ErrorPage>().is_some();
        assert!(marked(Error::NotFound));
        assert!(marked(Error::Internal(anyhow::anyhow!("x"))));
        assert!(!marked(Error::forbidden()));
        assert!(!marked(Error::bad_request("no")));
    }

    #[test]
    fn login_required_carries_next() {
        let Error::Redirect(to) = Error::login_required("/accounts/login/", "/games/?a=1&b=2")
        else {
            panic!()
        };
        assert_eq!(to, "/accounts/login/?next=%2Fgames%2F%3Fa%3D1%26b%3D2");
    }
}
