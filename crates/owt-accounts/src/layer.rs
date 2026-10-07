//! The signed-in account, once per request, and the extractors that name it.
//!
//! [`Accounts::load`] runs after the session layer: it reads the session's
//! signature, loads the account if the epoch still matches, and puts the result in
//! the request's extensions. The extractors read it from there, so a handler naming
//! [`Signed`] and a template helper naming [`Maybe`] cost one query between them.
//!
//! A signature whose epoch no longer matches (signed out everywhere, password
//! changed, deactivated) is dropped from the session, so the cookie stops carrying
//! it. A database error leaves the request anonymous and the cookie as it was: an
//! outage must neither admit a revoked session nor sign everyone out.

// The extractors answer from the extensions without awaiting; the trait is async.
#![allow(clippy::unused_async_trait_impl)]

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use owt_web::Error;
use owt_web::session::Session;
use sqlx::PgPool;

use crate::session::Signed as SignedData;
use crate::store::{self, Account};

/// The layer's state: the pool and where the sign-in page is.
#[derive(Clone, Debug)]
pub struct Accounts {
    pool: PgPool,
    sign_in: String,
}

impl Accounts {
    /// Accounts in `pool`; a handler that needs one sends the visitor to `sign_in`
    /// (a path, such as `/login`) with `?next=` set.
    pub fn new(pool: PgPool, sign_in: impl Into<String>) -> Self {
        Self {
            pool,
            sign_in: sign_in.into(),
        }
    }

    /// The middleware. Install it with
    /// `axum::middleware::from_fn_with_state(accounts, Accounts::load::<T>)`, where
    /// `T` is the session data type, *inside* the session layer (so it runs after
    /// it).
    pub async fn load<T: SignedData>(
        State(this): State<Self>,
        mut req: Request,
        next: Next,
    ) -> Response {
        let session = req.extensions().get::<Session<T>>().cloned();
        let account = match session.as_ref().and_then(|s| s.read(SignedData::signature)) {
            None => None,
            Some(signature) => {
                match store::by_id_in_epoch(&this.pool, signature.account, signature.epoch).await {
                    Ok(Some(account)) => Some(account),
                    Ok(None) => {
                        // Revoked: the cookie must stop carrying it.
                        if let Some(session) = &session {
                            session.update(|data| data.set_signature(None));
                        }
                        None
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the session's account could not be read");
                        None
                    }
                }
            }
        };
        req.extensions_mut().insert(Maybe(account));
        req.extensions_mut().insert(SignInAt(this.sign_in.clone()));
        next.run(req).await
    }
}

/// Where the sign-in page is, for the extractors' redirect.
#[derive(Clone, Debug)]
struct SignInAt(String);

/// The signed-in account, if any. Available to anything with the request's
/// extensions (a page-context extractor, say), not only as a handler argument.
#[derive(Clone, Debug, Default)]
pub struct Maybe(pub Option<Account>);

impl Maybe {
    /// The account the request's extensions hold, or none if the layer is not
    /// installed.
    #[must_use]
    pub fn of(extensions: &axum::http::Extensions) -> Self {
        extensions.get::<Self>().cloned().unwrap_or_default()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Maybe {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::of(&parts.extensions))
    }
}

fn wall(parts: &Parts) -> Error {
    let next = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let login = parts
        .extensions
        .get::<SignInAt>()
        .map_or("/login", |s| s.0.as_str());
    Error::login_required(login, next)
}

/// A signed-in account: the handler is walled, and an anonymous visitor is sent to
/// the sign-in page with `?next=` naming this request.
#[derive(Clone, Debug)]
pub struct Signed(pub Account);

impl<S: Send + Sync> FromRequestParts<S> for Signed {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match Maybe::of(&parts.extensions).0 {
            Some(account) => Ok(Self(account)),
            None => Err(wall(parts)),
        }
    }
}

/// A signed-in member of staff. Anyone else signed in gets a 403; an anonymous
/// visitor goes to the sign-in page.
#[derive(Clone, Debug)]
pub struct Staff(pub Account);

impl<S: Send + Sync> FromRequestParts<S> for Staff {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match Maybe::of(&parts.extensions).0 {
            Some(account) if account.is_staff => Ok(Self(account)),
            Some(_) => Err(Error::Forbidden("Only staff can open this page.".into())),
            None => Err(wall(parts)),
        }
    }
}
