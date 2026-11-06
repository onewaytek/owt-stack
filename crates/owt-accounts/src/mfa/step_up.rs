//! Step-up: refusing a sensitive action unless the person proved who they are lately.

use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use owt_web::Error;
use owt_web::session::Session;

use super::state::{self, MfaSession};
use crate::layer::{self, EnrollAt, HasFactor, Maybe, ReauthAt};
use crate::roles::Role;
use crate::session::Data;

/// Why the session must prove who it is again. The app answers it with its
/// re-authentication page (`?next=` the action), where [`Mfa::begin_reauth`] and
/// [`Mfa::challenge`] renew the proof. A variant may be added without a breaking release,
/// so a `match` on it ends with a `_` arm.
///
/// [`Mfa::begin_reauth`]: super::Mfa::begin_reauth
/// [`Mfa::challenge`]: super::Mfa::challenge
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepUp {
    /// The session is not signed in.
    #[error("Sign in to continue.")]
    NotSignedIn,
    /// The session holds no record of when the person proved who they are: it was
    /// signed in by a way that records none, or before records were kept.
    #[error("Confirm it is you to continue.")]
    Unrecorded,
    /// The last proof is older than the action allows.
    #[error("Confirm it is you to continue.")]
    Stale {
        /// How long ago, in seconds.
        age: u64,
        /// What the action allows, in seconds.
        max_age: u64,
    },
    /// The action needs a second factor and the session has not used one lately (or
    /// ever). Re-authenticate with the factor the account has.
    #[error("Confirm it is you with your second factor to continue.")]
    SecondFactor,
    /// The action needs a second factor and the account has none: send the person to
    /// enrollment ([`Accounts::enroll_at`](crate::Accounts::enroll_at)), not to
    /// re-authentication, which cannot help.
    #[error("Set up a second factor to continue.")]
    NoSecondFactor,
}

fn check<T: MfaSession>(
    session: &Session<T>,
    max_age: Duration,
    now: SystemTime,
    second_factor: bool,
    has_factor: Option<bool>,
) -> Result<(), StepUp> {
    let now = state::unix(now);
    let (signature, mfa) = session.read(|d| (d.signature(), *d.mfa()));
    let signature = signature.ok_or(StepUp::NotSignedIn)?;
    let auth = state::auth_for(&mfa, signature).ok_or(StepUp::Unrecorded)?;
    let then = if second_factor {
        match (auth.mfa_at, has_factor) {
            (Some(at), _) => at,
            (None, Some(false)) => return Err(StepUp::NoSecondFactor),
            (None, _) => return Err(StepUp::SecondFactor),
        }
    } else {
        auth.at
    };
    if state::within(then, max_age, now) {
        Ok(())
    } else if second_factor {
        Err(StepUp::SecondFactor)
    } else {
        Err(StepUp::Stale {
            age: now.saturating_sub(then),
            max_age: max_age.as_secs(),
        })
    }
}

/// Whether the session's account proved who it is (a password, a link, a provider or a
/// second factor) within `max_age`.
///
/// # Errors
/// A [`StepUp`] saying why not: answer it with the re-authentication page.
pub fn require_recent<T: MfaSession>(
    session: &Session<T>,
    max_age: Duration,
) -> Result<(), StepUp> {
    check(session, max_age, SystemTime::now(), false, None)
}

/// Whether the session's account used a **second factor** within `max_age`: for what
/// must not be done on a password alone, such as changing the factors. Only for an
/// account that has one (or a policy that requires it): an account without a second
/// factor never satisfies it, and the answer is [`StepUp::SecondFactor`], which
/// [`Mfa::begin_reauth`](super::Mfa::begin_reauth) cannot clear.
///
/// # Errors
/// A [`StepUp`] saying why not.
pub fn require_recent_mfa<T: MfaSession>(
    session: &Session<T>,
    max_age: Duration,
) -> Result<(), StepUp> {
    check(session, max_age, SystemTime::now(), true, None)
}

/// [`require_recent_mfa`] for a caller that knows whether the account has a factor
/// ([`Mfa::factors`](super::Mfa::factors)): without one the answer is
/// [`StepUp::NoSecondFactor`].
///
/// # Errors
/// A [`StepUp`] saying why not.
pub fn require_recent_mfa_for<T: MfaSession>(
    session: &Session<T>,
    max_age: Duration,
    has_factor: bool,
) -> Result<(), StepUp> {
    check(session, max_age, SystemTime::now(), true, Some(has_factor))
}

/// [`require_recent`] as of `now`, for an app with a clock of its own and for tests.
///
/// # Errors
/// A [`StepUp`] saying why not.
pub fn require_recent_at<T: MfaSession>(
    session: &Session<T>,
    max_age: Duration,
    now: SystemTime,
) -> Result<(), StepUp> {
    check(session, max_age, now, false, None)
}

impl From<StepUp> for Error {
    /// 403: an app that maps the error itself redirects to its page instead.
    fn from(e: StepUp) -> Self {
        Self::Forbidden(e.to_string().into())
    }
}

/// A guard for a handler: the signed-in account proved who it is within `SECS`
/// seconds, or the visitor is sent to the re-authentication page
/// ([`Accounts::reauth_at`](crate::Accounts::reauth_at)) with `?next=` naming this
/// request. Anonymous visitors meet the sign-in wall as [`Signed`](crate::Signed)'s.
///
/// `Recent<900>` for a quarter of an hour. `T` is the session data type
/// ([`Data`] unless the app has its own). Name it beside [`Signed`](crate::Signed):
/// it checks the session, not the account.
#[derive(Clone, Copy, Debug)]
pub struct Recent<const SECS: u64, T = Data>(PhantomData<fn() -> T>);

/// [`Recent`], for a second factor used within `SECS` seconds ([`require_recent_mfa`]).
/// Only the app's own second factor (a TOTP code or a recovery code) counts: a password,
/// a link or a provider's sign-in never does, whatever the provider checked.
#[derive(Clone, Copy, Debug)]
pub struct RecentMfa<const SECS: u64, T = Data>(PhantomData<fn() -> T>);

fn guard<T: MfaSession>(parts: &Parts, secs: u64, second_factor: bool) -> Result<(), Error> {
    let next = layer::asked_for(&parts.extensions, &parts.uri);
    guard_to::<T>(parts, secs, second_factor, next)
}

/// [`guard`], sending the visitor back to `next` once the proof is renewed: a `POST`
/// names the page its form is on, which a redirect can `GET`.
pub(crate) fn guard_to<T: MfaSession>(
    parts: &Parts,
    secs: u64,
    second_factor: bool,
    next: &str,
) -> Result<(), Error> {
    if Maybe::of(&parts.extensions).0.is_none() {
        return Err(layer::wall(parts));
    }
    let session = parts.extensions.get::<Session<T>>().ok_or_else(|| {
        Error::Internal(anyhow::anyhow!(
            "Recent needs the session layer of its data type"
        ))
    })?;
    // Known only under `Accounts::require_mfa`, which reads it for every request.
    let has_factor = parts.extensions.get::<HasFactor>().map(|h| h.0);
    let Err(why) = check(
        session,
        Duration::from_secs(secs),
        SystemTime::now(),
        second_factor,
        has_factor,
    ) else {
        return Ok(());
    };
    let at = if why == StepUp::NoSecondFactor {
        parts
            .extensions
            .get::<EnrollAt>()
            .map_or("/mfa/enroll", |r| r.0.as_str())
    } else {
        parts
            .extensions
            .get::<ReauthAt>()
            .map_or("/reauth", |r| r.0.as_str())
    };
    // The same redirect as the sign-in wall's, to the other page.
    Err(Error::login_required(at, next))
}

#[allow(clippy::unused_async_trait_impl)] // the trait is async
impl<S: Send + Sync, const SECS: u64, T: MfaSession> FromRequestParts<S> for Recent<SECS, T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        guard::<T>(parts, SECS, false).map(|()| Self(PhantomData))
    }
}

#[allow(clippy::unused_async_trait_impl)] // the trait is async
impl<S: Send + Sync, const SECS: u64, T: MfaSession> FromRequestParts<S> for RecentMfa<SECS, T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        guard::<T>(parts, SECS, true).map(|()| Self(PhantomData))
    }
}

/// Who a [`StepUpGate`] lets through to the step-up check.
#[derive(Clone, Copy, Debug)]
enum Who {
    Signed,
    Staff,
    Role(Role),
}

/// Step-up for a whole group of routes, as a middleware: every change (any method but
/// `GET`, `HEAD`, `OPTIONS` and `TRACE`) needs a proof of who the person is within the
/// gate's window, and the rest pass. Where [`Recent`] and [`RecentMfa`] guard one
/// handler each, the gate guards everything under it, so a route added later is
/// covered without anyone remembering to.
///
/// In order, for a request the gate checks:
/// 1. who: a signed-in account ([`Signed`](crate::Signed)'s wall otherwise), or with
///    [`StepUpGate::staff`] or [`StepUpGate::role`] the right one (403 otherwise);
/// 2. the proof: as [`Recent`], or as [`RecentMfa`] with
///    [`StepUpGate::second_factor`]. Without it the visitor is sent to the
///    re-authentication page (or enrollment, for an account without a factor), with
///    `?next=` naming the page to come back to.
///
/// A redirect cannot repeat a `POST`, so `?next=` names the page the change was sent
/// from: `HX-Current-URL` for an htmx request, else the `Referer`, both only when they
/// are this site's ([`owt_web::redirect::htmx_current_page`],
/// [`owt_web::redirect::referer_page`]), else the request's own path. The person
/// re-authenticates, lands back on the form and sends it again.
///
/// An htmx request (not a boosted one) would follow a 303 inside its request and swap
/// the re-authentication page into a fragment, so it gets a 204 with `HX-Redirect`
/// instead, which loads the page whole. The sign-in wall is left to
/// [`Accounts::load`](crate::Accounts::load), which does the same for it.
///
/// `T` is the session data type ([`Data`] unless the app has its own,
/// [`StepUpGate::with_session`]); name it at the layer:
///
/// ```
/// # use std::time::Duration;
/// # use axum::{Router, routing::post, middleware::from_fn_with_state};
/// use owt_accounts::mfa::StepUpGate;
/// use owt_accounts::session::Data;
///
/// let gate = StepUpGate::new(Duration::from_secs(300)).staff().second_factor();
/// let staff: Router = Router::new()
///     .route("/staff/refunds", post(|| async { "refunded" }))
///     .layer(from_fn_with_state(gate, StepUpGate::<Data>::guard));
/// ```
#[derive(Debug)]
pub struct StepUpGate<T = Data> {
    window: Duration,
    who: Who,
    second_factor: bool,
    reads: bool,
    data: PhantomData<fn() -> T>,
}

impl<T> Clone for StepUpGate<T> {
    fn clone(&self) -> Self {
        Self {
            window: self.window,
            who: self.who,
            second_factor: self.second_factor,
            reads: self.reads,
            data: PhantomData,
        }
    }
}

impl StepUpGate {
    /// Changes need a proof (a password, a link, a provider or a second factor) within
    /// `window`, from any signed-in account.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            who: Who::Signed,
            second_factor: false,
            reads: false,
            data: PhantomData,
        }
    }
}

impl<T: MfaSession> StepUpGate<T> {
    /// The same gate for an app whose session data type is `U`.
    #[must_use]
    pub fn with_session<U: MfaSession>(self) -> StepUpGate<U> {
        StepUpGate {
            window: self.window,
            who: self.who,
            second_factor: self.second_factor,
            reads: self.reads,
            data: PhantomData,
        }
    }

    /// Only staff pass; anyone else signed in gets a 403 before any re-authentication,
    /// as with [`Staff`](crate::Staff).
    #[must_use]
    pub fn staff(mut self) -> Self {
        self.who = Who::Staff;
        self
    }

    /// Only holders of `role` pass (staff too, for a role
    /// [`held_by_staff`](Role::held_by_staff)); anyone else signed in gets a 403, as
    /// with [`Holds`](crate::roles::Holds).
    #[must_use]
    pub fn role(mut self, role: Role) -> Self {
        self.who = Who::Role(role);
        self
    }

    /// The proof must be a second factor, as [`RecentMfa`]'s.
    #[must_use]
    pub fn second_factor(mut self) -> Self {
        self.second_factor = true;
        self
    }

    /// Reads (`GET`, `HEAD`) need the proof too, and the who check: for pages whose
    /// content is itself sensitive. `?next=` is then the page asked for.
    #[must_use]
    pub fn reads(mut self) -> Self {
        self.reads = true;
        self
    }

    /// The middleware: `.layer(from_fn_with_state(gate, StepUpGate::<Data>::guard))`,
    /// inside [`Accounts::load`](crate::Accounts::load) (added before it, so it runs
    /// after it).
    pub async fn guard(State(gate): State<Self>, request: Request, next: Next) -> Response {
        if request.method().is_safe() && !gate.reads {
            return next.run(request).await;
        }
        let (parts, body) = request.into_parts();
        if let Some(refused) = gate.refusal(&parts) {
            return refused;
        }
        next.run(Request::from_parts(parts, body)).await
    }

    /// The response that refuses the request, or `None` to let it through.
    fn refusal(&self, parts: &Parts) -> Option<Response> {
        // Who first: anyone else meets the sign-in wall or a 403, not re-authentication.
        let Some(account) = Maybe::of(&parts.extensions).0 else {
            return Some(layer::wall(parts).into_response());
        };
        let allowed = match self.who {
            Who::Signed => true,
            Who::Staff => account.is_staff,
            Who::Role(role) => account.holds(&role),
        };
        if !allowed {
            let why = match self.who {
                Who::Role(role) => format!("This needs the {} role.", role.label),
                _ => "Only staff can do this.".to_owned(),
            };
            return Some(Error::Forbidden(why.into()).into_response());
        }
        let htmx = flag(&parts.headers, "hx-request");
        let back = if parts.method.is_safe() {
            None
        } else if htmx {
            owt_web::redirect::htmx_current_page(&parts.headers)
                .or_else(|| owt_web::redirect::referer_page(&parts.headers))
        } else {
            owt_web::redirect::referer_page(&parts.headers)
        };
        let next = back.as_deref().unwrap_or_else(|| {
            let asked = layer::asked_for(&parts.extensions, &parts.uri);
            // The path alone for a change: its query is the form's, not a page's.
            if parts.method.is_safe() {
                asked
            } else {
                asked.split_once('?').map_or(asked, |(path, _)| path)
            }
        });
        match guard_to::<T>(parts, self.window.as_secs(), self.second_factor, next) {
            Ok(()) => None,
            Err(Error::Redirect(to)) if htmx && !flag(&parts.headers, "hx-boosted") => {
                Some(hx_redirect(&to))
            }
            Err(e) => Some(e.into_response()),
        }
    }
}

fn flag(headers: &HeaderMap, name: &str) -> bool {
    headers.get(name).is_some_and(|v| v.as_bytes() == b"true")
}

/// A 204 that has htmx load `to` as a whole page.
fn hx_redirect(to: &str) -> Response {
    let Ok(value) = HeaderValue::from_str(to) else {
        return Error::Redirect(to.to_owned()).into_response();
    };
    (
        StatusCode::NO_CONTENT,
        [
            (HeaderName::from_static("hx-redirect"), value),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}
