//! Step-up: refusing a sensitive action unless the person proved who they are lately.

use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use owt_web::Error;
use owt_web::session::Session;

use super::state::{self, MfaSession};
use crate::layer::{self, EnrollAt, HasFactor, Maybe, ReauthAt};
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
    let next = layer::asked_for(&parts.extensions, &parts.uri);
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
