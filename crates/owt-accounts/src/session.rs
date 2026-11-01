//! What the session cookie carries about the account, and how it is set and
//! revoked.
//!
//! The cookie holds the account's id and the `session_epoch` it was issued under.
//! On every request the epoch is compared with the account's (by [`crate::layer`]):
//! bumping the account's epoch ends every session it has anywhere. [`sign_out`] ends
//! one session: its id goes into `revoked_sessions`, which the same read checks by
//! primary key, so a kept copy of its cookie opens nothing.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::StatusCode;
use owt_auth::throttle::Throttle;
use owt_web::flash::{Flash, HasFlashes};
use owt_web::session::{Session, SessionData, Verdict};
use serde::{Deserialize, Serialize};
use sqlx::{PgExecutor, PgPool};

use crate::store::{self, Account};

/// Who a session is signed in as, and under which epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The account's id.
    pub account: i64,
    /// The account's `session_epoch` when it signed in.
    pub epoch: i32,
}

/// Session data that carries a [`Signature`]. [`Data`] is the ready-made one; an
/// app with more in its session implements this on its own type, keeping the two
/// serialized names short (they ride on every request) and clear of the envelope's
/// `k`, `x` and `i`.
pub trait Signed: SessionData {
    /// Who is signed in, if anyone.
    fn signature(&self) -> Option<Signature>;
    /// Sign in as `signature`, or out with `None`.
    fn set_signature(&mut self, signature: Option<Signature>);
    /// Called by [`sign_in`] before it sets the signature: forget what the session
    /// remembered about an earlier sign-in (when it happened, which factor, a second
    /// factor still pending), so none of it carries over to the new one. [`Data`]
    /// clears its [`mfa::State`](crate::mfa::State). The default does nothing.
    fn on_sign_in(&mut self) {}
}

/// Session data that holds a signature and the flash messages for the next page
/// ([`HasFlashes`]): the session type of an app that keeps nothing else in its
/// session. Build one with `..Data::default()`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    /// The account, when signed in.
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub account: Option<i64>,
    /// The epoch the sign-in was under.
    #[serde(rename = "e", default, skip_serializing_if = "is_zero")]
    pub epoch: i32,
    /// The messages for the next page ([`Session::flash`]).
    #[serde(rename = "f", default, skip_serializing_if = "Vec::is_empty")]
    pub flashes: Vec<Flash>,
    /// A second factor pending, and when the person last proved who they are
    /// ([`crate::mfa`]).
    #[serde(
        rename = "m",
        default,
        skip_serializing_if = "crate::mfa::State::is_empty"
    )]
    pub mfa: crate::mfa::State,
}

impl HasFlashes for Data {
    fn flashes(&self) -> &[Flash] {
        &self.flashes
    }

    fn flashes_mut(&mut self) -> &mut Vec<Flash> {
        &mut self.flashes
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's signature
fn is_zero(n: &i32) -> bool {
    *n == 0
}

impl Signed for Data {
    fn signature(&self) -> Option<Signature> {
        self.account.map(|account| Signature {
            account,
            epoch: self.epoch,
        })
    }

    fn set_signature(&mut self, signature: Option<Signature>) {
        if let Some(s) = signature {
            self.account = Some(s.account);
            self.epoch = s.epoch;
        } else {
            self.account = None;
            self.epoch = 0;
        }
    }

    fn on_sign_in(&mut self) {
        self.mfa = crate::mfa::State::default();
    }
}

/// Sign the session in as `account`: a new session id (against fixation), the
/// account's id and current epoch. The handler then redirects.
///
/// This records nothing about *how* the person proved who they are: a session signed in
/// by it has no [`mfa::State`](crate::mfa::State) times, and [`crate::mfa::require_recent`]
/// refuses it until [`crate::mfa::mark_authenticated`] stamps them. The way in that checks
/// a password and a second factor is [`crate::mfa::Mfa::password_sign_in`].
pub fn sign_in<T: Signed>(session: &Session<T>, account: &Account) {
    session.cycle_id();
    session.update(|data| {
        data.on_sign_in();
        data.set_signature(Some(Signature {
            account: account.id,
            epoch: account.session_epoch,
        }));
    });
}

/// Why [`password_sign_in`] signed nobody in. A variant may be added without a
/// breaking release, so a `match` on it ends with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignInRefused {
    /// A budget of the throttle is spent: the password was not checked.
    #[error("Too many attempts. Wait a minute and try again.")]
    Throttled,
    /// No active account that signs in with a password has that name and password.
    /// It does not say which was wrong, nor whether the account exists.
    #[error("That username or email and password do not match an account.")]
    Mismatch,
    /// The shared throttle could not be reached and fails closed (see
    /// [`owt_auth::throttle::shared`]): nothing was checked. Answer 503.
    #[error("Signing in is unavailable for a moment. Please try again shortly.")]
    Unavailable,
    /// A fault: the database. Its message says only that; log its source, which
    /// may name tables and columns, and never show it.
    #[error("The sign-in could not be checked. Try again in a moment.")]
    Fault(#[from] crate::Error),
}

impl SignInRefused {
    /// How long a throttled sign-in waits at most before a budget has room again: the
    /// budgets are per minute. For a `Retry-After` header.
    pub const RETRY_AFTER: Duration = Duration::from_secs(60);

    /// The status the sign-in form answers with: 429 throttled, 422 a mismatch, 500
    /// a fault.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::Mismatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Fault(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// The whole password sign-in: charge `throttle` for a sign-in to `login` from `ip`
/// (the client's address, [`owt_web::client_ip`]), check the password only if it
/// allows one ([`store::authenticate`], which stamps the account's `last_sign_in` at the
/// password, before any second factor: [`crate::mfa::Mfa::password_sign_in`] stamps it
/// after, and the layer holds a session that skipped the factor),
/// and sign `session` in ([`sign_in`]). `login` is a username or an email. The
/// handler then redirects, or shows the form again with the refusal's message and
/// [`SignInRefused::status`].
///
/// # Errors
///
/// [`SignInRefused`]: throttled, a mismatch (a `login` with a control character
/// inside it, after trimming, included: it is refused before the throttle is charged), or a fault.
pub async fn password_sign_in<T: Signed>(
    pool: &PgPool,
    throttle: &Throttle,
    session: &Session<T>,
    ip: IpAddr,
    login: &str,
    password: &str,
) -> Result<Account, SignInRefused> {
    // No username or email has a control character, so none can match; refused before
    // the throttle is charged, so a login cannot spell the key of another budget
    // (the gate's, in `password_gate`). Trimmed first, as the key and the lookup are:
    // a pasted `ada\n` still signs in.
    if login.trim().chars().any(char::is_control) {
        return Err(SignInRefused::Mismatch);
    }
    if !throttle.sign_in(ip, login) {
        return Err(SignInRefused::Throttled);
    }
    let account = store::authenticate(pool, login, password)
        .await?
        .ok_or(SignInRefused::Mismatch)?;
    sign_in(session, &account);
    Ok(account)
}

/// The deployment-wide password a gate checks against, and the account it opens.
#[derive(Clone, Copy, Debug)]
pub struct Gate<'a> {
    /// The expected password's Argon2 hash (an environment variable, say), as
    /// `owt_auth::password::hash` writes it. Not what was typed.
    pub hash: &'a str,
    /// The id of the account a match signs in: active, and it needs no password of
    /// its own (password sign-in may be off).
    pub account: i64,
}

/// The password gate: one password for the whole deployment, checked against `gate`'s
/// hash, opening the fixed account it names.
///
/// It is [`password_sign_in`] with the stored hash given rather than looked up.
/// `throttle` is charged for a sign-in to this account from `ip` (the same budgets
/// as for a login, under a key that no login can spell: [`password_sign_in`] refuses
/// control characters), the password gets one full Argon2 check
/// ([`owt_auth::password::verify_or_decoy`]: a hash that is no usable Argon2 string
/// still costs a full check and opens nothing), and a match stamps the account's
/// `last_sign_in` and signs `session` in ([`sign_in`]). The hash is not rehashed: it
/// is not stored here. A deactivated or missing account is a
/// [`SignInRefused::Mismatch`], as a wrong password is.
///
/// **Give the gate a [`Throttle`] of its own**, with a larger `sign_ins_per_account`,
/// and do not use it for ordinary logins (the larger budget would loosen them too).
/// Everyone shares the one account, so its budget is shared by every client: with the
/// default five a minute, a client that fails six times a minute locks the gate for
/// all. The per-address budgets then do the limiting.
///
/// # Errors
///
/// [`SignInRefused`]: throttled, a mismatch, or a fault.
pub async fn password_gate<T: Signed>(
    pool: &PgPool,
    throttle: &Throttle,
    session: &Session<T>,
    ip: IpAddr,
    password: &str,
    gate: Gate<'_>,
) -> Result<Account, SignInRefused> {
    // A NUL that no login through `password_sign_in` carries: the key is the gate's
    // alone there. Code that charges the throttle with strings of its own keeps
    // them clear of it.
    if !throttle.sign_in(ip, &format!("\0gate\0{}", gate.account)) {
        return Err(SignInRefused::Throttled);
    }
    let checked = owt_auth::password::check_or_decoy(password, Some(gate.hash)).await;
    if !checked.matched() {
        return Err(SignInRefused::Mismatch);
    }
    if checked == owt_auth::password::Check::MatchRaw {
        // The hash is the app's, not stored here: it can only be told to make a new one.
        tracing::warn!(
            "the gate's hash was made from the password as typed, before passwords were \
             normalized: make it again with owt_auth::password::hash"
        );
    }
    let account = store::open_active(pool, gate.account)
        .await
        .map_err(crate::Error::from)?
        .ok_or(SignInRefused::Mismatch)?;
    sign_in(session, &account);
    Ok(account)
}

/// Sign this session out: its id is recorded as revoked ([`store::revoke_session`],
/// kept until its cookie would have expired anyway), so a copy of the cookie someone
/// kept opens it no more, and a new, empty session replaces it. Other sessions of the
/// account stay; see [`sign_out_everywhere`].
///
/// # Errors
///
/// The database: the session is still replaced, but a copied cookie still opens it.
pub async fn sign_out<T: Signed>(
    db: impl PgExecutor<'_>,
    session: &Session<T>,
) -> sqlx::Result<()> {
    let revoked = match (session.read(Signed::signature), session.id()) {
        (Some(_), Some(id)) => {
            // Outside the session layer the lifetime is unknown: a month covers any.
            let expires = session.expires().unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
                    .saturating_add(30 * 24 * 3600)
            });
            store::revoke_session(db, &id, expires).await
        }
        _ => Ok(()),
    };
    session.flush();
    revoked
}

/// Sign out here and everywhere else: the account's epoch moves on, so every other
/// session of it ends at its next request, and this one is replaced.
pub async fn sign_out_everywhere<T: Signed>(
    db: impl PgExecutor<'_>,
    session: &Session<T>,
) -> sqlx::Result<()> {
    if let Some(signature) = session.read(Signed::signature) {
        store::sign_out_everywhere(db, signature.account).await?;
    }
    session.flush();
    Ok(())
}

/// Whether a signature still stands, as a [`Verdict`] for
/// [`owt_web::session::Sessions::validate_with`]. [`crate::layer::Accounts`] makes
/// the same check and loads the account in one read, so an app using the layer does
/// not also need this; it is for an app that wants the cookie removed at the layer
/// below, or that reads the signature without loading the account. `session` is the
/// presented session's id ([`owt_web::session::Presented::id`]), checked against the
/// sessions [`sign_out`] revoked.
pub async fn verdict(
    db: impl PgExecutor<'_>,
    signature: Option<Signature>,
    session: Option<&str>,
) -> Verdict {
    let Some(signature) = signature else {
        return Verdict::Valid;
    };
    match store::by_id_in_epoch(db, signature.account, signature.epoch, session).await {
        Ok(Some(_)) => Verdict::Valid,
        Ok(None) => Verdict::Revoked,
        Err(e) => {
            tracing::warn!(error = %e, "the session's account could not be read");
            Verdict::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cookie_carries_two_short_names_when_signed_in_and_none_when_not() {
        let out = serde_json::to_string(&Data::default()).unwrap();
        assert_eq!(out, "{}");
        let mut data = Data::default();
        data.set_signature(Some(Signature {
            account: 7,
            epoch: 3,
        }));
        assert_eq!(serde_json::to_string(&data).unwrap(), r#"{"a":7,"e":3}"#);
        let back: Data = serde_json::from_str(r#"{"a":7,"e":3}"#).unwrap();
        assert_eq!(
            back.signature(),
            Some(Signature {
                account: 7,
                epoch: 3
            })
        );
        let anonymous: Data = serde_json::from_str("{}").unwrap();
        assert_eq!(anonymous.signature(), None);
    }

    #[test]
    fn an_epoch_without_an_account_is_no_signature() {
        let data: Data = serde_json::from_str(r#"{"e":3}"#).unwrap();
        assert_eq!(data.signature(), None);
    }
}
