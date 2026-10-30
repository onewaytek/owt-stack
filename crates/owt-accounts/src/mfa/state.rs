//! What the session remembers about a second factor: a sign-in waiting for one, and
//! when the person last proved who they are.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use owt_web::session::Session;
use serde::{Deserialize, Serialize};

use crate::session::{Signature, Signed};
use crate::store::Account;

/// What a sign-in is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// The password (or another first factor) was checked and the account has a second
    /// factor: it must be answered before the session is signed in.
    #[serde(rename = "c")]
    Challenge,
    /// The password was checked, the policy requires a second factor and the account
    /// has none: it must enroll one before the session is signed in.
    #[serde(rename = "n")]
    Enroll,
    /// A signed-in session proving itself again (step-up): the password was checked,
    /// and the account's second factor must be answered.
    #[serde(rename = "r")]
    Reauth,
}

/// A sign-in or re-authentication part way through. It is not a [`Signature`]: nothing
/// that reads the session as signed in (the [`Signed`](crate::Signed) extractor,
/// [`Maybe`](crate::Maybe)) sees it, so it opens no page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The account whose password was checked.
    #[serde(rename = "a")]
    pub account: i64,
    /// Its `session_epoch` then; a change since ends the pending sign-in.
    #[serde(rename = "e")]
    pub epoch: i32,
    /// When, in Unix seconds.
    #[serde(rename = "t")]
    pub at: u64,
    /// What it waits for.
    #[serde(rename = "k")]
    pub kind: Kind,
}

/// When the session's account last proved who they are, in Unix seconds, tied to the
/// signature it was recorded for: a record for another account, or an earlier epoch,
/// counts for nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// The account.
    #[serde(rename = "a")]
    pub account: i64,
    /// Its `session_epoch`.
    #[serde(rename = "e")]
    pub epoch: i32,
    /// The last password, link or provider sign-in, or second factor.
    #[serde(rename = "t")]
    pub at: u64,
    /// The last second factor, if one was ever used in this session.
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    pub mfa_at: Option<u64>,
}

/// The session's second-factor state: [`Data`](crate::session::Data) carries it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// A sign-in waiting for a second factor.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// When the signed-in account last proved itself.
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
}

impl State {
    /// Whether it holds nothing (and so is left out of the cookie).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_none() && self.auth.is_none()
    }
}

/// Session data that carries a [`State`]. [`Data`](crate::session::Data) is the
/// ready-made one; an app with its own session type implements this beside
/// [`Signed`], keeping the state's serialized name short and clear of the envelope's
/// `k`, `x` and `i`, and clearing it in [`Signed::on_sign_in`].
pub trait MfaSession: Signed {
    /// The state.
    fn mfa(&self) -> &State;
    /// The state, to change.
    fn mfa_mut(&mut self) -> &mut State;
}

impl MfaSession for crate::session::Data {
    fn mfa(&self) -> &State {
        &self.mfa
    }

    fn mfa_mut(&mut self) -> &mut State {
        &mut self.mfa
    }
}

/// Unix seconds now.
pub(crate) fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The record of the session's last authentication, if it is for the signature the
/// session now holds.
pub(crate) fn auth_for(state: &State, signature: Signature) -> Option<Auth> {
    state
        .auth
        .filter(|a| a.account == signature.account && a.epoch == signature.epoch)
}

/// How far ahead of this replica's clock another's may be before a time recorded by it
/// stops counting as recent.
const CLOCK_SKEW: u64 = 5;

/// Whether `then` (Unix seconds) is no older than `max_age` at `now`. A time further
/// in the future than the clocks of replicas differ by is not recent: a clock moved
/// back must not extend a re-authentication.
pub(crate) fn within(then: u64, max_age: Duration, now: u64) -> bool {
    then <= now.saturating_add(CLOCK_SKEW) && now.saturating_sub(then) <= max_age.as_secs()
}

/// Record that `account` proved who it is at `now`, with a second factor if `mfa`
/// (which keeps an earlier second-factor time when it is not).
pub(crate) fn record<T: MfaSession>(
    session: &Session<T>,
    account: &Account,
    mfa: bool,
    now: SystemTime,
) {
    let at = unix(now);
    session.update(|d| {
        let kept = d
            .mfa()
            .auth
            .filter(|a| a.account == account.id && a.epoch == account.session_epoch)
            .and_then(|a| a.mfa_at);
        d.mfa_mut().auth = Some(Auth {
            account: account.id,
            epoch: account.session_epoch,
            at,
            mfa_at: if mfa { Some(at) } else { kept },
        });
    });
}
