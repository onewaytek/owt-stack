//! What the session cookie carries about the account, and how it is set and
//! revoked.
//!
//! The cookie holds the account's id and the `session_epoch` it was issued under.
//! On every request the epoch is compared with the account's (by [`crate::layer`]):
//! bumping the account's epoch ends every session it has anywhere. That is the
//! whole of revocation; there is no session table.

use owt_web::session::{Session, SessionData, Verdict};
use serde::{Deserialize, Serialize};
use sqlx::PgExecutor;

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
}

/// Session data that holds a signature and nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    /// The account, when signed in.
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub account: Option<i64>,
    /// The epoch the sign-in was under.
    #[serde(rename = "e", default, skip_serializing_if = "is_zero")]
    pub epoch: i32,
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
}

/// Sign the session in as `account`: a new session id (against fixation), the
/// account's id and current epoch. The handler then redirects.
pub fn sign_in<T: Signed>(session: &Session<T>, account: &Account) {
    session.cycle_id();
    session.update(|data| {
        data.set_signature(Some(Signature {
            account: account.id,
            epoch: account.session_epoch,
        }));
    });
}

/// Sign this session out: a new, empty one replaces it. Other sessions of the
/// account stay; see [`sign_out_everywhere`].
pub fn sign_out<T: Signed>(session: &Session<T>) {
    session.flush();
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
/// below, or that reads the signature without loading the account.
pub async fn verdict(db: impl PgExecutor<'_>, signature: Option<Signature>) -> Verdict {
    let Some(signature) = signature else {
        return Verdict::Valid;
    };
    match store::by_id_in_epoch(db, signature.account, signature.epoch).await {
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
