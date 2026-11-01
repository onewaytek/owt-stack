//! Answering a pending sign-in with a second factor, and re-authenticating a signed-in
//! session.

use std::net::IpAddr;
use std::time::SystemTime;

use owt_auth::recovery;
use owt_auth::totp;
use owt_web::session::Session;
use sqlx::PgPool;

use super::state::{self, Kind, MfaSession, State};
use super::{Event, EventKind, Factor, Key, LOCK_AFTER, LOCK_FOR, Limiter, Mfa, MfaError, Next};
use crate::session::{self, Signed};
use crate::store::{self, Account};

/// What the person typed for the second factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The authenticator's six digits.
    Totp(&'a str),
    /// A recovery code, as typed (case, hyphens and spaces do not matter).
    Recovery(&'a str),
}

/// How a session stands to an account that is enrolling.
pub(super) enum Entry {
    /// Signed in as the account.
    Signed,
    /// Waiting to enroll.
    Enroll,
}

impl Entry {
    /// The session is signed in as `account`, or holds its unexpired pending enrollment.
    pub(super) fn of<T: MfaSession>(
        session: &Session<T>,
        account: &Account,
        ttl: std::time::Duration,
        now: SystemTime,
    ) -> Option<Self> {
        let (signature, pending) = session.read(|d| (d.signature(), d.mfa().pending));
        if signature.is_some_and(|s| s.account == account.id && s.epoch == account.session_epoch) {
            return Some(Self::Signed);
        }
        pending
            .filter(|p| {
                p.kind == Kind::Enroll
                    && p.account == account.id
                    && p.epoch == account.session_epoch
                    && state::within(p.at, ttl, state::unix(now))
            })
            .map(|_| Self::Enroll)
    }
}

impl Mfa {
    /// Answer the pending sign-in (or re-authentication) with a second factor.
    ///
    /// The attempt is charged to `limiter` first, under a key of the account's, so a
    /// code cannot be guessed; a wrong answer is [`MfaError::Invalid`] and does not say
    /// which part was wrong. A code works once: a TOTP step at or before the last
    /// accepted is refused, and a recovery code is marked used in the same statement
    /// that checks it is unused, so two requests with one code cannot both pass.
    ///
    /// On success a pending sign-in becomes a signed-in session (a new session id; the
    /// time of both factors recorded), and a re-authentication renews the times. The
    /// events say which factor passed, and that a recovery code was used (tell the
    /// owner).
    ///
    /// # Errors
    /// [`MfaError::NoChallenge`] if no pending sign-in is held or it has expired or its
    /// account changed; [`MfaError::Throttled`], [`MfaError::Unavailable`],
    /// [`MfaError::Invalid`], or a fault.
    pub async fn challenge<T: MfaSession, L: Limiter>(
        &self,
        pool: &PgPool,
        limiter: &L,
        session: &Session<T>,
        ip: IpAddr,
        answer: Answer<'_>,
    ) -> Result<(Account, Vec<Event>), MfaError> {
        let now = SystemTime::now();
        let pending = session
            .read(|d| d.mfa().pending)
            .filter(|p| matches!(p.kind, Kind::Challenge | Kind::Reauth))
            .filter(|p| state::within(p.at, self.pending_ttl, state::unix(now)))
            .ok_or(MfaError::NoChallenge)?;
        limiter
            .charge(ip, Key::SecondFactor(pending.account))
            .await?;
        let account = store::by_id_in_epoch(pool, pending.account, pending.epoch)
            .await?
            .filter(|a| {
                pending.kind == Kind::Challenge
                    || session
                        .read(Signed::signature)
                        .is_some_and(|s| s.account == a.id && s.epoch == a.session_epoch)
            });
        let Some(account) = account else {
            session.update(|d| d.mfa_mut().pending = None);
            return Err(MfaError::NoChallenge);
        };

        let mut events = Vec::new();
        let factor = match answer {
            Answer::Totp(code) => {
                self.check_totp(pool, &account, code, now).await?;
                Factor::Totp
            }
            Answer::Recovery(code) => {
                let remaining = Self::use_recovery_code(pool, &account, code).await?;
                if Self::unlock_by_recovery(pool, account.id).await? {
                    events.push(Event::new(account.id, EventKind::Unlocked(Factor::Totp)));
                }
                events.push(Event::new(
                    account.id,
                    EventKind::RecoveryCodeUsed { remaining },
                ));
                Factor::RecoveryCode
            }
        };
        events.push(Event::new(account.id, EventKind::ChallengePassed(factor)));

        if pending.kind == Kind::Reauth {
            session.update(|d| d.mfa_mut().pending = None);
        } else {
            session::sign_in(session, &account);
            // The sign-in is complete only now, so this is the time it shows. (If the
            // stamp fails the session holds no second factor and the layer holds it: the
            // person starts again, and the code just used is a replay, so waits for the next.)
            store::signed_in(pool, account.id).await?;
        }
        state::record(session, &account, true, now);
        Ok((account, events))
    }

    /// A TOTP code against the account's confirmed authenticator, once. A wrong code is
    /// counted; [`LOCK_AFTER`] in a row lock the authenticator.
    async fn check_totp(
        &self,
        pool: &PgPool,
        account: &Account,
        code: &str,
        now: SystemTime,
    ) -> Result<(), MfaError> {
        // A lock that has run out is cleared, with the count that caused it.
        sqlx::query(
            "UPDATE account_totp SET failed_attempts = 0, locked_until = NULL
             WHERE account_id = $1 AND locked_until <= now()",
        )
        .bind(account.id)
        .execute(pool)
        .await?;
        let row: Option<(Vec<u8>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT secret, last_step, EXTRACT(EPOCH FROM locked_until)::bigint
             FROM account_totp WHERE account_id = $1 AND confirmed_at IS NOT NULL",
        )
        .bind(account.id)
        .fetch_optional(pool)
        .await?;
        let Some((stored, last, locked_until)) = row else {
            return Err(MfaError::Invalid);
        };
        if let Some(until) = locked_until {
            return Err(MfaError::Locked {
                until,
                just_locked: false,
            });
        }
        let (secret, reseal) = self.open(&stored, account.id)?;
        let last = last.and_then(|s| u64::try_from(s).ok());
        let Some(step) = totp::verify(&secret, code, now, last) else {
            return Err(Self::count_failure(pool, account.id).await?);
        };
        let step = i64::try_from(step).map_err(|e| MfaError::fault(e.into()))?;
        // The check and the write are one statement: two requests with one code both
        // read the old step, and only one of them moves it forward.
        let moved = sqlx::query(
            "UPDATE account_totp SET last_step = $2, failed_attempts = 0
             WHERE account_id = $1 AND locked_until IS NULL
               AND (last_step IS NULL OR last_step < $2)",
        )
        .bind(account.id)
        .bind(step)
        .execute(pool)
        .await?;
        if moved.rows_affected() != 1 {
            return Err(Self::count_failure(pool, account.id).await?);
        }
        if reseal {
            self.reseal(pool, account.id, &stored, &secret).await;
        }
        Ok(())
    }

    /// Count a wrong code; the error to answer with ([`MfaError::Locked`] when this one
    /// locked the factor, for [`LOCK_FOR`]).
    async fn count_failure(pool: &PgPool, account: i64) -> Result<MfaError, MfaError> {
        let (until, just): (Option<i64>, bool) = sqlx::query_as(
            "UPDATE account_totp SET failed_attempts = failed_attempts + 1,
                    locked_until = CASE WHEN failed_attempts + 1 >= $2 AND locked_until IS NULL
                                        THEN now() + make_interval(secs => $3)
                                        ELSE locked_until END
             WHERE account_id = $1
             RETURNING EXTRACT(EPOCH FROM locked_until)::bigint,
                       failed_attempts = $2 AND locked_until IS NOT NULL",
        )
        .bind(account)
        .bind(LOCK_AFTER)
        .bind(LOCK_FOR.as_secs_f64())
        .fetch_one(pool)
        .await?;
        Ok(match until {
            Some(until) => MfaError::Locked {
                until,
                just_locked: just,
            },
            None => MfaError::Invalid,
        })
    }

    /// A recovery code was used: the authenticator's count of wrong codes starts again,
    /// and it is unlocked. Whether it was locked.
    async fn unlock_by_recovery(pool: &PgPool, account: i64) -> Result<bool, MfaError> {
        let was: Option<(bool,)> = sqlx::query_as(
            "WITH old AS (SELECT locked_until > now() AS locked FROM account_totp
                          WHERE account_id = $1 FOR UPDATE),
                  done AS (UPDATE account_totp SET failed_attempts = 0, locked_until = NULL
                           WHERE account_id = $1 RETURNING 1)
             SELECT COALESCE(locked, false) FROM old",
        )
        .bind(account)
        .fetch_optional(pool)
        .await?;
        Ok(was.is_some_and(|(locked,)| locked))
    }

    /// Use up the recovery code `typed` matches among the account's unused ones; the
    /// codes left.
    async fn use_recovery_code(
        pool: &PgPool,
        account: &Account,
        typed: &str,
    ) -> Result<i64, MfaError> {
        let unused: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, hash FROM account_recovery_codes
             WHERE account_id = $1 AND used_at IS NULL ORDER BY id",
        )
        .bind(account.id)
        .fetch_all(pool)
        .await?;
        let hashes: Vec<&str> = unused.iter().map(|(_, h)| h.as_str()).collect();
        let found = recovery::find_match(typed, &hashes)
            .await?
            .ok_or(MfaError::Invalid)?;
        let used = sqlx::query(
            "UPDATE account_recovery_codes SET used_at = now()
             WHERE id = $1 AND account_id = $2 AND used_at IS NULL",
        )
        .bind(unused[found].0)
        .bind(account.id)
        .execute(pool)
        .await?;
        if used.rows_affected() != 1 {
            return Err(MfaError::Invalid);
        }
        let (left,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM account_recovery_codes WHERE account_id = $1 AND used_at IS NULL",
        )
        .bind(account.id)
        .fetch_one(pool)
        .await?;
        Ok(left)
    }

    /// Begin re-authenticating the signed-in `account` (step-up): check its password
    /// (`password` is `None` only for an account that has none) and, if it has a
    /// second factor, make the re-authentication pending on it
    /// ([`Next::Challenge`]; [`challenge`](Self::challenge) completes it). Without a
    /// factor the time of authentication is renewed at once ([`Next::Done`]).
    ///
    /// The attempt is charged to `limiter` under a key of the account's, apart from its
    /// sign-in's.
    ///
    /// # Errors
    /// [`MfaError::BadPassword`] for a wrong password, [`MfaError::NoChallenge`] if the
    /// session is not signed in as `account`, [`MfaError::NothingToProve`] for an account
    /// with neither password nor factor, or a throttle or fault.
    pub async fn begin_reauth<T: MfaSession, L: Limiter>(
        &self,
        pool: &PgPool,
        limiter: &L,
        session: &Session<T>,
        ip: IpAddr,
        account: &Account,
        password: Option<&str>,
    ) -> Result<Next, MfaError> {
        let now = SystemTime::now();
        let signed = session
            .read(Signed::signature)
            .is_some_and(|s| s.account == account.id && s.epoch == account.session_epoch);
        if !signed {
            return Err(MfaError::NoChallenge);
        }
        limiter.charge(ip, Key::Reauth(account.id)).await?;
        let has_password = store::has_password(pool, account.id).await?;
        let has_factor = self.factors(pool, account.id).await?.any();
        if has_password {
            let given = password.ok_or(MfaError::BadPassword)?;
            let opened = store::check_password(pool, &account.username, given).await?;
            if opened.is_none_or(|a| a.id != account.id) {
                return Err(MfaError::BadPassword);
            }
        } else if !has_factor {
            return Err(MfaError::NothingToProve);
        }
        if has_factor {
            session.update(|d| {
                let auth = d.mfa().auth;
                *d.mfa_mut() = State {
                    pending: Some(state::Pending {
                        account: account.id,
                        epoch: account.session_epoch,
                        at: state::unix(now),
                        kind: Kind::Reauth,
                    }),
                    auth,
                };
            });
            Ok(Next::Challenge)
        } else {
            state::record(session, account, false, now);
            Ok(Next::Done)
        }
    }
}
