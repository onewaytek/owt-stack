//! A second factor after the password, a policy that can require it, and step-up
//! re-authentication for sensitive actions.
//!
//! Two factors exist: an **authenticator app** (TOTP, [`owt_auth::totp`]) and, behind it,
//! **recovery codes** ([`owt_auth::recovery`]) for the day the phone is lost. (Passkeys
//! are not here yet.) Everything is a function an app wires to routes, in the style of
//! [`crate::session::password_sign_in`]; [`Mfa`] holds the configuration they share.
//!
//! # The sign-in
//!
//! [`Mfa::password_sign_in`] checks the throttle and the password as
//! [`session::password_sign_in`](crate::session::password_sign_in) does, then asks what
//! the account needs ([`Next`]):
//!
//! * [`Next::Done`]: it has no second factor and the [policy](MfaPolicy) does not
//!   require one. The session is signed in.
//! * [`Next::Challenge`]: it has a factor. The session now holds a **pending** sign-in,
//!   [`Pending`], that is not a signature: [`Signed`](crate::Signed), [`Staff`](crate::Staff)
//!   and [`Maybe`](crate::Maybe) all see an anonymous visitor. The app shows the code
//!   form; [`Mfa::challenge`] checks a TOTP code or a recovery code and only then signs
//!   in (a new session id, the time of both factors recorded).
//! * [`Next::Enroll`]: the policy requires a factor and it has none. The pending sign-in
//!   opens nothing except enrollment: [`Mfa::pending_account`], [`Mfa::begin_totp`] and
//!   [`Mfa::confirm_totp`], which signs the session in once the first code is proved.
//!   (Whoever has the password can enroll their own authenticator at this point.
//!   Requiring enrollment only protects accounts that have a factor from a password
//!   alone; to protect a new account, create it with a one-time sign-in link or have
//!   staff enroll it.)
//!
//! A pending sign-in expires ([`Mfa::pending_ttl`], ten minutes). Every wrong answer is
//! charged to the throttle under a key of the account's, so six digits cannot be
//! guessed. Any other first factor (a sign-in link, a provider) goes through
//! [`Mfa::first_factor_passed`] in place of [`session::sign_in`](crate::session::sign_in),
//! or it skips the second factor.
//!
//! # Step-up
//!
//! The session records when the account last proved who it is ([`State`]).
//! [`require_recent`] (or the [`Recent`] extractor) refuses a session whose last
//! proof is older than a limit with a [`StepUp`], which the app answers with its
//! re-authentication page; [`Mfa::begin_reauth`] and [`Mfa::challenge`] renew it.
//! Put it in front of what must not be done from a session someone merely left open:
//! exporting records, changing or removing a factor, regenerating recovery codes,
//! break-glass access, changing the password or email.
//!
//! # Secrets
//!
//! The TOTP secret is stored where the database could be read: have a
//! [`SecretSealer`] encrypt it with a key the database does not hold (`owt-crypt`'s,
//! say). The development default [`Unsealed`] stores it in the clear and says so in the
//! log.
//!
//! # Audit
//!
//! Each operation that changes a factor, uses a recovery code or passes a challenge
//! returns [`Event`]s for the app's audit log; a refusal ([`MfaError::Invalid`],
//! [`MfaError::Throttled`]) is for the app to record too. Nothing is written for it.
//! Notify the owner when a recovery code is used or a factor is removed.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use owt_auth::recovery::{self, Recovery};
use owt_auth::throttle::Throttle;
use owt_auth::totp::{self, Secret};
use owt_web::session::Session;
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::session::{self, SignInRefused};
use crate::store::{self, Account};

mod challenge;
mod state;
mod step_up;

pub use challenge::Answer;
pub use state::{Auth, Kind, MfaSession, Pending, State};
pub use step_up::{
    Recent, RecentMfa, StepUp, require_recent, require_recent_at, require_recent_mfa,
};

/// Stamp the session as authenticated now, for a sign-in that did not go through this
/// module ([`session::sign_in`](crate::session::sign_in) clears the record): call it
/// right after, only when the person really just proved who they are (a password, a
/// one-time link, a provider's sign-in). It records no second factor.
pub fn mark_authenticated<T: MfaSession>(session: &Session<T>, account: &Account) {
    state::record(session, account, false, SystemTime::now());
}

/// A second factor an account can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Factor {
    /// An authenticator app's six-digit code.
    Totp,
    /// A single-use recovery code.
    RecoveryCode,
}

impl Factor {
    /// A stable name for logs and audit records.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

/// What happened to an account's factors, for the app's audit log. Returned by the
/// operation that did it; the library writes no log of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Event {
    /// The account.
    pub account: i64,
    /// What happened.
    pub kind: EventKind,
}

/// What an [`Event`] records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// A factor was enrolled (confirmed with a first code).
    Enrolled(Factor),
    /// A factor was removed.
    Removed(Factor),
    /// A new set of recovery codes replaced the old. They are shown once.
    RecoveryCodesIssued,
    /// A recovery code signed the account in (or re-authenticated it): its owner
    /// should be told, and `remaining` codes are left.
    RecoveryCodeUsed {
        /// The unused codes left.
        remaining: i64,
    },
    /// A second-factor challenge was passed: a sign-in completed, or a session was
    /// re-authenticated.
    ChallengePassed(Factor),
}

impl Event {
    /// A stable, dotted name for the audit log: `mfa.totp.enrolled`,
    /// `mfa.totp.removed`, `mfa.recovery_codes.issued`, `mfa.recovery_code.used`,
    /// `mfa.challenge.passed`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.kind {
            EventKind::Enrolled(Factor::Totp) => "mfa.totp.enrolled",
            EventKind::Enrolled(_) => "mfa.factor.enrolled",
            EventKind::Removed(Factor::Totp) => "mfa.totp.removed",
            EventKind::Removed(_) => "mfa.factor.removed",
            EventKind::RecoveryCodesIssued => "mfa.recovery_codes.issued",
            EventKind::RecoveryCodeUsed { .. } => "mfa.recovery_code.used",
            EventKind::ChallengePassed(_) => "mfa.challenge.passed",
        }
    }
}

/// Which accounts must have a second factor.
#[derive(Clone, Default)]
pub enum MfaPolicy {
    /// Nobody must; an account that enrolled is still challenged.
    #[default]
    Optional,
    /// Every account.
    Required,
    /// The accounts the function says (staff only, say).
    When(Arc<dyn Fn(&Account) -> bool + Send + Sync>),
}

impl std::fmt::Debug for MfaPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Optional => "Optional",
            Self::Required => "Required",
            Self::When(_) => "When(..)",
        })
    }
}

impl MfaPolicy {
    /// Required of the accounts for which `f` is true.
    pub fn when(f: impl Fn(&Account) -> bool + Send + Sync + 'static) -> Self {
        Self::When(Arc::new(f))
    }

    /// Whether `account` must have a second factor.
    #[must_use]
    pub fn requires(&self, account: &Account) -> bool {
        match self {
            Self::Optional => false,
            Self::Required => true,
            Self::When(f) => f(account),
        }
    }
}

/// Seals the TOTP secret before it is stored and opens it when it is read.
///
/// The secret in `account_totp.secret` lets whoever reads it make that account's codes
/// for ever. An app seals it with an authenticated cipher (AES-GCM or
/// XChaCha20-Poly1305) under a key the database does not hold, and binds the
/// ciphertext to the row with `context` as the associated data, so one account's
/// sealed secret pasted into another's row does not open.
pub trait SecretSealer: Send + Sync {
    /// The bytes to store for `plaintext`.
    ///
    /// # Errors
    /// The sealing failed; nothing is stored.
    fn seal(&self, plaintext: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// The secret `sealed` holds.
    ///
    /// # Errors
    /// It does not open (a wrong key, damage, another row's `context`).
    fn open(&self, sealed: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The development sealer: stores the secret **in the clear**. Not for production: a
/// read of the database (a backup, a SQL injection, a replica) would then hand over every
/// account's second factor. [`Mfa::new`] logs a warning when it is in use.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unsealed;

impl SecretSealer for Unsealed {
    fn seal(&self, plaintext: &[u8], _: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, sealed: &[u8], _: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(sealed.to_vec())
    }
}

/// Why a charge to a [`Limiter`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Throttled {
    /// A budget is spent.
    Spent,
    /// The shared counter could not be reached and fails closed.
    Unavailable,
}

/// What charges sign-in attempts: the in-process [`Throttle`], or with the `redis`
/// feature the [`SharedThrottle`](owt_auth::throttle::shared::SharedThrottle), whose
/// budgets hold across replicas (use it when there are several).
pub trait Limiter: Send + Sync {
    /// Charge a sign-in attempt under `key` from `ip`.
    fn charge(&self, ip: IpAddr, key: &str) -> impl Future<Output = Result<(), Throttled>> + Send;
}

impl Limiter for Throttle {
    fn charge(&self, ip: IpAddr, key: &str) -> impl Future<Output = Result<(), Throttled>> + Send {
        let allowed = self.sign_in(ip, key);
        std::future::ready(if allowed {
            Ok(())
        } else {
            Err(Throttled::Spent)
        })
    }
}

#[cfg(feature = "redis")]
impl Limiter for owt_auth::throttle::shared::SharedThrottle {
    async fn charge(&self, ip: IpAddr, key: &str) -> Result<(), Throttled> {
        use owt_auth::throttle::shared::Refusal;
        self.sign_in(ip, key).await.map_err(|r| match r {
            Refusal::Unavailable => Throttled::Unavailable,
            _ => Throttled::Spent,
        })
    }
}

/// What a person, or the app on their behalf, can do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Next {
    /// Signed in (or re-authenticated): redirect.
    Done,
    /// A second factor is needed: show the code form and call [`Mfa::challenge`].
    Challenge,
    /// The policy requires a factor and the account has none: send the person to
    /// enrollment ([`Mfa::begin_totp`]).
    Enroll,
}

/// Why an operation did nothing. Each message is written for the person. A variant may
/// be added without a breaking release, so a `match` on it ends with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MfaError {
    /// A budget of the throttle is spent: nothing was checked.
    #[error("Too many attempts. Wait a minute and try again.")]
    Throttled,
    /// The shared throttle could not be reached and fails closed. Answer 503.
    #[error("Signing in is unavailable for a moment. Please try again shortly.")]
    Unavailable,
    /// The code is wrong, expired, or already used. It does not say which.
    #[error("That code is not right, or it has been used already.")]
    Invalid,
    /// There is no sign-in waiting for a second factor, or it has expired.
    #[error("That sign-in has expired. Please start again.")]
    NoChallenge,
    /// An authenticator is already set up; remove it first.
    #[error("An authenticator is already set up for this account.")]
    AlreadyEnrolled,
    /// No enrollment has begun for the code to confirm.
    #[error("Set up the authenticator again: it was not started, or has been replaced.")]
    NotEnrolling,
    /// The account has no such factor.
    #[error("This account has no authenticator.")]
    NotEnrolled,
    /// Removing it would leave an account that must have a second factor with none.
    #[error("This account must have a second factor, so the last one cannot be removed.")]
    LastFactor,
    /// Re-authenticating needs a password or a factor, and the account has neither.
    #[error("There is nothing to confirm your identity with. Sign in again.")]
    NothingToProve,
    /// A fault: the database, the random source or the sealer. Its source may name
    /// tables; log it and never show it.
    #[error("The check could not be made. Try again in a moment.")]
    Fault(#[from] crate::Error),
}

impl From<sqlx::Error> for MfaError {
    fn from(e: sqlx::Error) -> Self {
        Self::Fault(e.into())
    }
}

impl From<Throttled> for MfaError {
    fn from(t: Throttled) -> Self {
        match t {
            Throttled::Spent => Self::Throttled,
            Throttled::Unavailable => Self::Unavailable,
        }
    }
}

impl MfaError {
    /// The status a form answers with: 429 throttled, 503 unavailable, 422 a code or
    /// a request refused, 500 a fault.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Fault(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn fault(e: anyhow::Error) -> Self {
        Self::Fault(crate::Error::Hash(e))
    }
}

impl From<MfaError> for owt_web::Error {
    fn from(e: MfaError) -> Self {
        match e {
            MfaError::Unavailable => Self::unavailable(e.to_string()),
            MfaError::Fault(e) => e.into(),
            other => Self::Unprocessable(other.to_string().into()),
        }
    }
}

/// An authenticator being set up: show it once.
///
/// It holds the secret in three forms. Send the page `Cache-Control: no-store`, do not
/// log it, and let it go out of scope (its text is zeroed when dropped, the SVG is not:
/// an SVG is markup the browser needs).
pub struct TotpEnrollment {
    /// The secret as base32, to type into an authenticator that cannot scan.
    pub secret: Zeroizing<String>,
    /// The `otpauth://` URI the QR code encodes.
    pub uri: Zeroizing<String>,
    /// The QR code as an SVG document (safe to embed unescaped: the library made it).
    pub qr_svg: String,
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrollment(<redacted>)")
    }
}

/// What confirming a first code returns.
#[derive(Debug)]
pub struct Confirmed {
    /// Single-use recovery codes (ten unless [`Mfa::recovery_codes`] says otherwise), **shown once**: they are stored only as hashes.
    /// Replaces any earlier set.
    pub recovery_codes: Vec<Recovery>,
    /// What to do next: [`Next::Done`] when the session is signed in (it was enrolling).
    pub next: Next,
    /// For the audit log.
    pub events: Vec<Event>,
}

/// An account's factors, as the settings page lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factors {
    /// When the authenticator was confirmed (Unix seconds), if one is set up.
    pub totp_confirmed_at: Option<i64>,
    /// Recovery codes not yet used.
    pub recovery_codes_left: i64,
}

impl Factors {
    /// How many second factors the account holds (recovery codes are a way back from
    /// losing one, not a factor of their own).
    #[must_use]
    pub fn count(&self) -> usize {
        usize::from(self.totp_confirmed_at.is_some())
    }

    /// Whether the account has a second factor to challenge.
    #[must_use]
    pub fn any(&self) -> bool {
        self.count() > 0
    }
}

/// The configuration the second-factor functions share. Build one at start, keep it
/// in the app's state.
#[derive(Clone)]
pub struct Mfa {
    issuer: String,
    sealer: Arc<dyn SecretSealer>,
    policy: MfaPolicy,
    pending_ttl: Duration,
    recovery_codes: usize,
}

impl std::fmt::Debug for Mfa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mfa")
            .field("issuer", &self.issuer)
            .field("policy", &self.policy)
            .field("pending_ttl", &self.pending_ttl)
            .finish_non_exhaustive()
    }
}

impl Mfa {
    /// Second factors named `issuer` in the person's authenticator app (the service's
    /// name), [`Optional`](MfaPolicy::Optional), with the development sealer
    /// ([`Unsealed`]): set [`sealer`](Self::sealer) before production.
    #[must_use]
    pub fn new(issuer: impl Into<String>) -> Self {
        static WARN: Once = Once::new();
        WARN.call_once(|| {
            tracing::warn!("TOTP secrets are stored unsealed: set Mfa::sealer before production");
        });
        Self {
            issuer: issuer.into(),
            sealer: Arc::new(Unsealed),
            policy: MfaPolicy::Optional,
            pending_ttl: Duration::from_secs(600),
            recovery_codes: recovery::DEFAULT_COUNT,
        }
    }

    /// Seal the secrets with `sealer`.
    #[must_use]
    pub fn sealer(mut self, sealer: impl SecretSealer + 'static) -> Self {
        self.sealer = Arc::new(sealer);
        self
    }

    /// Which accounts must have a second factor.
    #[must_use]
    pub fn policy(mut self, policy: MfaPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// How long a pending sign-in waits for its factor (ten minutes by default).
    #[must_use]
    pub fn pending_ttl(mut self, ttl: Duration) -> Self {
        self.pending_ttl = ttl;
        self
    }

    /// How many recovery codes to issue (ten by default; at least one).
    #[must_use]
    pub fn recovery_codes(mut self, count: usize) -> Self {
        self.recovery_codes = count.max(1);
        self
    }

    /// Whether `account` must have a second factor under the policy.
    #[must_use]
    pub fn requires(&self, account: &Account) -> bool {
        self.policy.requires(account)
    }

    fn context(account: i64) -> Vec<u8> {
        format!("owt-accounts/totp/{account}").into_bytes()
    }

    /// The account whose pending sign-in is waiting for [`Kind::Enroll`] (it must enroll a
    /// factor) or [`Kind::Challenge`], if the session holds one that has not expired and
    /// whose epoch still stands.
    ///
    /// # Errors
    /// The database.
    pub async fn pending_account<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
    ) -> sqlx::Result<Option<(Account, Kind)>> {
        let Some(pending) = session.read(|d| d.mfa().pending) else {
            return Ok(None);
        };
        if !state::within(pending.at, self.pending_ttl, state::unix(SystemTime::now())) {
            return Ok(None);
        }
        let account = store::by_id_in_epoch(pool, pending.account, pending.epoch).await?;
        Ok(account.map(|a| (a, pending.kind)))
    }

    /// The factors `account` holds.
    ///
    /// # Errors
    /// The database.
    pub async fn factors(&self, pool: &PgPool, account: i64) -> sqlx::Result<Factors> {
        let (confirmed_at, left): (Option<i64>, i64) = sqlx::query_as(
            "SELECT
               (SELECT EXTRACT(EPOCH FROM confirmed_at)::bigint FROM account_totp
                 WHERE account_id = $1 AND confirmed_at IS NOT NULL),
               (SELECT count(*) FROM account_recovery_codes
                 WHERE account_id = $1 AND used_at IS NULL)",
        )
        .bind(account)
        .fetch_one(pool)
        .await?;
        Ok(Factors {
            totp_confirmed_at: confirmed_at,
            recovery_codes_left: left,
        })
    }

    /// Begin setting up an authenticator for `account`: a fresh secret, stored
    /// unconfirmed (it signs nobody in), and the forms to show it in. Calling again
    /// before a code is confirmed replaces the secret.
    ///
    /// For a signed-in account, put this behind [`require_recent_mfa`] or
    /// [`require_recent`]: whoever holds a session can otherwise enroll their own
    /// authenticator on the account.
    ///
    /// # Errors
    /// [`MfaError::AlreadyEnrolled`] (remove the old one first), or a fault.
    pub async fn begin_totp(
        &self,
        pool: &PgPool,
        account: &Account,
    ) -> Result<TotpEnrollment, MfaError> {
        let secret = Secret::generate().map_err(MfaError::fault)?;
        let sealed = self
            .sealer
            .seal(secret.as_bytes(), &Self::context(account.id))
            .map_err(MfaError::fault)?;
        let stored = sqlx::query(
            "INSERT INTO account_totp (account_id, secret) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE
               SET secret = EXCLUDED.secret, last_step = NULL, created_at = now()
               WHERE account_totp.confirmed_at IS NULL",
        )
        .bind(account.id)
        .bind(&sealed)
        .execute(pool)
        .await?;
        if stored.rows_affected() == 0 {
            return Err(MfaError::AlreadyEnrolled);
        }
        let name = if account.email.is_empty() {
            &account.username
        } else {
            &account.email
        };
        let uri = totp::otpauth_uri(&self.issuer, name, &secret);
        let qr_svg = qrcode::QrCode::new(uri.as_bytes())
            .map(|code| {
                code.render::<qrcode::render::svg::Color<'_>>()
                    .min_dimensions(224, 224)
                    .build()
            })
            .map_err(|e| MfaError::fault(e.into()))?;
        Ok(TotpEnrollment {
            secret: secret.to_base32(),
            uri,
            qr_svg,
        })
    }

    /// Confirm the authenticator `begin_totp` started with the first `code` it shows.
    /// The authenticator then challenges every sign-in, and ten recovery codes are
    /// made (replacing any earlier set) and returned **once**.
    ///
    /// `session` is either signed in as `account` (the settings page: the time of a
    /// second factor is recorded) or holds its pending [`Kind::Enroll`] (the
    /// policy's first sign-in: it is signed in now, [`Confirmed::next`] is
    /// [`Next::Done`]); anything else is [`MfaError::NoChallenge`].
    ///
    /// # Errors
    /// [`MfaError::Invalid`] for a wrong code, [`MfaError::NotEnrolling`] if none was
    /// begun, or a fault.
    pub async fn confirm_totp<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
        code: &str,
    ) -> Result<Confirmed, MfaError> {
        let now = SystemTime::now();
        let entry = challenge::Entry::of(session, account, self.pending_ttl, now)
            .ok_or(MfaError::NoChallenge)?;
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret FROM account_totp WHERE account_id = $1 AND confirmed_at IS NULL",
        )
        .bind(account.id)
        .fetch_optional(pool)
        .await?;
        let (sealed,) = row.ok_or(MfaError::NotEnrolling)?;
        let secret = self.open(&sealed, account.id)?;
        let step = totp::verify(&secret, code, now, None).ok_or(MfaError::Invalid)?;
        let codes = recovery::generate(self.recovery_codes)
            .await
            .map_err(MfaError::fault)?;

        let mut tx = pool.begin().await?;
        // Confirm only the secret that was checked: a begin between the read and here
        // replaced it.
        let confirmed = sqlx::query(
            "UPDATE account_totp SET confirmed_at = now(), last_step = $2
             WHERE account_id = $1 AND confirmed_at IS NULL AND secret = $3",
        )
        .bind(account.id)
        .bind(i64::try_from(step).map_err(|e| MfaError::fault(e.into()))?)
        .bind(&sealed)
        .execute(&mut *tx)
        .await?;
        if confirmed.rows_affected() == 0 {
            return Err(MfaError::NotEnrolling);
        }
        replace_codes(&mut tx, account.id, &codes).await?;
        tx.commit().await?;

        let next = entry.finish(session, account, now, true);
        Ok(Confirmed {
            recovery_codes: codes,
            next,
            events: vec![
                Event {
                    account: account.id,
                    kind: EventKind::Enrolled(Factor::Totp),
                },
                Event {
                    account: account.id,
                    kind: EventKind::RecoveryCodesIssued,
                },
            ],
        })
    }

    /// Replace the account's recovery codes with new ones, returned **once**.
    /// Needs an authenticator (the codes are its backup). Put it behind
    /// [`require_recent_mfa`].
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`], or a fault.
    pub async fn regenerate_recovery_codes(
        &self,
        pool: &PgPool,
        account: &Account,
    ) -> Result<(Vec<Recovery>, Event), MfaError> {
        if !self.factors(pool, account.id).await?.any() {
            return Err(MfaError::NotEnrolled);
        }
        let codes = recovery::generate(self.recovery_codes)
            .await
            .map_err(MfaError::fault)?;
        let mut tx = pool.begin().await?;
        // Held for the swap, and gone if the authenticator was removed meanwhile.
        let held: Option<(i64,)> = sqlx::query_as(
            "SELECT account_id FROM account_totp
             WHERE account_id = $1 AND confirmed_at IS NOT NULL FOR UPDATE",
        )
        .bind(account.id)
        .fetch_optional(&mut *tx)
        .await?;
        if held.is_none() {
            return Err(MfaError::NotEnrolled);
        }
        replace_codes(&mut tx, account.id, &codes).await?;
        tx.commit().await?;
        let event = Event {
            account: account.id,
            kind: EventKind::RecoveryCodesIssued,
        };
        Ok((codes, event))
    }

    /// Remove the authenticator and the recovery codes behind it. Refused with
    /// [`MfaError::LastFactor`] when the policy requires `account` to have a factor and
    /// this is its last. Changes no session epoch: other sessions stay signed in. Put it
    /// behind [`require_recent_mfa`], and tell the owner.
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`], [`MfaError::LastFactor`], or a fault.
    pub async fn remove_totp(&self, pool: &PgPool, account: &Account) -> Result<Event, MfaError> {
        let mut tx = pool.begin().await?;
        let held: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM confirmed_at)::bigint FROM account_totp
             WHERE account_id = $1 FOR UPDATE",
        )
        .bind(account.id)
        .fetch_optional(&mut *tx)
        .await?;
        match held {
            Some((Some(_),)) => {}
            // An enrollment never confirmed is not a factor: clearing it is harmless,
            // but there is nothing to remove.
            _ => return Err(MfaError::NotEnrolled),
        }
        // Other factors would be counted here; there are none yet.
        if self.requires(account) {
            return Err(MfaError::LastFactor);
        }
        sqlx::query("DELETE FROM account_totp WHERE account_id = $1")
            .bind(account.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
            .bind(account.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Event {
            account: account.id,
            kind: EventKind::Removed(Factor::Totp),
        })
    }

    fn open(&self, sealed: &[u8], account: i64) -> Result<Secret, MfaError> {
        let plain = Zeroizing::new(
            self.sealer
                .open(sealed, &Self::context(account))
                .map_err(MfaError::fault)?,
        );
        Secret::from_bytes(&plain)
            .ok_or_else(|| MfaError::fault(anyhow::anyhow!("a stored TOTP secret of a bad length")))
    }

    /// What follows a checked first factor (a password, a sign-in link, a provider's
    /// sign-in) for `account`: it is signed in, or its sign-in is made pending on a
    /// second factor, or on enrollment. Use it in place of
    /// [`session::sign_in`](crate::session::sign_in) on every way in that should
    /// honour the policy.
    ///
    /// # Errors
    /// The database.
    pub async fn first_factor_passed<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
    ) -> Result<Next, MfaError> {
        let now = SystemTime::now();
        let kind = if self.factors(pool, account.id).await?.any() {
            Some(Kind::Challenge)
        } else if self.requires(account) {
            Some(Kind::Enroll)
        } else {
            None
        };
        let Some(kind) = kind else {
            session::sign_in(session, account);
            state::record(session, account, false, now);
            return Ok(Next::Done);
        };
        let pending = Pending {
            account: account.id,
            epoch: account.session_epoch,
            at: state::unix(now),
            kind,
        };
        // A new id, and no signature: whoever was signed in on this browser is not, and
        // the pending sign-in grants nothing.
        session.cycle_id();
        session.update(|d| {
            d.set_signature(None);
            *d.mfa_mut() = State {
                pending: Some(pending),
                auth: None,
            };
        });
        Ok(match kind {
            Kind::Enroll => Next::Enroll,
            _ => Next::Challenge,
        })
    }

    /// The password sign-in with a second factor: charge `limiter` for `login` from
    /// `ip`, check the password only if it allows ([`store::authenticate`]), then
    /// [`first_factor_passed`](Self::first_factor_passed).
    ///
    /// # Errors
    /// [`SignInRefused`]: throttled, a mismatch, unavailable (the shared throttle), or a
    /// fault.
    pub async fn password_sign_in<T: MfaSession, L: Limiter>(
        &self,
        pool: &PgPool,
        limiter: &L,
        session: &Session<T>,
        ip: IpAddr,
        login: &str,
        password: &str,
    ) -> Result<Next, SignInRefused> {
        if login.trim().chars().any(char::is_control) {
            return Err(SignInRefused::Mismatch);
        }
        limiter.charge(ip, login).await.map_err(|t| match t {
            Throttled::Spent => SignInRefused::Throttled,
            Throttled::Unavailable => SignInRefused::Unavailable,
        })?;
        let account = store::authenticate(pool, login, password)
            .await?
            .ok_or(SignInRefused::Mismatch)?;
        self.first_factor_passed(pool, session, &account)
            .await
            .map_err(|e| match e {
                MfaError::Fault(e) => SignInRefused::Fault(e),
                other => SignInRefused::Fault(crate::Error::Hash(anyhow::anyhow!(other))),
            })
    }
}

/// Replace the account's recovery codes, in `tx`.
async fn replace_codes(
    tx: &mut sqlx::PgConnection,
    account: i64,
    codes: &[Recovery],
) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    for code in codes {
        sqlx::query("INSERT INTO account_recovery_codes (account_id, hash) VALUES ($1, $2)")
            .bind(account)
            .bind(&code.hash)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}
