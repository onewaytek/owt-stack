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
//!   Whoever has the password can enroll their own authenticator at this point, so the
//!   events of such an enrollment have `while_pending` set: **email the account's owner
//!   whenever one does** (and when turning on [`MfaPolicy::Required`], roll it out by
//!   groups). The policy protects accounts that have a factor from a password alone, not
//!   a never-enrolled account from one.
//!
//! A pending sign-in expires ([`Mfa::pending_ttl`], ten minutes). Every wrong answer is
//! charged to the throttle under a key of the account's ([`Key`]), so six digits cannot be
//! guessed; and [`LOCK_AFTER`] wrong authenticator codes in a row (counted in the
//! database, so across replicas and over days) lock it, until a recovery code or staff
//! ([`Mfa::unlock_totp`]) unlock it ([`MfaError::Locked`]: tell the owner).
//!
//! # Every door
//!
//! The second factor is enforced where the session is *read*, not where it is made:
//! build the layer's [`Accounts`](crate::Accounts) with
//! [`require_mfa`](crate::Accounts::require_mfa): `Accounts::load` and `load_with` then
//! enforce it, with no second layer to remember.
//! A signature for an account that has a factor, or that the policy requires to have
//! one, then counts as signed in only when the session shows the second factor passed for
//! that account and epoch; otherwise the request is anonymous and the session becomes the
//! pending sign-in above. So a provider sign-in, a link, a password gate and an old
//! `/login` route left in place cannot skip it. Without the layer, only the doors that
//! call [`Mfa::first_factor_passed`] enforce it.
//!
//! # Step-up
//!
//! The session records when the account last proved who it is ([`State`]).
//! [`require_recent`] (or the [`Recent`] extractor) refuses a session whose last
//! proof is older than a limit with a [`StepUp`], which the app answers with its
//! re-authentication page; [`Mfa::begin_reauth`] and [`Mfa::challenge`] renew it.
//! Put it in front of what must not be done from a session someone merely left open:
//! exporting records, break-glass access, changing the password or email. Changing a
//! factor needs it, and the compiler sees to that: [`Mfa::authorize_change`] makes the
//! [`ChangeProof`] that [`Mfa::begin_totp`], [`Mfa::confirm_totp`], [`Mfa::remove_totp`]
//! and [`Mfa::regenerate_recovery_codes`] take, and it asks for a second factor used
//! within the limit (a recovery code counts: it proves the person holds one of the
//! account's factors). Each of those moves the account's session epoch on, so every other
//! session of it ends, and reseals the current one.
//!
//! # Secrets
//!
//! The TOTP secret is stored where the database could be read: have a
//! [`SecretSealer`] encrypt it with a key the database does not hold (`owt-crypt`'s,
//! say). What is stored carries a format byte and the key id, so keys rotate; the
//! development default [`Unsealed`] stores it in the clear, marked plain, and says so in
//! the log; a release build refuses it. A plain row is accepted and sealed at its next use once a real sealer is set.
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

use crate::session::{self, SignInRefused, Signed};
use crate::store::{self, Account};

mod challenge;
mod state;
mod step_up;

pub use challenge::Answer;
pub use state::{Auth, Kind, MfaSession, Pending, State};
pub(crate) use step_up::guard_to;
pub use step_up::{
    Recent, RecentMfa, StepUp, require_recent, require_recent_at, require_recent_mfa,
    require_recent_mfa_for,
};

/// Refresh the session's recency of authentication (what [`require_recent`] reads) now, for a sign-in that did not go through this
/// module ([`session::sign_in`](crate::session::sign_in) clears the record): call it right
/// after the credential was checked (a one-time link, a provider's sign-in). It stamps
/// only the account the session is signed in as, and records no second factor: an account
/// that has one, or that the policy requires to, is held at the layer
/// ([`Accounts::require_mfa`](crate::Accounts::require_mfa)) until it passes, whatever
/// this records. Returns whether it stamped.
///
/// This refreshes recency; it does not complete a sign-in or pass a second factor. Call it
/// only straight after a credential was checked: a handler that calls it as a keep-alive
/// lets a stale cookie pass [`Mfa::authorize_change`] for an account with no factor yet.
pub fn mark_authenticated<T: MfaSession>(session: &Session<T>, account: &Account) -> bool {
    let signed = session
        .read(Signed::signature)
        .is_some_and(|s| s.account == account.id && s.epoch == account.session_epoch);
    if signed {
        state::record(session, account, false, SystemTime::now());
    }
    signed
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
    /// A factor was enrolled from a *pending* sign-in, on a password alone (the policy
    /// required a factor and the account had none). Whoever holds the password can do
    /// this, so tell the account's owner by email whenever it is true.
    pub while_pending: bool,
}

impl Event {
    pub(crate) fn new(account: i64, kind: EventKind) -> Self {
        Self {
            account,
            kind,
            while_pending: false,
        }
    }
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
    /// The authenticator was locked after too many wrong codes (see
    /// [`MfaError::locked_event`]): someone is guessing; tell the owner.
    Locked(Factor),
    /// A locked factor was unlocked (by a recovery code or by staff).
    Unlocked(Factor),
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
            EventKind::Locked(_) => "mfa.factor.locked",
            EventKind::Unlocked(_) => "mfa.factor.unlocked",
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
///
/// What is stored carries a format byte and the [`key_id`](Self::key_id) of the key that
/// sealed it, so keys can be rotated: a secret sealed under an older key id is opened
/// with it (the sealer is told which) and resealed under the current one at its next
/// use. A secret stored by [`Unsealed`] is marked as plain and is likewise accepted and
/// resealed once a real sealer is set, so adopting one later locks nobody out.
pub trait SecretSealer: Send + Sync {
    /// The id of the key [`seal`](Self::seal) uses now (at most 255 bytes).
    fn key_id(&self) -> &str;

    /// Whether this stores the secret in the clear ([`Unsealed`] only).
    fn is_plaintext(&self) -> bool {
        false
    }

    /// The bytes to store for `plaintext`, under the current key.
    ///
    /// # Errors
    /// The sealing failed; nothing is stored.
    fn seal(&self, plaintext: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// The secret `sealed` holds, sealed under the key `key_id` names.
    ///
    /// # Errors
    /// It does not open (a wrong or unknown key, damage, another row's `context`).
    fn open(&self, key_id: &str, sealed: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The development sealer: stores the secret **in the clear**, marked as plain. Not for
/// production: a read of the database (a backup, a SQL injection, a replica) would then
/// hand over every account's second factor. [`Mfa::new`] logs a warning when it is in
/// use, and a build without `debug_assertions` (a release build) refuses it: enrolling,
/// and signing in with a factor stored by it, fail with [`MfaError::Fault`] until
/// [`Mfa::sealer`] sets a real sealer, which then reseals each plain secret at its next
/// use.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unsealed;

/// [`Unsealed`] in a release build: a fault, so no secret is stored or read in the
/// clear outside development.
fn refuse_unsealed() -> Result<(), MfaError> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err(MfaError::fault(anyhow::anyhow!(
            "TOTP secrets are unsealed in a release build: set Mfa::sealer"
        )))
    }
}

impl SecretSealer for Unsealed {
    #[allow(clippy::unnecessary_literal_bound)] // the trait's signature
    fn key_id(&self) -> &str {
        ""
    }

    fn is_plaintext(&self) -> bool {
        true
    }

    fn seal(&self, plaintext: &[u8], _: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, _: &str, sealed: &[u8], _: &[u8]) -> anyhow::Result<Vec<u8>> {
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

/// What an attempt is charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key<'a> {
    /// A password sign-in to this login (a username or an email).
    Login(&'a str),
    /// Second-factor answers for this account.
    SecondFactor(i64),
    /// Re-authentication of this account.
    Reauth(i64),
}

impl Key<'_> {
    /// The string a [`Throttle`] counts it under. A login cannot spell the other two
    /// ([`Mfa::password_sign_in`] refuses control characters).
    #[must_use]
    pub fn as_throttle_key(&self) -> String {
        match self {
            Self::Login(login) => (*login).to_owned(),
            Self::SecondFactor(id) => format!("\0mfa\0{id}"),
            Self::Reauth(id) => format!("\0reauth\0{id}"),
        }
    }
}

/// The account a throttle key names, if it is one of the second-factor kinds: for the
/// `Lockout::account` that
/// [`SharedThrottle::on_lockout`](owt_auth::throttle::shared::SharedThrottle::on_lockout)
/// passes its hook, so the app can email the owner "someone is guessing your second
/// factor".
#[must_use]
pub fn lockout_account(throttle_key: &str) -> Option<i64> {
    throttle_key
        .strip_prefix("\0mfa\0")
        .or_else(|| throttle_key.strip_prefix("\0reauth\0"))
        .and_then(|id| id.parse().ok())
}

/// What charges sign-in attempts: the in-process [`Throttle`], or with the `redis`
/// feature the [`SharedThrottle`](owt_auth::throttle::shared::SharedThrottle), whose
/// budgets hold across replicas (use it when there are several).
pub trait Limiter: Send + Sync {
    /// Charge an attempt under `key` from `ip`.
    fn charge(
        &self,
        ip: IpAddr,
        key: Key<'_>,
    ) -> impl Future<Output = Result<(), Throttled>> + Send;
}

impl Limiter for Throttle {
    fn charge(
        &self,
        ip: IpAddr,
        key: Key<'_>,
    ) -> impl Future<Output = Result<(), Throttled>> + Send {
        let allowed = self.sign_in(ip, &key.as_throttle_key());
        std::future::ready(if allowed {
            Ok(())
        } else {
            Err(Throttled::Spent)
        })
    }
}

#[cfg(feature = "redis")]
impl Limiter for owt_auth::throttle::shared::SharedThrottle {
    async fn charge(&self, ip: IpAddr, key: Key<'_>) -> Result<(), Throttled> {
        use owt_auth::throttle::shared::Refusal;
        self.sign_in(ip, &key.as_throttle_key())
            .await
            .map_err(|r| match r {
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
    /// The authenticator is locked for [`LOCK_FOR`] after too many wrong codes in a row.
    /// A recovery code unlocks it at once, or staff do ([`Mfa::unlock_totp`]).
    #[error(
        "Too many wrong codes. Use a recovery code to unlock the authenticator, or try again in a few minutes."
    )]
    Locked {
        /// When it unlocks by itself, in Unix seconds.
        until: i64,
        /// This answer is the one that locked it: the app should tell the owner
        /// ([`MfaError::locked_event`]).
        just_locked: bool,
    },
    /// A password was asked for and is not the account's.
    #[error("That is not your password.")]
    BadPassword,
    /// The change needs the person to have proved who they are lately.
    #[error(transparent)]
    StepUp(#[from] StepUp),
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
    /// The audit event for the lock this answer just caused, to email the owner about
    /// (and record). `None` for any other answer, and for a lock already in force.
    #[must_use]
    pub fn locked_event(&self, account: i64) -> Option<Event> {
        matches!(
            self,
            Self::Locked {
                just_locked: true,
                ..
            }
        )
        .then(|| Event::new(account, EventKind::Locked(Factor::Totp)))
    }

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
/// log it, and let it go out of scope (its text is zeroed when dropped, the SVG's too).
pub struct TotpEnrollment {
    /// The secret as base32, to type into an authenticator that cannot scan.
    pub secret: Zeroizing<String>,
    /// The `otpauth://` URI the QR code encodes.
    pub uri: Zeroizing<String>,
    /// The QR code as an SVG document (safe to embed unescaped: the library made it).
    pub qr_svg: Zeroizing<String>,
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
    /// The authenticator is locked after too many wrong codes ([`MfaError::Locked`]).
    pub totp_locked: bool,
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

/// Wrong authenticator codes in a row after which the factor is locked.
pub const LOCK_AFTER: i32 = 10;

/// How long a lock lasts if no recovery code or staff lifts it sooner.
pub const LOCK_FOR: Duration = Duration::from_mins(15);

/// Proof that the person may change their factors now: made by [`Mfa::authorize_change`]
/// and nothing else, and asked for by every function that changes them
/// ([`Mfa::begin_totp`], [`Mfa::confirm_totp`], [`Mfa::remove_totp`],
/// [`Mfa::regenerate_recovery_codes`]), so a handler that forgets the step-up does not
/// compile.
#[derive(Debug)]
pub struct ChangeProof {
    account: i64,
    pending: bool,
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
    accept_plaintext: bool,
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
    /// ([`Unsealed`]), which a release build refuses: set [`sealer`](Self::sealer).
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
            accept_plaintext: true,
        }
    }

    /// Seal the secrets with `sealer`. Secrets already stored in the clear (by
    /// [`Unsealed`]) keep working and are sealed at their next use.
    #[must_use]
    pub fn sealer(mut self, sealer: impl SecretSealer + 'static) -> Self {
        self.sealer = Arc::new(sealer);
        self
    }

    /// Whether a secret stored in the clear is accepted (and sealed at its next use) once a
    /// real sealer is set: `true` by default, for the move from [`Unsealed`]. Turn it off
    /// when none remain (`SELECT count(*) FROM account_totp WHERE get_byte(secret, 0) = 0`
    /// is 0): until then anyone who can write to the table can plant a known secret in a
    /// plain row, which the sealer's authentication would have stopped. A plain row is
    /// then a fault, as a sealed row is under [`Unsealed`].
    #[must_use]
    pub fn accept_plaintext(mut self, accept: bool) -> Self {
        self.accept_plaintext = accept;
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

    /// The bytes to store for `secret`: `0` and the secret itself for [`Unsealed`], else
    /// `1`, the key id's length, the key id, and what the sealer returned.
    fn pack(&self, secret: &Secret, account: i64) -> Result<Vec<u8>, MfaError> {
        if self.sealer.is_plaintext() {
            refuse_unsealed()?;
            let mut out = vec![0u8];
            out.extend_from_slice(secret.as_bytes());
            return Ok(out);
        }
        let id = self.sealer.key_id().as_bytes();
        let len = u8::try_from(id.len())
            .map_err(|_| MfaError::fault(anyhow::anyhow!("a sealer key id over 255 bytes")))?;
        let sealed = self
            .sealer
            .seal(secret.as_bytes(), &Self::context(account))
            .map_err(MfaError::fault)?;
        let mut out = vec![1u8, len];
        out.extend_from_slice(id);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The secret `stored` holds, and whether it should be stored again (it is plain and
    /// there is a real sealer now, or it was sealed under an older key).
    fn unpack(&self, stored: &[u8], account: i64) -> Result<(Secret, bool), MfaError> {
        let bad = || MfaError::fault(anyhow::anyhow!("a stored TOTP secret in an unknown format"));
        let (plain, reseal) = match stored.first().copied() {
            Some(0) if self.sealer.is_plaintext() || self.accept_plaintext => {
                if self.sealer.is_plaintext() {
                    refuse_unsealed()?;
                }
                (
                    Zeroizing::new(stored[1..].to_vec()),
                    !self.sealer.is_plaintext(),
                )
            }
            Some(1) if !self.sealer.is_plaintext() => {
                let len = usize::from(*stored.get(1).ok_or_else(bad)?);
                let id = stored.get(2..2 + len).ok_or_else(bad)?;
                let id = std::str::from_utf8(id).map_err(|_| bad())?;
                let sealed = stored.get(2 + len..).ok_or_else(bad)?;
                let plain = self
                    .sealer
                    .open(id, sealed, &Self::context(account))
                    .map_err(MfaError::fault)?;
                (Zeroizing::new(plain), id != self.sealer.key_id())
            }
            _ => return Err(bad()),
        };
        let secret = Secret::from_bytes(&plain).ok_or_else(|| {
            MfaError::fault(anyhow::anyhow!("a stored TOTP secret of a bad length"))
        })?;
        Ok((secret, reseal))
    }

    /// Store `secret` again under the current sealer, if `stored` is still what the row
    /// holds. Best effort: the next use tries again.
    pub(crate) async fn reseal(&self, pool: &PgPool, account: i64, stored: &[u8], secret: &Secret) {
        let Ok(packed) = self.pack(secret, account) else {
            return;
        };
        let done = sqlx::query(
            "UPDATE account_totp SET secret = $3 WHERE account_id = $1 AND secret = $2",
        )
        .bind(account)
        .bind(stored)
        .bind(&packed)
        .execute(pool)
        .await;
        if let Err(e) = done {
            tracing::warn!(error = %e, "a TOTP secret could not be resealed");
        }
    }

    pub(crate) fn open(&self, stored: &[u8], account: i64) -> Result<(Secret, bool), MfaError> {
        self.unpack(stored, account)
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
        let account = store::by_id_in_epoch(
            pool,
            pending.account,
            pending.epoch,
            session.id().as_deref(),
        )
        .await?;
        Ok(account.map(|a| (a, pending.kind)))
    }

    /// The factors `account` holds.
    ///
    /// # Errors
    /// The database.
    pub async fn factors(&self, pool: &PgPool, account: i64) -> sqlx::Result<Factors> {
        let (confirmed_at, locked, left): (Option<i64>, bool, i64) = sqlx::query_as(
            "SELECT
               (SELECT EXTRACT(EPOCH FROM confirmed_at)::bigint FROM account_totp
                 WHERE account_id = $1 AND confirmed_at IS NOT NULL),
               COALESCE((SELECT locked_until > now() FROM account_totp
                 WHERE account_id = $1 AND confirmed_at IS NOT NULL), false),
               (SELECT count(*) FROM account_recovery_codes
                 WHERE account_id = $1 AND used_at IS NULL)",
        )
        .bind(account)
        .fetch_one(pool)
        .await?;
        Ok(Factors {
            totp_confirmed_at: confirmed_at,
            recovery_codes_left: left,
            totp_locked: locked,
        })
    }

    /// Whether the session may change `account`'s factors now, as a [`ChangeProof`] every
    /// change asks for:
    ///
    /// * the session is signed in as `account`, which has a factor: a second factor must
    ///   have been used within `max_age` ([`require_recent_mfa`]; a recovery code counts);
    /// * signed in, no factor yet (the first enrollment): a recent sign-in
    ///   ([`require_recent`]);
    /// * holding the pending [`Kind::Enroll`] of `account`: allowed. The proof is then
    ///   marked pending and the events of the enrollment carry `while_pending`.
    ///
    /// # Errors
    /// [`MfaError::StepUp`] (send the person to re-authenticate), [`MfaError::NoChallenge`]
    /// if the session is neither, or the database.
    pub async fn authorize_change<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
        max_age: Duration,
    ) -> Result<ChangeProof, MfaError> {
        let entry = challenge::Entry::of(session, account, self.pending_ttl, SystemTime::now())
            .ok_or(MfaError::NoChallenge)?;
        let pending = match entry {
            challenge::Entry::Enroll => true,
            challenge::Entry::Signed => {
                if self.factors(pool, account.id).await?.any() {
                    require_recent_mfa(session, max_age)?;
                } else {
                    require_recent(session, max_age)?;
                }
                false
            }
        };
        Ok(ChangeProof {
            account: account.id,
            pending,
        })
    }

    fn proof_for(proof: &ChangeProof, account: &Account) -> Result<(), MfaError> {
        if proof.account == account.id {
            Ok(())
        } else {
            Err(MfaError::NoChallenge)
        }
    }

    /// Begin setting up an authenticator for `account`: a fresh secret, stored
    /// unconfirmed (it signs nobody in), and the forms to show it in. Calling again
    /// before a code is confirmed replaces the secret.
    ///
    /// # Errors
    /// [`MfaError::AlreadyEnrolled`] (remove the old one first), or a fault.
    pub async fn begin_totp(
        &self,
        pool: &PgPool,
        account: &Account,
        proof: &ChangeProof,
    ) -> Result<TotpEnrollment, MfaError> {
        Self::proof_for(proof, account)?;
        let secret = Secret::generate().map_err(MfaError::fault)?;
        let stored = sqlx::query(
            "INSERT INTO account_totp (account_id, secret) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE
               SET secret = EXCLUDED.secret, last_step = NULL, created_at = now()
               WHERE account_totp.confirmed_at IS NULL",
        )
        .bind(account.id)
        .bind(self.pack(&secret, account.id)?)
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
            qr_svg: Zeroizing::new(qr_svg),
        })
    }

    /// Confirm the authenticator `begin_totp` started with the first `code` it shows.
    /// The authenticator then challenges every sign-in, and the recovery codes are made
    /// (replacing any earlier set) and returned **once**.
    ///
    /// The account's session epoch moves on: every *other* session of it ends at its next
    /// request (one an attacker held does not outlive the owner's enrollment), and this
    /// session is resealed under the new epoch with the factor recorded. A pending
    /// enrollment ([`Kind::Enroll`]) is signed in now ([`Confirmed::next`] is
    /// [`Next::Done`]); its events have `while_pending` set, and the owner should be
    /// emailed.
    ///
    /// # Errors
    /// [`MfaError::Invalid`] for a wrong code, [`MfaError::NotEnrolling`] if none was
    /// begun, or a fault.
    pub async fn confirm_totp<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
        proof: &ChangeProof,
        code: &str,
    ) -> Result<Confirmed, MfaError> {
        Self::proof_for(proof, account)?;
        let now = SystemTime::now();
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret FROM account_totp WHERE account_id = $1 AND confirmed_at IS NULL",
        )
        .bind(account.id)
        .fetch_optional(pool)
        .await?;
        let (stored,) = row.ok_or(MfaError::NotEnrolling)?;
        let (secret, _) = self.open(&stored, account.id)?;
        let step = totp::verify(&secret, code, now, None).ok_or(MfaError::Invalid)?;
        let codes = recovery::generate(self.recovery_codes)
            .await
            .map_err(MfaError::fault)?;

        let mut tx = pool.begin().await?;
        // Confirm only the secret that was checked: a begin between the read and here
        // replaced it.
        let confirmed = sqlx::query(
            "UPDATE account_totp SET confirmed_at = now(), last_step = $2,
                    failed_attempts = 0, locked_until = NULL
             WHERE account_id = $1 AND confirmed_at IS NULL AND secret = $3",
        )
        .bind(account.id)
        .bind(i64::try_from(step).map_err(|e| MfaError::fault(e.into()))?)
        .bind(&stored)
        .execute(&mut *tx)
        .await?;
        if confirmed.rows_affected() == 0 {
            return Err(MfaError::NotEnrolling);
        }
        replace_codes(&mut tx, account.id, &codes).await?;
        let epoch = bump_epoch(&mut tx, account.id, account.session_epoch).await?;
        tx.commit().await?;

        let account_now = Account {
            session_epoch: epoch,
            ..account.clone()
        };
        let next = if proof.pending {
            session::sign_in(session, &account_now);
            state::record(session, &account_now, true, now);
            store::signed_in(pool, account.id).await?;
            Next::Done
        } else {
            state::reseal(session, &account_now, account.session_epoch, true, now);
            Next::Done
        };
        let event = |kind| Event {
            while_pending: proof.pending,
            ..Event::new(account.id, kind)
        };
        Ok(Confirmed {
            recovery_codes: codes,
            next,
            events: vec![
                event(EventKind::Enrolled(Factor::Totp)),
                event(EventKind::RecoveryCodesIssued),
            ],
        })
    }

    /// Replace the account's recovery codes with new ones, returned **once**. Needs an
    /// authenticator (the codes are its backup). Moves the session epoch on and reseals
    /// this session, as [`confirm_totp`](Self::confirm_totp) does.
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`], or a fault.
    pub async fn regenerate_recovery_codes<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
        proof: &ChangeProof,
    ) -> Result<(Vec<Recovery>, Event), MfaError> {
        Self::proof_for(proof, account)?;
        if proof.pending || !self.factors(pool, account.id).await?.any() {
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
        let epoch = bump_epoch(&mut tx, account.id, account.session_epoch).await?;
        tx.commit().await?;
        let account_now = Account {
            session_epoch: epoch,
            ..account.clone()
        };
        state::reseal(
            session,
            &account_now,
            account.session_epoch,
            false,
            SystemTime::now(),
        );
        Ok((
            codes,
            Event::new(account.id, EventKind::RecoveryCodesIssued),
        ))
    }

    /// Remove the authenticator and the recovery codes behind it. Refused with
    /// [`MfaError::LastFactor`] when the policy requires `account` to have a factor and
    /// this is its last. Moves the session epoch on (other sessions end) and reseals
    /// this one. Tell the owner.
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`], [`MfaError::LastFactor`], or a fault.
    pub async fn remove_totp<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
        proof: &ChangeProof,
    ) -> Result<Event, MfaError> {
        Self::proof_for(proof, account)?;
        if proof.pending {
            return Err(MfaError::NotEnrolled);
        }
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
            // An enrollment never confirmed is not a factor: there is nothing to remove.
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
        let epoch = bump_epoch(&mut tx, account.id, account.session_epoch).await?;
        tx.commit().await?;
        let account_now = Account {
            session_epoch: epoch,
            ..account.clone()
        };
        state::reseal(
            session,
            &account_now,
            account.session_epoch,
            false,
            SystemTime::now(),
        );
        Ok(Event::new(account.id, EventKind::Removed(Factor::Totp)))
    }

    /// Unlock the authenticator after too many wrong codes ([`LOCK_AFTER`]): for staff
    /// answering the owner. (A recovery code unlocks it by itself.)
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`] if there is no authenticator, or a fault.
    pub async fn unlock_totp(&self, pool: &PgPool, account: i64) -> Result<Event, MfaError> {
        let done = sqlx::query(
            "UPDATE account_totp SET failed_attempts = 0, locked_until = NULL
             WHERE account_id = $1 AND confirmed_at IS NOT NULL",
        )
        .bind(account)
        .execute(pool)
        .await?;
        if done.rows_affected() == 0 {
            return Err(MfaError::NotEnrolled);
        }
        Ok(Event::new(account, EventKind::Unlocked(Factor::Totp)))
    }

    /// What follows a checked first factor (a password, a sign-in link, a provider's
    /// sign-in) for `account`: it is signed in, or its sign-in is made pending on a
    /// second factor, or on enrollment. The password sign-in below does this; the layer
    /// ([`Accounts::require_mfa`](crate::Accounts::require_mfa)) does it for a session
    /// signed in any other way.
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
        let has = self.factors(pool, account.id).await?.any();
        let Some(kind) = self.pending_kind(account, has) else {
            session::sign_in(session, account);
            state::record(session, account, false, now);
            store::signed_in(pool, account.id).await?;
            return Ok(Next::Done);
        };
        Self::make_pending(session, account, kind, now);
        Ok(match kind {
            Kind::Enroll => Next::Enroll,
            _ => Next::Challenge,
        })
    }

    /// What `account` must pass before it is signed in, given whether it `has` a factor.
    fn pending_kind(&self, account: &Account, has: bool) -> Option<Kind> {
        if has {
            Some(Kind::Challenge)
        } else if self.requires(account) {
            Some(Kind::Enroll)
        } else {
            None
        }
    }

    /// Make the session a pending sign-in: a new id, no signature.
    fn make_pending<T: MfaSession>(
        session: &Session<T>,
        account: &Account,
        kind: Kind,
        now: SystemTime,
    ) {
        let pending = Pending {
            account: account.id,
            epoch: account.session_epoch,
            at: state::unix(now),
            kind,
        };
        session.cycle_id();
        session.update(|d| {
            d.set_signature(None);
            *d.mfa_mut() = State {
                pending: Some(pending),
                auth: None,
            };
        });
    }

    /// The layer's question about a request that carries a signature for `account`:
    /// whether it may stand as signed in. It may if the session shows a second factor
    /// passed for this account and epoch, or if the account has none and the policy does
    /// not require one. Otherwise the session becomes the pending sign-in it should have
    /// been (so a challenge or enrollment form can follow), and the request is
    /// anonymous. `Ok(Some(has_factor))` when it stands.
    pub(crate) async fn gate<T: MfaSession>(
        &self,
        pool: &PgPool,
        session: &Session<T>,
        account: &Account,
    ) -> sqlx::Result<Option<bool>> {
        let passed = session.read(|d| {
            d.signature()
                .and_then(|s| state::auth_for(d.mfa(), s))
                .is_some_and(|a| a.mfa_at.is_some())
        });
        if passed {
            return Ok(Some(true));
        }
        let has = self.factors(pool, account.id).await?.any();
        match self.pending_kind(account, has) {
            None => Ok(Some(false)),
            Some(kind) => {
                Self::make_pending(session, account, kind, SystemTime::now());
                Ok(None)
            }
        }
    }

    /// The password sign-in with a second factor: charge `limiter` for `login` from
    /// `ip`, check the password only if it allows ([`store::check_password`], which does
    /// not stamp `last_sign_in`: that waits for the second factor), then
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
        limiter
            .charge(ip, Key::Login(login))
            .await
            .map_err(|t| match t {
                Throttled::Spent => SignInRefused::Throttled,
                Throttled::Unavailable => SignInRefused::Unavailable,
            })?;
        let account = store::check_password(pool, login, password)
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

/// Move the account's session epoch on from `old`, in `tx`; the new one. Nothing moves, and
/// the change is refused, if the epoch is no longer `old` or the account is no longer
/// active: the session making the change was revoked meanwhile (signed out everywhere, a
/// deactivation), and must not come out of it with a fresh epoch, codes, or a factor.
async fn bump_epoch(tx: &mut sqlx::PgConnection, account: i64, old: i32) -> Result<i32, MfaError> {
    let new: Option<i32> = sqlx::query_scalar(
        "UPDATE accounts SET session_epoch = session_epoch + 1
         WHERE id = $1 AND session_epoch = $2 AND is_active RETURNING session_epoch",
    )
    .bind(account)
    .bind(old)
    .fetch_optional(tx)
    .await?;
    new.ok_or(MfaError::NoChallenge)
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
