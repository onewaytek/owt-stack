//! Passkeys (Web Authentication) as a second factor and as a step-up proof.
//!
//! A passkey is a key pair an authenticator (a phone, a laptop's platform authenticator,
//! a security key) makes for this site and keeps; the site stores the public half in
//! `account_passkeys` and checks a signature over a fresh challenge at each use. The
//! ceremonies are webauthn-rs's (`webauthn-rs` 0.6, on `RustCrypto`, with no `OpenSSL`).
//!
//! * **The site is named in configuration** (`RelyingParty`): the relying-party id (a
//!   domain, `example.com`) and the origins the browser may report
//!   (`https://example.com`). A passkey works only on the id it was made for, so
//!   choose it once. `RelyingParty::from_env` reads `PASSKEY_RP_ID`,
//!   `PASSKEY_ORIGIN` and `PASSKEY_RP_NAME`; `Mfa::passkeys`
//!   turns passkeys on.
//! * **Ceremony state stays on the server.** Beginning a registration or an
//!   authentication stores webauthn-rs's state in `account_passkey_ceremonies`, bound
//!   to the account, the purpose and the session that began it, and hands the browser
//!   the options and an opaque token (`Ceremony`). Finishing deletes the row as it
//!   reads it, so a challenge answers once, and only from the session that began it
//!   (a token carried to another browser is refused); it expires after five minutes.
//! * **A passkey is a factor like the authenticator app**: registering one needs a
//!   [`ChangeProof`](super::ChangeProof), the first factor of an account issues its
//!   recovery codes, removing one needs step-up, and the last factor of an account the
//!   policy requires cannot be removed. Every change moves the account's session epoch
//!   on and returns [`Event`](super::Event)s.
//! * **A counter that does not rise past the stored one is refused**
//!   ([`MfaError::PasskeyCloned`]), checked against the row as it stands when the
//!   answer arrives, not as it stood when the ceremony began: it means the credential
//!   may exist twice. (A synced passkey reports no counter, so this never applies to
//!   it.) The passkey is disabled there and then: it is no longer offered, accepted or
//!   counted as a factor, and the settings page shows it as a suspected copy until its
//!   owner removes it. Every session of the account ends with it (the session epoch
//!   moves on in the same transaction), so a session the copy opened ends too. The error carries an event for the audit log
//!   ([`MfaError::event`]), and the same event goes to the notifier
//!   ([`Mfa::on_security_event`](super::Mfa::on_security_event)) to tell the owner.
//!
//! **The ceremonies need the `passkeys` cargo feature**, which builds `webauthn-rs`:
//! `RelyingParty`, `Ceremony`, `Mfa::passkeys` and the begin and finish functions
//! exist only with it. Without it this module keeps what reads and edits the
//! `account_passkeys` table ([`PasskeyInfo`], [`Mfa::list_passkeys`],
//! [`Mfa::rename_passkey`], [`Mfa::remove_passkey`]), so the factor counts, the
//! settings page and the view models are the same in either build, and a build with
//! the feature off behaves as one with it on and no `Mfa::passkeys` call.

use sqlx::PgPool;

use super::{ChangeProof, Event, EventKind, Factor, Mfa, MfaError, state};
use crate::store::Account;

#[cfg(feature = "passkeys")]
mod ceremony;
#[cfg(feature = "passkeys")]
pub use ceremony::{
    CEREMONY_TTL, Ceremony, CreationChallengeResponse, PublicKeyCredential,
    RegisterPublicKeyCredential, RelyingParty, RelyingPartyError, RequestChallengeResponse, Url,
};

/// The longest name a passkey may be given, in characters.
pub const NAME_MAX: usize = 64;

/// A passkey of an account, for its settings page.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
#[non_exhaustive]
pub struct PasskeyInfo {
    /// Its row id, which rename and remove take.
    pub id: i64,
    /// The name the person gave it.
    pub name: String,
    /// When it was registered, in Unix seconds.
    pub created_at: i64,
    /// When it last signed in or re-authenticated, in Unix seconds.
    pub last_used_at: Option<i64>,
    /// The authenticator may sync it to other devices (a synced passkey).
    pub backup_eligible: bool,
    /// It is synced (backed up) now.
    pub backup_state: bool,
    /// When it was disabled as a suspected copy ([`MfaError::PasskeyCloned`]), in Unix
    /// seconds: a disabled passkey is no factor until it is removed.
    pub disabled_at: Option<i64>,
}

/// A passkey name as given: trimmed, one to [`NAME_MAX`] characters, no control
/// characters.
fn clean_name(name: &str) -> Result<&str, MfaError> {
    let name = name.trim();
    let count = name.chars().count();
    if count == 0 || count > NAME_MAX || name.chars().any(char::is_control) {
        return Err(MfaError::BadName);
    }
    Ok(name)
}

impl Mfa {
    /// Passkeys are on: the `passkeys` feature is built and `Mfa::passkeys` named
    /// the site.
    #[cfg(feature = "passkeys")]
    pub(crate) fn passkeys_on(&self) -> bool {
        self.passkeys.is_some()
    }

    /// Passkeys are on: never, without the `passkeys` feature.
    #[cfg(not(feature = "passkeys"))]
    #[expect(clippy::unused_self, reason = "the same signature as with the feature")]
    pub(crate) fn passkeys_on(&self) -> bool {
        false
    }

    /// The account's passkeys, oldest first, the disabled ones included.
    ///
    /// # Errors
    /// A database fault.
    pub async fn list_passkeys(
        &self,
        pool: &PgPool,
        account: i64,
    ) -> sqlx::Result<Vec<PasskeyInfo>> {
        sqlx::query_as(
            "SELECT id, name, EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
                    EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at,
                    backup_eligible, backup_state,
                    EXTRACT(EPOCH FROM disabled_at)::bigint AS disabled_at
             FROM account_passkeys WHERE account_id = $1 ORDER BY id",
        )
        .bind(account)
        .fetch_all(pool)
        .await
    }

    /// Rename one of the account's passkeys. A name is a label, so this needs no
    /// step-up; it needs the account (the one signed in).
    ///
    /// # Errors
    /// [`MfaError::BadName`], [`MfaError::NotEnrolled`] when the account has no such
    /// passkey, or a fault.
    pub async fn rename_passkey(
        &self,
        pool: &PgPool,
        account: &Account,
        passkey: i64,
        name: &str,
    ) -> Result<Event, MfaError> {
        let name = clean_name(name)?;
        let done =
            sqlx::query("UPDATE account_passkeys SET name = $3 WHERE id = $1 AND account_id = $2")
                .bind(passkey)
                .bind(account.id)
                .bind(name)
                .execute(pool)
                .await?;
        if done.rows_affected() == 0 {
            return Err(MfaError::NotEnrolled);
        }
        Ok(Event {
            passkey: Some(passkey),
            ..Event::new(account.id, EventKind::Renamed(Factor::Passkey))
        })
    }

    /// Remove one of the account's passkeys. As with [`remove_totp`](Self::remove_totp):
    /// it needs a [`ChangeProof`] from a signed-in session, the account's last factor
    /// cannot be removed when the policy requires one ([`MfaError::LastFactor`]), the
    /// last factor takes the recovery codes with it, and the session epoch moves on.
    ///
    /// # Errors
    /// [`MfaError::NotEnrolled`] when the account has no such passkey,
    /// [`MfaError::LastFactor`], [`MfaError::NoChallenge`], or a fault.
    pub async fn remove_passkey<T: state::MfaSession>(
        &self,
        pool: &PgPool,
        session: &owt_web::session::Session<T>,
        account: &Account,
        proof: &ChangeProof,
        passkey: i64,
    ) -> Result<Event, MfaError> {
        Self::proof_for(proof, account)?;
        if proof.pending {
            return Err(MfaError::NotEnrolled);
        }
        let mut tx = pool.begin().await?;
        lock_account(&mut tx, account.id).await?;
        let usable: Option<bool> = sqlx::query_scalar(
            "SELECT disabled_at IS NULL FROM account_passkeys WHERE id = $1 AND account_id = $2",
        )
        .bind(passkey)
        .bind(account.id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(usable) = usable else {
            return Err(MfaError::NotEnrolled);
        };
        // A disabled passkey is no factor, so removing it is never removing the last
        // one; the codes go when no passkey or authenticator of any kind is left.
        let count = factor_count(&mut tx, account.id).await?;
        if usable && count <= 1 && self.requires(account) {
            return Err(MfaError::LastFactor);
        }
        let last = count + disabled_count(&mut tx, account.id).await? <= 1;
        sqlx::query("DELETE FROM account_passkeys WHERE id = $1")
            .bind(passkey)
            .execute(&mut *tx)
            .await?;
        if last {
            sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
                .bind(account.id)
                .execute(&mut *tx)
                .await?;
        }
        let epoch = super::bump_epoch(&mut tx, account.id, account.session_epoch).await?;
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
            std::time::SystemTime::now(),
        );
        Ok(Event {
            passkey: Some(passkey),
            ..Event::new(account.id, EventKind::Removed(Factor::Passkey))
        })
    }
}

/// Hold the account's row for the rest of the transaction, so two changes to its
/// factors (removing the last two at once, say) are made one after the other.
pub(super) async fn lock_account(
    tx: &mut sqlx::PgConnection,
    account: i64,
) -> Result<(), MfaError> {
    let held: Option<i64> = sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .fetch_optional(tx)
        .await?;
    held.map(|_| ()).ok_or(MfaError::NoChallenge)
}

/// How many passkeys of the account are disabled.
pub(super) async fn disabled_count(
    tx: &mut sqlx::PgConnection,
    account: i64,
) -> Result<i64, MfaError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_passkeys WHERE account_id = $1 AND disabled_at IS NOT NULL",
    )
    .bind(account)
    .fetch_one(tx)
    .await?;
    Ok(n)
}

/// How many factors the account has: a confirmed authenticator and its passkeys that
/// are not disabled.
pub(super) async fn factor_count(
    tx: &mut sqlx::PgConnection,
    account: i64,
) -> Result<i64, MfaError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM account_totp
                 WHERE account_id = $1 AND confirmed_at IS NOT NULL)
              + (SELECT count(*) FROM account_passkeys
                 WHERE account_id = $1 AND disabled_at IS NULL)",
    )
    .bind(account)
    .fetch_one(tx)
    .await?;
    Ok(n)
}
