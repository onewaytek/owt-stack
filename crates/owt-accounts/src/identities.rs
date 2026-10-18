//! Provider identities linked to accounts: what an OAuth sign-in resolves to.
//!
//! [`owt_auth::oauth`] gets the [`Identity`] from the provider; [`arrive`] turns it
//! into an account, by the app's [`Welcome`] policy. Linking a second provider to a
//! signed-in account, listing them and unlinking are here too.
//!
//! An identity is found by its provider's [`key`](Provider::key) and subject alone.
//! Its email never finds an account: the address can change at the provider and pass
//! to someone else, so an unlinked identity whose verified email matches an account
//! is still a stranger to it. The only way to add a provider to an existing account
//! is [`link`], from a session already signed in to that account.
//!
//! An app that vouches for a person itself (its own check, a device it enrolled, a
//! system account its jobs act as) reaches the account with [`arrive_as`], by a key
//! and subject of its own, with no provider.

use owt_auth::oauth::{Identity, Provider};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

use crate::store::{self, Account, New};
use crate::{Refused, Result};

/// A row of `account_identities`.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Linked {
    /// The row's id; what an unlink names.
    pub id: i64,
    /// The account it signs in.
    pub account_id: i64,
    /// The provider's [`key`](Provider::key): `google`, `discord`, or an OIDC
    /// issuer's URL.
    pub provider: String,
    /// The provider's stable id for the person.
    pub subject: String,
    /// The provider's user-info response at the last sign-in.
    pub claims: Value,
}

impl Linked {
    /// Something to show for it: the email (unless the provider says it is
    /// unverified, when anyone could have typed it), name or handle the claims carry,
    /// else the subject.
    #[must_use]
    pub fn label(&self) -> &str {
        // Some providers send the flag as a string ("false").
        let unverified = [&self.claims["email_verified"], &self.claims["verified"]]
            .iter()
            .any(|v| v.as_bool() == Some(false) || v.as_str() == Some("false"));
        [
            if unverified { "" } else { "email" },
            "name",
            "display_name",
            "preferred_username",
            "username",
            "login",
        ]
        .iter()
        .find_map(|k| self.claims.get(k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .unwrap_or(&self.subject)
    }
}

/// The identity `provider` knows as `subject`, if it is linked.
pub async fn find(
    db: impl PgExecutor<'_>,
    provider: &Provider,
    subject: &str,
) -> sqlx::Result<Option<Linked>> {
    sqlx::query_as::<_, Linked>(
        "SELECT id, account_id, provider, subject, claims FROM account_identities WHERE provider = $1 AND subject = $2"
    )
    .bind(provider.key())
    .bind(subject)
    .fetch_optional(db)
    .await
}

/// The identities linked to an account, oldest first.
pub async fn list(db: impl PgExecutor<'_>, account_id: i64) -> sqlx::Result<Vec<Linked>> {
    sqlx::query_as::<_, Linked>(
        "SELECT id, account_id, provider, subject, claims FROM account_identities WHERE account_id = $1 ORDER BY id"
    )
    .bind(account_id)
    .fetch_all(db)
    .await
}

/// Link `identity`, which `provider` just vouched for, to `account_id`. Call it only
/// for the account the session is signed in to: this is how a person adds a provider.
/// Already linked there: the claims are refreshed. Linked to another account:
/// [`Refused::IdentityTaken`]. No subject: [`Refused::NoSubject`].
pub async fn link(
    db: impl PgExecutor<'_>,
    account_id: i64,
    provider: &Provider,
    identity: &Identity,
) -> Result<Linked> {
    if identity.uid.is_empty() {
        return Err(Refused::NoSubject.into());
    }
    let linked = sqlx::query_as::<_, Linked>(
        "INSERT INTO account_identities (account_id, provider, subject, claims)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (provider, subject) DO UPDATE
            SET claims = EXCLUDED.claims, last_sign_in = now()
            WHERE account_identities.account_id = EXCLUDED.account_id
         RETURNING id, account_id, provider, subject, claims",
    )
    .bind(account_id)
    .bind(provider.key())
    .bind(&identity.uid)
    .bind(&identity.extra)
    .fetch_optional(db)
    .await?;
    // No row back: the conflict's WHERE excluded it, so another account holds it.
    linked.ok_or_else(|| Refused::IdentityTaken.into())
}

/// Unlink identity `id` from `account_id`. Refused when it is the account's only
/// way in (no password, no other identity, no local identity); `false` when no such
/// link exists.
///
/// Two unlinks at once are serialized on the account's row, and each counts the
/// identities only once it holds it: counted in the statement that waited, the
/// second would see the first's identity still there, and both would go.
pub async fn unlink(pool: &PgPool, account_id: i64, id: i64) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let done = unlink_in(&mut tx, account_id, id).await?;
    tx.commit().await?;
    Ok(done)
}

/// [`unlink`], inside the caller's transaction (which it locks the account's row in).
pub(crate) async fn unlink_in(
    tx: &mut sqlx::PgConnection,
    account_id: i64,
    id: i64,
) -> Result<bool> {
    let Some(has_password) = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
        "SELECT {} FROM accounts WHERE id = $1 FOR UPDATE",
        store::USABLE_PASSWORD
    )))
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(false);
    };
    // A statement after the lock reads what committed before it was granted.
    let (theirs, count) = sqlx::query_as::<_, (bool, i64)>(
        "SELECT EXISTS (SELECT 1 FROM account_identities WHERE id = $2 AND account_id = $1),
                (SELECT count(*) FROM account_identities WHERE account_id = $1)
                + (SELECT count(*) FROM account_local_identities WHERE account_id = $1)",
    )
    .bind(account_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if !theirs {
        return Ok(false);
    }
    if !has_password && count <= 1 {
        return Err(Refused::LastWayIn.into());
    }
    let done = sqlx::query("DELETE FROM account_identities WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// What an app lets a provider sign-in do when the identity is new.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Welcome {
    /// An identity linked to nothing creates an account. Off: the sign-in is refused
    /// as [`Arrival::Unknown`], for an app with no self-signup.
    pub create: bool,
    /// A created account takes the provider's verified email as its own, which is a
    /// sign-in name (with a password) and unique. Off (the default), the address
    /// stays in the identity's claims only: an issuer that vouches loosely could
    /// otherwise give a stranger an address its owner has yet to register, and the
    /// owner's sign-up would find it taken. Turn it on only for providers whose
    /// verification the app trusts.
    pub record_email: bool,
}

/// How a provider sign-in resolved. An outcome may be added without a breaking release, so a
/// `match` on it ends with a `_` arm; [`Arrival::account`] answers for all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Arrival {
    /// The identity was linked already.
    Known(Account),
    /// An account was created for it, with a username made from the identity (or,
    /// by [`arrive_as`], from the name the app gave).
    Created(Account),
    /// Nothing matched and the policy creates nothing.
    Unknown,
}

impl Arrival {
    /// The account, when the arrival signs one in.
    #[must_use]
    pub fn account(&self) -> Option<&Account> {
        match self {
            Self::Known(a) | Self::Created(a) => Some(a),
            Self::Unknown => None,
        }
    }
}

/// The stored provider keys no configured provider has, with how many identities
/// each holds: rows no sign-in can reach. An app checks it at start and refuses to
/// serve while it is not empty, since a person whose identity is stored under a key
/// the app no longer uses is a stranger at their next sign-in (a second, empty
/// account with self-signup on). [`rekey`] moves them.
pub async fn unconfigured(
    db: impl PgExecutor<'_>,
    providers: &[&Provider],
) -> sqlx::Result<Vec<(String, i64)>> {
    let keys: Vec<&str> = providers.iter().map(|p| p.key()).collect();
    sqlx::query_as::<_, (String, i64)>(
        "SELECT provider, count(*) FROM account_identities
         WHERE provider <> ALL($1) GROUP BY provider ORDER BY provider",
    )
    .bind(&keys)
    .fetch_all(db)
    .await
}

/// What [`rekey`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rekeyed {
    /// Identities moved to the new key.
    pub moved: u64,
    /// Subjects left under the old key because the new key has them already: the
    /// person signed in after the deploy and before the rekey, so has two accounts.
    /// Which one to keep is a person's decision; the old one is untouched.
    pub conflicts: Vec<String>,
}

/// Why [`rekey`] refused. A reason may be added without a breaking release, so a `match` on
/// it ends with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RekeyError {
    /// `from` is `to`'s key already: there is nothing to move.
    #[error("the identities are under {0} already")]
    SameKey(String),
    /// `from` is a key a configured provider still gives: its people would become the
    /// other provider's, and a matching subject there would sign in as them.
    #[error("{0} is still a configured provider's key")]
    InUse(String),
    /// The database.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Move the identities stored under `from`, a key no configured provider gives (an
/// OIDC provider's id `sso`, say, where the key is its issuer), to `to`'s
/// [`key`](Provider::key). Run it before serving with `to`, naming in `configured`
/// every provider the app has: a `from` one of them gives is refused.
///
/// # Errors
///
/// [`RekeyError`].
pub async fn rekey(
    pool: &PgPool,
    from: &str,
    to: &Provider,
    configured: &[&Provider],
) -> std::result::Result<Rekeyed, RekeyError> {
    if from == to.key() {
        return Err(RekeyError::SameKey(from.to_owned()));
    }
    if configured.iter().any(|p| p.key() == from) {
        return Err(RekeyError::InUse(from.to_owned()));
    }
    let mut tx = pool.begin().await?;
    let moved = sqlx::query(
        "UPDATE account_identities old SET provider = $2
         WHERE old.provider = $1 AND NOT EXISTS (
            SELECT 1 FROM account_identities new
            WHERE new.provider = $2 AND new.subject = old.subject)",
    )
    .bind(from)
    .bind(to.key())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // Only the subjects the new key holds: a row an older replica wrote under the old
    // key meanwhile is moved by the next call (and `unconfigured` reports it).
    let conflicts = sqlx::query_scalar(
        "SELECT old.subject FROM account_identities old
         JOIN account_identities new ON new.provider = $2 AND new.subject = old.subject
         WHERE old.provider = $1 ORDER BY old.subject",
    )
    .bind(from)
    .bind(to.key())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Rekeyed { moved, conflicts })
}

/// The first key of the advisory lock [`arrive`] takes per identity (the second is a
/// hash of the identity). Two-key advisory locks do not overlap one-key ones, so an
/// app's own `pg_advisory_lock(bigint)` cannot contend with it.
const ARRIVAL_LOCK: i32 = 0x6f77_7401;

/// Resolve a provider's identity to an account, per `welcome`: by its subject, never
/// its email. Refreshes the identity's claims. A deactivated account resolves to
/// [`Arrival::Unknown`]; an identity with an empty subject is [`Refused::NoSubject`].
/// An account it resolves to has its `last_sign_in` stamped ([`store::signed_in`]),
/// before the identity is touched: the order an unlink locks them in. In the caller's
/// transaction ([`arrive_in`]) the account's row stays locked until it ends.
///
/// One transaction, under a lock on the identity: two first sign-ins with it at once
/// (a callback opened twice) resolve to one account, the second finding what the
/// first created, rather than leaving an account no identity reaches.
pub async fn arrive(
    pool: &PgPool,
    provider: &Provider,
    identity: &Identity,
    welcome: Welcome,
) -> Result<Arrival> {
    arrive_in(&mut *pool.acquire().await?, provider, identity, welcome).await
}

/// [`arrive`] on `conn`: inside the caller's transaction, say, so that what the app
/// does with the account (keeping the provider's tokens) commits with the arrival or
/// not at all. In a transaction it works in a savepoint, so an error or refusal
/// undoes only its own writes, and the lock on the identity is held until the
/// caller's transaction ends.
pub async fn arrive_in(
    conn: &mut sqlx::PgConnection,
    provider: &Provider,
    identity: &Identity,
    welcome: Welcome,
) -> Result<Arrival> {
    if identity.uid.is_empty() {
        return Err(Refused::NoSubject.into());
    }
    let mut tx = sqlx::Connection::begin(conn).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(ARRIVAL_LOCK)
        .bind(format!("{}\n{}", provider.key(), identity.uid))
        .execute(&mut *tx)
        .await?;
    let arrival = if let Some(linked) = find(&mut *tx, provider, &identity.uid).await? {
        // The account before the identity, the order an unlink locks them in. An
        // unlink that held it has removed the identity by now, and the refresh finds
        // nothing: the identity reaches nothing, and is not linked again.
        lock_account(&mut tx, linked.account_id).await?;
        let refreshed = sqlx::query(
            "UPDATE account_identities SET claims = $4, last_sign_in = now()
             WHERE provider = $1 AND subject = $2 AND account_id = $3",
        )
        .bind(provider.key())
        .bind(&identity.uid)
        .bind(linked.account_id)
        .bind(&identity.extra)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        match store::by_id(&mut *tx, linked.account_id).await? {
            Some(account) if refreshed => {
                store::signed_in(&mut *tx, account.id).await?;
                Arrival::Known(account)
            }
            _ => Arrival::Unknown,
        }
    } else if welcome.create {
        let email = identity.email.as_deref().unwrap_or("");
        // Only a verified email is worth recording, and only when the app trusts the
        // provider's word for it; an account holding it already keeps it, and
        // learns nothing of this sign-in.
        let email = if welcome.record_email
            && identity.email_verified
            && store::by_email(&mut *tx, email).await?.is_none()
        {
            email
        } else {
            ""
        };
        let account = create_for(&mut tx, &username_base(identity), email).await?;
        store::signed_in(&mut *tx, account.id).await?;
        link(&mut *tx, account.id, provider, identity).await?;
        Arrival::Created(account)
    } else {
        Arrival::Unknown
    };
    tx.commit().await?;
    Ok(arrival)
}

/// Lock the account's row as an arrival changes it, before its identity's: the
/// order an unlink and a retirement take them in.
async fn lock_account(tx: &mut Transaction<'_, Postgres>, id: i64) -> sqlx::Result<()> {
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The first key of the advisory lock [`arrive_as`] takes per local identity.
const LOCAL_ARRIVAL_LOCK: i32 = 0x6f77_7402;

/// Resolve the account an app knows as `subject` under `key`, a namespace of the
/// app's own (`kiosk`, `system`): for a person or a process the app vouches for
/// itself, with no provider. Local identities are kept apart from providers' (no
/// provider's subject matches one, and [`list`], [`unconfigured`] and the
/// connections page never show one).
///
/// Linked already: [`Arrival::Known`] (a deactivated account is
/// [`Arrival::Unknown`]). Not linked: with `create` (a username, given a number
/// after it when taken), [`Arrival::Created`], an account with no email whose
/// password sign-in is off ([`store::set_password_sign_in`]): no password opens it
/// and [`store::authenticate`] never finds it by name, so this pair is its only way
/// in besides a sign-in link. Without `create`, [`Arrival::Unknown`].
/// [`Refused::NoSubject`] when `key` or `subject` is empty, [`Refused::Username`]
/// when `create` breaks the username rule.
///
/// As [`arrive`], one transaction under a lock on the pair, so two at once resolve
/// to one account, and the account's `last_sign_in` is stamped before the pair is
/// touched, the order [`forget_as`] locks them in.
pub async fn arrive_as(
    pool: &PgPool,
    key: &str,
    subject: &str,
    create: Option<&str>,
) -> Result<Arrival> {
    arrive_as_in(&mut *pool.acquire().await?, key, subject, create).await
}

/// [`arrive_as`] on `conn`, as [`arrive_in`] is [`arrive`]: in a savepoint inside
/// the caller's transaction, holding the lock on the pair until it ends.
pub async fn arrive_as_in(
    conn: &mut sqlx::PgConnection,
    key: &str,
    subject: &str,
    create: Option<&str>,
) -> Result<Arrival> {
    if key.is_empty() || subject.is_empty() {
        return Err(Refused::NoSubject.into());
    }
    if let Some(refused) = create.and_then(store::username_problem) {
        return Err(refused.into());
    }
    let mut tx = sqlx::Connection::begin(conn).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(LOCAL_ARRIVAL_LOCK)
        .bind(format!("{key}\n{subject}"))
        .execute(&mut *tx)
        .await?;
    let linked: Option<i64> = sqlx::query_scalar(
        "SELECT account_id FROM account_local_identities WHERE key = $1 AND subject = $2",
    )
    .bind(key)
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await?;
    let arrival = match (linked, create) {
        (Some(id), _) => {
            // The account before the pair, the order a retirement locks them in.
            lock_account(&mut tx, id).await?;
            let still = sqlx::query(
                "UPDATE account_local_identities SET last_sign_in = now()
                 WHERE key = $1 AND subject = $2",
            )
            .bind(key)
            .bind(subject)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            // A pair retired while this waited for the account reaches nothing.
            match store::by_id(&mut *tx, id).await? {
                Some(account) if still => {
                    store::signed_in(&mut *tx, account.id).await?;
                    Arrival::Known(account)
                }
                _ => Arrival::Unknown,
            }
        }
        (None, Some(username)) => {
            let account = create_for(&mut tx, &store::normalize(username), "").await?;
            store::signed_in(&mut *tx, account.id).await?;
            sqlx::query("UPDATE accounts SET password_sign_in = false WHERE id = $1")
                .bind(account.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO account_local_identities (account_id, key, subject)
                 VALUES ($1, $2, $3)",
            )
            .bind(account.id)
            .bind(key)
            .bind(subject)
            .execute(&mut *tx)
            .await?;
            Arrival::Created(account)
        }
        (None, None) => Arrival::Unknown,
    };
    tx.commit().await?;
    Ok(arrival)
}

/// Retire the local identity `subject` under `key` (a device lost or re-enrolled):
/// the pair reaches nothing from now on, and the account it reached is signed out
/// everywhere (every session ends and its unused sign-in links are void), so no
/// session the pair opened outlives it. The account's id, or `None` when the pair
/// was not linked. Nothing else is touched: the account stays, active, and may be
/// left with no way in but a link an operator mints, which is what retiring a
/// system account's only identity means. Deactivate it as well to retire it whole.
pub async fn forget_as(
    db: impl PgExecutor<'_>,
    key: &str,
    subject: &str,
) -> sqlx::Result<Option<i64>> {
    // The account's row is locked first, as unlink locks it before counting the ways
    // in: an unlink waiting on it then counts without this pair, and one holding it
    // has counted with it and finishes before this deletes.
    sqlx::query_scalar(
        "WITH owner AS (
            SELECT a.id FROM accounts a
            JOIN account_local_identities l ON l.account_id = a.id
            WHERE l.key = $1 AND l.subject = $2 FOR UPDATE OF a),
         gone AS (
            DELETE FROM account_local_identities
            WHERE key = $1 AND subject = $2 AND account_id IN (SELECT id FROM owner)
            RETURNING account_id),
         voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id IN (SELECT account_id FROM gone) AND used_at IS NULL)
         UPDATE accounts SET session_epoch = session_epoch + 1
         WHERE id IN (SELECT account_id FROM gone) RETURNING id",
    )
    .bind(key)
    .bind(subject)
    .fetch_optional(db)
    .await
}

/// A username from what the provider says: the display name, else the email's
/// local part, else `user`; letters, digits, `_`, `.` and `-` only, 30 at most.
fn username_base(identity: &Identity) -> String {
    let raw = identity
        .display_name
        .clone()
        .or_else(|| {
            identity
                .email
                .as_ref()
                .map(|e| e.split('@').next().unwrap_or("").to_owned())
        })
        .unwrap_or_default();
    let keep = |c: &char| c.is_alphanumeric() || "_.-".contains(*c);
    let cleaned = store::normalize(&raw.chars().filter(keep).collect::<String>());
    let cleaned: String = cleaned
        .trim_start_matches(|c: char| !c.is_alphanumeric())
        .chars()
        .take(30)
        .collect();
    // A name the username rules refuse (two scripts, a symbol that mimics a
    // letter): its ASCII letters and digits, else `user`.
    let ascii: String = cleaned
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    [cleaned, ascii]
        .into_iter()
        .find(|name| store::valid_username(name))
        .unwrap_or_else(|| "user".to_owned())
}

/// Create an account named `base`, or `base2`, `base3`… if taken, then `base` with
/// a fresh random suffix for as long as those are taken too (each has one chance in
/// 36⁸ of colliding, so in practice the first one lands; there is no candidate after
/// which this gives up or panics). The email is dropped if another account takes it
/// first: [`arrive`] checked it was free, but two first sign-ins with one address
/// can race, and the loser still gets an account (without the email, as an
/// unverified one would). Each attempt is a savepoint, so a refused one leaves `tx`
/// usable.
async fn create_for(
    tx: &mut Transaction<'_, Postgres>,
    base: &str,
    mut email: &str,
) -> Result<Account> {
    let mut candidates = std::iter::once(base.to_owned())
        .chain((2..=20).map(|n| format!("{base}{n}")))
        .chain(std::iter::repeat_with(|| {
            format!("{base}-{}", random_suffix())
        }));
    let mut username = candidates.next().expect("the iterator is endless");
    loop {
        let new = New {
            username: &username,
            email,
            password: None,
            is_staff: false,
        };
        let mut attempt = sqlx::Connection::begin(&mut **tx).await?;
        match store::create_in(&mut attempt, new).await {
            Ok(account) => {
                attempt.commit().await?;
                return Ok(account);
            }
            Err(crate::Error::Refused(
                Refused::UsernameTaken(_) | Refused::UsernameLookalike(_),
            )) => {
                username = candidates.next().expect("the iterator is endless");
            }
            Err(crate::Error::Refused(Refused::EmailTaken(_))) if !email.is_empty() => {
                email = "";
            }
            // A name the rules refuse after all: a plain one, once.
            Err(crate::Error::Refused(Refused::Username)) if !username.starts_with("user-") => {
                username = format!("user-{}", random_suffix());
            }
            Err(e) => return Err(e),
        }
        attempt.rollback().await?;
    }
}

/// Eight digits: digits belong to every script, so `иван-` and `李小龙-` stay
/// one-script names with it.
fn random_suffix() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..8)
        .map(|_| char::from(b'0' + rng.random_range(0..10u8)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(name: Option<&str>, email: Option<&str>) -> Identity {
        Identity {
            uid: "1".into(),
            email: email.map(str::to_owned),
            email_verified: true,
            display_name: name.map(str::to_owned),
            extra: Value::Null,
        }
    }

    #[test]
    fn a_username_comes_from_the_name_then_the_email_then_a_default() {
        assert_eq!(
            username_base(&identity(Some("Ada Lovelace"), None)),
            "adalovelace"
        );
        assert_eq!(
            username_base(&identity(None, Some("Ada.L+x@example.com"))),
            "ada.lx"
        );
        assert_eq!(username_base(&identity(Some("!!!"), None)), "user");
        // Two scripts: the Latin part. Only a lookalike: the default.
        assert_eq!(username_base(&identity(Some("Ivan Иванов"), None)), "ivan");
        assert_eq!(username_base(&identity(Some("иван"), None)), "иван");
        assert_eq!(username_base(&identity(Some("_.admin"), None)), "admin");
        assert_eq!(
            username_base(&identity(Some("\u{430}\u{434}"), None)),
            "\u{430}\u{434}"
        );
        assert_eq!(username_base(&identity(None, None)), "user");
        assert_eq!(
            username_base(&identity(Some(&"é".repeat(40)), None))
                .chars()
                .count(),
            30
        );
    }

    #[test]
    fn a_label_prefers_what_a_person_recognises() {
        let mut linked = Linked {
            id: 1,
            account_id: 1,
            provider: "google".into(),
            subject: "108".into(),
            claims: serde_json::json!({"name": "Ada", "email": "ada@example.com"}),
        };
        assert_eq!(linked.label(), "ada@example.com");
        linked.claims = serde_json::json!({"login": "ada"});
        assert_eq!(linked.label(), "ada");
        linked.claims = serde_json::json!({"email": ""});
        assert_eq!(linked.label(), "108");
        // An address the provider did not verify is not shown as theirs.
        linked.claims =
            serde_json::json!({"email": "ceo@example.com", "email_verified": false, "name": "Eve"});
        assert_eq!(linked.label(), "Eve");
        linked.claims = serde_json::json!({"email": "ceo@example.com", "verified": false});
        assert_eq!(linked.label(), "108");
    }
}
