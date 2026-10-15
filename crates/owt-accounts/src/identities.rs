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
    /// Something to show for it: the email, name or handle the claims carry, else
    /// the subject.
    #[must_use]
    pub fn label(&self) -> &str {
        [
            "email",
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
/// way in (no password, no other identity); `false` when no such link exists.
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
    let Some(has_password) = sqlx::query_scalar::<_, bool>(
        "SELECT password_hash <> '' FROM accounts WHERE id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(false);
    };
    // A statement after the lock reads what committed before it was granted.
    let (theirs, count) = sqlx::query_as::<_, (bool, i64)>(
        "SELECT EXISTS (SELECT 1 FROM account_identities WHERE id = $2 AND account_id = $1),
                (SELECT count(*) FROM account_identities WHERE account_id = $1)",
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

/// How a provider sign-in resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// The identity was linked already.
    Known(Account),
    /// An account was created for it, with a username made from the identity.
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

/// Why [`rekey`] refused.
#[derive(Debug, thiserror::Error)]
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

/// Move the identities stored under `from` (a key the app used to give, such as the
/// id `sso` an OIDC provider was stored under before its issuer was its key) to
/// `to`'s [`key`](Provider::key). Run it before serving with the new key, naming in
/// `configured` every provider the app now has: a `from` one of them still gives is
/// refused.
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
    if identity.uid.is_empty() {
        return Err(Refused::NoSubject.into());
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(ARRIVAL_LOCK)
        .bind(format!("{}\n{}", provider.key(), identity.uid))
        .execute(&mut *tx)
        .await?;
    let arrival = if let Some(linked) = find(&mut *tx, provider, &identity.uid).await? {
        match store::by_id(&mut *tx, linked.account_id).await? {
            Some(account) => {
                link(&mut *tx, account.id, provider, identity).await?;
                Arrival::Known(account)
            }
            None => Arrival::Unknown,
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
        link(&mut *tx, account.id, provider, identity).await?;
        Arrival::Created(account)
    } else {
        Arrival::Unknown
    };
    tx.commit().await?;
    Ok(arrival)
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
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_alphanumeric() || "_.-".contains(*c))
        .take(30)
        .collect::<String>()
        .to_lowercase();
    if cleaned.is_empty() {
        "user".to_owned()
    } else {
        cleaned
    }
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
        match store::create(&mut *attempt, new).await {
            Ok(account) => {
                attempt.commit().await?;
                return Ok(account);
            }
            Err(crate::Error::Refused(Refused::UsernameTaken(_))) => {
                username = candidates.next().expect("the iterator is endless");
            }
            Err(crate::Error::Refused(Refused::EmailTaken(_))) if !email.is_empty() => {
                email = "";
            }
            Err(e) => return Err(e),
        }
        attempt.rollback().await?;
    }
}

fn random_suffix() -> String {
    use rand::RngExt;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
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
    }
}
