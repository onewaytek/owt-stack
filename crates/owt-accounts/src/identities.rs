//! Provider identities linked to accounts: what an OAuth sign-in resolves to.
//!
//! [`owt_auth::oauth`] gets the [`Identity`](owt_auth::oauth::Identity) from the
//! provider; [`arrive`] turns it into an account, by the app's [`Welcome`] policy.
//! Linking a second provider to a signed-in account, listing them and unlinking are
//! here too.

use serde_json::Value;
use sqlx::{PgExecutor, PgPool};

use crate::store::{self, Account, New};
use crate::{Refused, Result};

/// A row of `account_identities`.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Linked {
    /// The row's id; what an unlink names.
    pub id: i64,
    /// The account it signs in.
    pub account_id: i64,
    /// The provider, as the app names it (`google`, `discord`, an issuer's slug).
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
    provider: &str,
    subject: &str,
) -> sqlx::Result<Option<Linked>> {
    sqlx::query_as::<_, Linked>(
        "SELECT id, account_id, provider, subject, claims FROM account_identities WHERE provider = $1 AND subject = $2"
    )
    .bind(provider)
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

/// Link an identity to `account_id`. Already linked there: the claims are refreshed.
/// Linked to another account: [`Refused::IdentityTaken`].
pub async fn link(
    db: impl PgExecutor<'_>,
    account_id: i64,
    provider: &str,
    subject: &str,
    claims: &Value,
) -> Result<Linked> {
    let linked = sqlx::query_as::<_, Linked>(
        "INSERT INTO account_identities (account_id, provider, subject, claims)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (provider, subject) DO UPDATE
            SET claims = EXCLUDED.claims, last_sign_in = now()
            WHERE account_identities.account_id = EXCLUDED.account_id
         RETURNING id, account_id, provider, subject, claims",
    )
    .bind(account_id)
    .bind(provider)
    .bind(subject)
    .bind(claims)
    .fetch_optional(db)
    .await?;
    // No row back: the conflict's WHERE excluded it, so another account holds it.
    linked.ok_or_else(|| Refused::IdentityTaken.into())
}

/// Unlink identity `id` from `account_id`. Refused when it is the account's only
/// way in (no password, no other identity); `false` when no such link exists.
pub async fn unlink(pool: &PgPool, account_id: i64, id: i64) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let (has_password, count) = sqlx::query_as::<_, (bool, i64)>(
        "SELECT password_hash <> '',
                (SELECT count(*) FROM account_identities WHERE account_id = $1)
         FROM accounts WHERE id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or((false, 0));
    if !has_password && count <= 1 {
        return Err(Refused::LastWayIn.into());
    }
    let done = sqlx::query("DELETE FROM account_identities WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// What an app lets a provider sign-in do when the identity is new.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Welcome {
    /// An identity whose provider-verified email matches an active account's signs
    /// into it (and is linked). Only safe when the provider verifies emails.
    pub match_verified_email: bool,
    /// An identity matching nothing creates an account. Off: the sign-in is refused
    /// as [`Arrival::Unknown`], for an app with no self-signup.
    pub create: bool,
}

/// How a provider sign-in resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// The identity was linked already.
    Known(Account),
    /// Its verified email matched an account; the identity is now linked to it.
    Matched(Account),
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
            Self::Known(a) | Self::Matched(a) | Self::Created(a) => Some(a),
            Self::Unknown => None,
        }
    }
}

/// Resolve a provider's identity to an account, per `welcome`. Refreshes the
/// identity's claims. A deactivated account resolves to [`Arrival::Unknown`].
pub async fn arrive(
    pool: &PgPool,
    provider: &str,
    identity: &owt_auth::oauth::Identity,
    welcome: Welcome,
) -> Result<Arrival> {
    if identity.uid.is_empty() {
        return Ok(Arrival::Unknown);
    }
    if let Some(linked) = find(pool, provider, &identity.uid).await? {
        let Some(account) = store::by_id(pool, linked.account_id).await? else {
            return Ok(Arrival::Unknown);
        };
        link(pool, account.id, provider, &identity.uid, &identity.extra).await?;
        return Ok(Arrival::Known(account));
    }
    if welcome.match_verified_email
        && identity.email_verified
        && let Some(email) = &identity.email
        && let Some(account) = store::by_email(pool, email).await?
    {
        link(pool, account.id, provider, &identity.uid, &identity.extra).await?;
        return Ok(Arrival::Matched(account));
    }
    if !welcome.create {
        return Ok(Arrival::Unknown);
    }
    let email = identity.email.as_deref().unwrap_or("");
    // Only a verified email is worth recording; another account may hold it anyway.
    let email = if identity.email_verified && store::by_email(pool, email).await?.is_none() {
        email
    } else {
        ""
    };
    let account = create_for(pool, &username_base(identity), email).await?;
    link(pool, account.id, provider, &identity.uid, &identity.extra).await?;
    Ok(Arrival::Created(account))
}

/// A username from what the provider says: the display name, else the email's
/// local part, else `user`; letters, digits, `_`, `.` and `-` only, 30 at most.
fn username_base(identity: &owt_auth::oauth::Identity) -> String {
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

/// Create an account named `base`, or `base2`, `base3`… if taken, or `base` with a
/// random suffix after that.
async fn create_for(pool: &PgPool, base: &str, email: &str) -> Result<Account> {
    let mut candidates = std::iter::once(base.to_owned())
        .chain((2..=20).map(|n| format!("{base}{n}")))
        .chain(std::iter::once(format!("{base}-{}", random_suffix())));
    loop {
        let username = candidates
            .next()
            .expect("the random candidate is always there");
        let new = New {
            username: &username,
            email,
            password: None,
            is_staff: false,
        };
        match store::create(pool, new).await {
            Err(crate::Error::Refused(Refused::UsernameTaken(_))) => {}
            other => return other,
        }
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

    fn identity(name: Option<&str>, email: Option<&str>) -> owt_auth::oauth::Identity {
        owt_auth::oauth::Identity {
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
