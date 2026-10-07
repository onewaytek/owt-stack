//! The account rows. Functions take `impl PgExecutor` where one statement does, so a
//! caller may run them inside its own transaction; `authenticate` takes the pool
//! because the check happens off the connection.

use sqlx::{PgExecutor, PgPool};

use crate::{Error, Refused, Result, password};

/// A row of `accounts`, without its hash.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Account {
    /// The id; what the session carries.
    pub id: i64,
    /// Lower-cased and trimmed.
    pub username: String,
    /// Lower-cased and trimmed; empty when none.
    pub email: String,
    /// May do what the app reserves for staff.
    pub is_staff: bool,
    /// A deactivated account signs nobody in; its rows stay.
    pub is_active: bool,
    /// Compared with the session's on every request.
    pub session_epoch: i32,
}

/// The most characters a username has.
pub const MAX_USERNAME_CHARS: usize = 150;

/// How usernames and emails are stored and looked up: trimmed and lower-cased.
#[must_use]
pub fn normalize(name: &str) -> String {
    name.trim().to_lowercase()
}

fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.chars().count() <= MAX_USERNAME_CHARS
        && !username
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// One address: something before one `@`, something after, no whitespace. The
/// mail that proves it is the app's business.
fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// What a new account is made from.
#[derive(Clone, Copy, Debug)]
pub struct New<'a> {
    /// Normalized before storing.
    pub username: &'a str,
    /// Normalized before storing; empty for none.
    pub email: &'a str,
    /// `None` for an account no password opens. Checked against
    /// [`password::check`] with the username and email.
    pub password: Option<&'a str>,
    /// See [`Account::is_staff`].
    pub is_staff: bool,
}

/// A unique violation, as the refusal for the key it broke.
fn taken(e: &sqlx::Error, new: &New<'_>) -> Option<Refused> {
    let db = e.as_database_error()?;
    if !db.is_unique_violation() {
        return None;
    }
    match db.constraint() {
        Some("accounts_username_key") => Some(Refused::UsernameTaken(normalize(new.username))),
        Some("accounts_email_key") => Some(Refused::EmailTaken(normalize(new.email))),
        _ => None,
    }
}

/// Create an account. Refuses an invalid username or email, a password that breaks
/// a rule, and a username or email another account has (by the constraint, so two
/// racing sign-ups cannot both win).
pub async fn create(db: impl PgExecutor<'_>, new: New<'_>) -> Result<Account> {
    let username = normalize(new.username);
    if !valid_username(&username) {
        return Err(Refused::Username.into());
    }
    let email = normalize(new.email);
    if !email.is_empty() && !valid_email(&email) {
        return Err(Refused::Email.into());
    }
    let hash = match new.password {
        None => String::new(),
        Some(password) => {
            let problems = password::check(password, &[&username, &email]);
            if !problems.is_empty() {
                return Err(Refused::Password(problems).into());
            }
            owt_auth::password::hash(password)
                .await
                .map_err(Error::Hash)?
        }
    };
    sqlx::query_as::<_, Account>(
        "INSERT INTO accounts (username, email, password_hash, is_staff)
         VALUES ($1, $2, $3, $4) RETURNING id, username, email, is_staff, is_active, session_epoch",
    )
    .bind(&username)
    .bind(&email)
    .bind(&hash)
    .bind(new.is_staff)
    .fetch_one(db)
    .await
    .map_err(|e| match taken(&e, &new) {
        Some(refused) => refused.into(),
        None => e.into(),
    })
}

/// The active account `login` (a username or an email) and `password` open, if any.
///
/// A login that matches no account, or an account with no password, still costs a
/// full Argon2 check, so the time taken does not say which accounts exist. A hash in
/// an older format is replaced once the password has proved itself, and the account's
/// `last_sign_in` is stamped.
///
/// Charge [`owt_auth::throttle::Throttle::sign_in`] first and do not call this when
/// it refuses: that is what bounds guessing.
pub async fn authenticate(pool: &PgPool, login: &str, password: &str) -> Result<Option<Account>> {
    let login = normalize(login);
    // A username may equal another account's email: the username match wins.
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM accounts
         WHERE is_active AND (username = $1 OR (email <> '' AND email = $1))
         ORDER BY username = $1 DESC LIMIT 1",
    )
    .bind(&login)
    .fetch_optional(pool)
    .await?;
    let stored = row
        .as_ref()
        .map(|(_, hash)| hash.as_str())
        .filter(|hash| !hash.is_empty());
    if !owt_auth::password::verify_or_decoy(password, stored).await {
        return Ok(None);
    }
    let Some((id, hash)) = row else {
        return Ok(None);
    };
    if owt_auth::password::needs_rehash(&hash)
        && let Ok(hash) = owt_auth::password::hash(password).await
    {
        sqlx::query("UPDATE accounts SET password_hash = $1 WHERE id = $2")
            .bind(&hash)
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(
        sqlx::query_as::<_, Account>(
            "UPDATE accounts SET last_sign_in = now() WHERE id = $1 AND is_active RETURNING id, username, email, is_staff, is_active, session_epoch"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?,
    )
}

/// The active account with this id.
pub async fn by_id(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(
        "SELECT id, username, email, is_staff, is_active, session_epoch FROM accounts WHERE id = $1 AND is_active"
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// The active account with this id, if `epoch` is still its current one: the
/// session's question.
pub async fn by_id_in_epoch(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(
        "SELECT id, username, email, is_staff, is_active, session_epoch FROM accounts WHERE id = $1 AND is_active AND session_epoch = $2"
    )
    .bind(id)
    .bind(epoch)
    .fetch_optional(db)
    .await
}

/// The account (active or not) with this username.
pub async fn by_username(db: impl PgExecutor<'_>, username: &str) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(
        "SELECT id, username, email, is_staff, is_active, session_epoch FROM accounts WHERE username = $1"
    )
    .bind(normalize(username))
    .fetch_optional(db)
    .await
}

/// The active account with this email, if the email is set.
pub async fn by_email(db: impl PgExecutor<'_>, email: &str) -> sqlx::Result<Option<Account>> {
    let email = normalize(email);
    if email.is_empty() {
        return Ok(None);
    }
    sqlx::query_as::<_, Account>(
        "SELECT id, username, email, is_staff, is_active, session_epoch FROM accounts WHERE email = $1 AND is_active"
    )
    .bind(email)
    .fetch_optional(db)
    .await
}

/// Every account, by username.
pub async fn list(db: impl PgExecutor<'_>) -> sqlx::Result<Vec<Account>> {
    sqlx::query_as::<_, Account>("SELECT id, username, email, is_staff, is_active, session_epoch FROM accounts ORDER BY username")
        .fetch_all(db)
        .await
}

/// Whether the account has a password (else only an identity or a link opens it).
pub async fn has_password(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<bool> {
    sqlx::query_scalar::<_, bool>("SELECT password_hash <> '' FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map(|has| has.unwrap_or(false))
}

/// Replace the password and sign the account out everywhere. `false` when there is
/// no such account. Refuses a password that breaks a rule.
pub async fn set_password(db: impl PgExecutor<'_>, id: i64, password: &str) -> Result<bool> {
    let problems = password::check(password, &[]);
    if !problems.is_empty() {
        return Err(Refused::Password(problems).into());
    }
    let hash = owt_auth::password::hash(password)
        .await
        .map_err(Error::Hash)?;
    let done = sqlx::query(
        "UPDATE accounts SET password_hash = $1, session_epoch = session_epoch + 1 WHERE id = $2",
    )
    .bind(&hash)
    .bind(id)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Sign the account out everywhere: every session it has, on any device, ends at
/// its next request.
pub async fn sign_out_everywhere(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE accounts SET session_epoch = session_epoch + 1 WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Activate or deactivate. Deactivating also signs the account out everywhere.
pub async fn set_active(db: impl PgExecutor<'_>, id: i64, active: bool) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE accounts SET session_epoch = session_epoch + (is_active AND NOT $2)::int,
                is_active = $2
         WHERE id = $1",
    )
    .bind(id)
    .bind(active)
    .execute(db)
    .await?;
    Ok(())
}

/// Grant or revoke staff. Revoking signs the account out everywhere, so a session
/// does not keep a privilege its account lost.
pub async fn set_staff(db: impl PgExecutor<'_>, id: i64, staff: bool) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE accounts SET session_epoch = session_epoch + (is_staff AND NOT $2)::int,
                is_staff = $2
         WHERE id = $1",
    )
    .bind(id)
    .bind(staff)
    .execute(db)
    .await?;
    Ok(())
}

/// Change the email. Refuses an invalid address and one another account has.
pub async fn set_email(db: impl PgExecutor<'_>, id: i64, email: &str) -> Result<()> {
    let email = normalize(email);
    if !email.is_empty() && !valid_email(&email) {
        return Err(Refused::Email.into());
    }
    sqlx::query("UPDATE accounts SET email = $1 WHERE id = $2")
        .bind(&email)
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| {
            let unique = e
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
            if unique {
                Error::from(Refused::EmailTaken(email.clone()))
            } else {
                Error::from(e)
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_one_token_of_bounded_length() {
        assert!(valid_username("alice"));
        assert!(valid_username("alice@example.com"));
        assert!(valid_username("ünïcödé"));
        assert!(!valid_username(""));
        assert!(!valid_username("two words"));
        assert!(!valid_username("tab\there"));
        assert!(!valid_username(&"a".repeat(MAX_USERNAME_CHARS + 1)));
        assert!(valid_username(&"a".repeat(MAX_USERNAME_CHARS)));
    }

    #[test]
    fn an_email_is_one_address() {
        assert!(valid_email("a@b"));
        assert!(valid_email("alice+tag@example.com"));
        assert!(!valid_email("alice"));
        assert!(!valid_email("@example.com"));
        assert!(!valid_email("alice@"));
        assert!(!valid_email("a@b@c"));
        assert!(!valid_email("alice @example.com"));
    }

    #[test]
    fn normalize_folds_case_and_space() {
        assert_eq!(normalize("  Alice "), "alice");
        assert_eq!(normalize("A@Example.COM"), "a@example.com");
    }
}
