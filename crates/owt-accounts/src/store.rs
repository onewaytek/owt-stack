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
    /// The names of the app's roles it holds (see [`crate::roles`]), sorted; read on
    /// every request with the rest, so a revoked role is gone at the next one.
    /// A query of the app's own that does not select it (one written before roles,
    /// say) reads none: it fails closed. Select [`COLUMNS`] to read them.
    #[sqlx(default)]
    pub roles: Vec<String>,
}

impl Account {
    /// Whether it holds `role`: granted, or staff when the role is
    /// [`held_by_staff`](crate::roles::Role::held_by_staff).
    #[must_use]
    pub fn holds(&self, role: &crate::roles::Role) -> bool {
        (role.staff && self.is_staff) || self.roles.iter().any(|r| r == role.name)
    }
}

/// The columns an [`Account`] is read from, for a query on `accounts` (unaliased):
/// `format!("SELECT {COLUMNS} FROM accounts WHERE …")` with `query_as::<_, Account>`.
pub const COLUMNS: &str = "id, username, email, is_staff, is_active, session_epoch, \
     ARRAY(SELECT r.role FROM account_roles r WHERE r.account_id = accounts.id ORDER BY r.role) AS roles";

/// The most characters a username has.
pub const MAX_USERNAME_CHARS: usize = 150;

/// How usernames and emails are stored and looked up: trimmed, NFKC-normalized and
/// lower-cased, so the fullwidth `ａｄｍｉｎ`, a composed and a decomposed `é`, and
/// `Admin` are each one name.
#[must_use]
pub fn normalize(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let compatible: String = name.trim().nfkc().collect();
    compatible.to_lowercase().nfkc().collect()
}

/// A name people read as one thing, and as no one else's. A login is a username or
/// an email, so the two must not overlap: no username has an `@` (every email does),
/// so a username shaped like an address cannot shadow its owner's email at sign-in.
/// And a username must not pass for another in the admin list or an app's pages, so
/// every character is a letter, digit or combining mark that Unicode's identifier
/// profile allows (UTS #39: no invisible joiners or fillers, no bidirectional
/// controls, no symbols that mimic letters), or `-`, `.` or `_`; it starts with a
/// letter or digit; and its letters are of one script (no Cyrillic `а` inside a Latin
/// `admin`).
pub(crate) fn valid_username(username: &str) -> bool {
    use unicode_normalization::char::is_combining_mark;
    use unicode_security::{GeneralSecurityProfile, MixedScript};
    let allowed = |c: char| {
        matches!(c, '-' | '.' | '_')
            || (c.identifier_allowed() && (c.is_alphanumeric() || is_combining_mark(c)))
    };
    username.chars().next().is_some_and(char::is_alphanumeric)
        && username.chars().count() <= MAX_USERNAME_CHARS
        && username.chars().all(allowed)
        && username.is_single_script()
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
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO accounts (username, email, password_hash, is_staff)
         VALUES ($1, $2, $3, $4) RETURNING {COLUMNS}"
    )))
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
///
/// The check takes a while (Argon2, perhaps after waiting for a permit), and the
/// password may change meanwhile, by its owner or by staff answering a compromise.
/// So the sign-in stands only if the hash it checked is still the account's: a
/// sign-in with the old password that finishes after the change fails, rather than
/// taking the new session epoch (and, with a rehash, writing the old password back).
pub async fn authenticate(pool: &PgPool, login: &str, password: &str) -> Result<Option<Account>> {
    let login = normalize(login);
    // At most one row: no username has an `@`, every email does, and each is unique.
    // `lower(email)` (the stored form already) is what the unique index covers.
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM accounts
         WHERE is_active AND (username = $1 OR (email <> '' AND lower(email) = $1))",
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
    let mut current = hash;
    if owt_auth::password::needs_rehash(&current)
        && let Ok(rehashed) = owt_auth::password::hash(password).await
    {
        let done = sqlx::query(
            "UPDATE accounts SET password_hash = $1 WHERE id = $2 AND password_hash = $3",
        )
        .bind(&rehashed)
        .bind(id)
        .bind(&current)
        .execute(pool)
        .await?;
        if done.rows_affected() == 1 {
            current = rehashed;
        }
    }
    Ok(sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "UPDATE accounts SET last_sign_in = now()
         WHERE id = $1 AND is_active AND password_hash = $2 RETURNING {COLUMNS}"
    )))
    .bind(id)
    .bind(&current)
    .fetch_optional(pool)
    .await?)
}

/// The active account with this id.
pub async fn by_id(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE id = $1 AND is_active"
    )))
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
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE id = $1 AND is_active AND session_epoch = $2"
    )))
    .bind(id)
    .bind(epoch)
    .fetch_optional(db)
    .await
}

/// The account (active or not) with this username.
pub async fn by_username(db: impl PgExecutor<'_>, username: &str) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE username = $1"
    )))
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
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE lower(email) = $1 AND is_active"
    )))
    .bind(email)
    .fetch_optional(db)
    .await
}

/// Every account, by username.
pub async fn list(db: impl PgExecutor<'_>) -> sqlx::Result<Vec<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts ORDER BY username"
    )))
    .fetch_all(db)
    .await
}

/// Whether the account has a password that can open it (else only an identity or
/// a link does): an Argon2 hash, not an empty or legacy one.
pub async fn has_password(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<bool> {
    sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
        "SELECT {USABLE_PASSWORD} FROM accounts WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
    .map(|has| has.unwrap_or(false))
}

/// SQL true when the row's password can open it: an Argon2 PHC string, as
/// [`owt_auth::password::usable`] says (a legacy hash opens nothing).
pub(crate) const USABLE_PASSWORD: &str = "password_hash LIKE '$argon2%'";

/// The signed-in person's own change: `current` must open `account` first, so a
/// session someone else is holding cannot also take the password (and sign its owner
/// out). [`Refused::CurrentPassword`] when it does not. Charge the sign-in throttle
/// for the account first, as for a sign-in: this is a password check too.
pub async fn change_password(
    pool: &PgPool,
    account: &Account,
    current: &str,
    new: &str,
) -> Result<bool> {
    let stored =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM accounts WHERE id = $1")
            .bind(account.id)
            .fetch_optional(pool)
            .await?;
    if !owt_auth::password::verify_or_decoy(current, stored.as_deref()).await {
        return Err(Refused::CurrentPassword.into());
    }
    set_password(pool, account, new).await
}

/// Replace `account`'s password, sign it out everywhere and void its unused sign-in
/// links. `false` when the row is gone. For staff, or a reset by link; the account's
/// own change is [`change_password`]. Refuses a password that breaks a rule, the similarity rule included: the
/// account is passed, not its id, so its username and email are there to check
/// against.
pub async fn set_password(
    db: impl PgExecutor<'_>,
    account: &Account,
    password: &str,
) -> Result<bool> {
    let problems = password::check(password, &[&account.username, &account.email]);
    if !problems.is_empty() {
        return Err(Refused::Password(problems).into());
    }
    let hash = owt_auth::password::hash(password)
        .await
        .map_err(Error::Hash)?;
    let done = sqlx::query(
        "WITH voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id = $2 AND used_at IS NULL)
         UPDATE accounts SET password_hash = $1, session_epoch = session_epoch + 1
         WHERE id = $2",
    )
    .bind(&hash)
    .bind(account.id)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Sign the account out everywhere: every session it has, on any device, ends at
/// its next request, and its unused sign-in links are void.
pub async fn sign_out_everywhere(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<()> {
    sqlx::query(
        "WITH voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id = $1 AND used_at IS NULL)
         UPDATE accounts SET session_epoch = session_epoch + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Activate or deactivate. Deactivating also signs the account out everywhere and
/// voids its unused sign-in links, so reactivating it later revives none.
pub async fn set_active(db: impl PgExecutor<'_>, id: i64, active: bool) -> sqlx::Result<()> {
    sqlx::query(
        "WITH voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id = $1 AND used_at IS NULL AND NOT $2)
         UPDATE accounts SET session_epoch = session_epoch + (is_active AND NOT $2)::int,
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
    fn usernames_are_one_token_of_bounded_length_and_never_an_address() {
        assert!(valid_username("alice"));
        assert!(valid_username("ünïcödé"));
        assert!(valid_username("alice.example.com"));
        assert!(!valid_username("alice@example.com"));
        assert!(!valid_username("@alice"));
        assert!(!valid_username(""));
        assert!(!valid_username("two words"));
        assert!(!valid_username("tab\there"));
        assert!(!valid_username(&"a".repeat(MAX_USERNAME_CHARS + 1)));
        assert!(valid_username(&"a".repeat(MAX_USERNAME_CHARS)));
    }

    /// Every name the sweep registered as a distinct `admin`, and the scripts real
    /// people write their names in.
    #[test]
    fn a_username_cannot_pass_for_another() {
        let ok = |raw: &str| valid_username(&normalize(raw));
        for real in [
            "ada_lovelace",
            "josé",
            "jose\u{301}",
            "μαρία",
            "иван",
            "नमस्ते",
            "李小龙",
            "user-2.0",
            "ＡＤＭＩＮ",
        ] {
            assert!(ok(real), "{real:?} is a real name");
        }
        // Composed and decomposed, fullwidth and plain: one name each.
        assert_eq!(normalize("jose\u{301}"), normalize("jos\u{e9}"));
        assert_eq!(normalize("ＡＤＭＩＮ"), "admin");
        for fake in [
            "admin\u{200b}",
            "ad\u{200d}min",
            "\u{feff}admin",
            "ad\u{ad}min",
            "admin\u{2060}",
            "admin\u{3164}",
            "admin\u{2800}",
            "admin\u{e0041}",
            "\u{202e}nimda",
            "\u{430}dmin",
            "ceo\u{ff20}corp.com",
            "\u{301}admin",
            "_admin",
            "admin'",
            "ad:min",
        ] {
            assert!(!ok(fake), "{fake:?} passed for a name");
        }
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
