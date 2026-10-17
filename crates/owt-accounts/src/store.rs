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
    let lowered: String = compatible.to_lowercase().nfkc().collect();
    // Trimmed again: NFKC turns some characters into a space and a mark (`´` is
    // U+0020 U+0301), so a name that began with one would begin with a space.
    lowered.trim().to_owned()
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
    // After NFKC, a mark still standing beside a letter of a script that has its
    // accented letters precomposed (Latin, Greek, Cyrillic) is a trick: a stacked
    // or overlaid accent. So are the spacing modifier letters (`ʼ` passing for `'`).
    let trick = |c: char| {
        matches!(c,
            '\u{02B0}'..='\u{02FF}' | '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}' | '\u{20D0}'..='\u{20FF}' | '\u{FE20}'..='\u{FE2F}')
    };
    let allowed = |c: char| {
        matches!(c, '-' | '.' | '_')
            || (c.identifier_allowed()
                && !trick(c)
                && (c.is_alphanumeric() || is_combining_mark(c)))
    };
    username.chars().next().is_some_and(char::is_alphanumeric)
        && username.chars().count() <= MAX_USERNAME_CHARS
        && username.chars().all(allowed)
        && username.is_single_script()
}

/// What [`create`] would refuse in this username, before it looks at the other
/// accounts: [`Refused::Username`] when the name, [`normalize`]d, breaks the rule
/// (letters, digits and marks of one script, or `-`, `.` and `_`; starting with a
/// letter or digit; no `@`; at most [`MAX_USERNAME_CHARS`]). A sign-up form that
/// checks every field at once asks this rather than keep a copy of the rule; a
/// name taken or too like another's is still `create`'s to refuse.
#[must_use]
pub fn username_problem(username: &str) -> Option<Refused> {
    (!valid_username(&normalize(username))).then_some(Refused::Username)
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
        Some("accounts_username_skeleton_key") => {
            Some(Refused::UsernameLookalike(normalize(new.username)))
        }
        Some("accounts_email_key") => Some(Refused::EmailTaken(normalize(new.email))),
        _ => None,
    }
}

/// The key two usernames collide on when a reader could not tell them apart: the
/// Unicode TS #39 confusable skeleton, lower-cased (`paypa1` and `paypal`, Latin
/// `coco` and Cyrillic `сосо`, `rn` and `m`). Stored beside the username, unique.
#[must_use]
pub fn skeleton(username: &str) -> String {
    unicode_security::confusable_detection::skeleton(username)
        .collect::<String>()
        .to_lowercase()
}

/// Create an account. Refuses an invalid username or email, a password that breaks
/// a rule, a username or email another account has, and a username too like another
/// account's ([`skeleton`]): by the constraints, so two racing sign-ups cannot both
/// win. An account [`migrations::complete`](crate::migrations::complete) has yet to
/// reach (one an older replica wrote during a deploy) has no stored skeleton, so its
/// name's is computed here and compared too.
pub async fn create(pool: &PgPool, new: New<'_>) -> Result<Account> {
    create_in(&mut *pool.acquire().await?, new).await
}

/// [`create`] on `conn`: inside the caller's transaction, say.
pub async fn create_in(conn: &mut sqlx::PgConnection, new: New<'_>) -> Result<Account> {
    if let Some(refused) = username_problem(new.username) {
        return Err(refused.into());
    }
    let username = normalize(new.username);
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
    let key = skeleton(&username);
    let unkeyed: Vec<String> =
        sqlx::query_scalar("SELECT username FROM accounts WHERE username_skeleton IS NULL")
            .fetch_all(&mut *conn)
            .await?;
    // As complete will key them: the skeleton of the name each becomes.
    if unkeyed
        .iter()
        .any(|old| skeleton(&normalize(old).replace('@', "-")) == key)
    {
        return Err(Refused::UsernameLookalike(username).into());
    }
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO accounts (username, username_skeleton, email, password_hash, is_staff)
         VALUES ($1, $5, $2, $3, $4) RETURNING {COLUMNS}"
    )))
    .bind(&username)
    .bind(&email)
    .bind(&hash)
    .bind(new.is_staff)
    .bind(&key)
    .fetch_one(&mut *conn)
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

/// What an app reads about the signed-in account beside the [`Account`], in the
/// same query as the session's epoch check: [`by_id_in_epoch_with`], and the layer's
/// [`load_with`](crate::Accounts::load_with).
///
/// [`QUERY`](Self::QUERY) is a `SELECT` run as a `LEFT JOIN LATERAL` beside the
/// account's row, so it can name the row as `accounts` (the app's own columns on it,
/// or a join on `accounts.id`):
///
/// ```sql
/// SELECT COLUMNS, extra.* FROM accounts LEFT JOIN LATERAL (QUERY) extra ON true
/// WHERE accounts.id = $1 AND accounts.is_active AND accounts.session_epoch = $2
/// ```
///
/// The type is decoded from the same row as the [`Account`], by column name, so the
/// query names its columns apart from [`COLUMNS`]' (`AS display_name`, not
/// `username`). A query that finds no row reads as `NULL` in each column, so a field
/// it may miss is an `Option`; a column that fails to decode fails the load like a
/// database error. A query that finds several rows gives the first: end it with
/// `LIMIT 1` unless the join is on a key.
///
/// `QUERY` is SQL pasted into the statement as it is, so it is a constant of the app's
/// code: never built from anything a visitor sends. It binds no parameters of its own
/// (`$1` and `$2` are the library's); it reads the account through `accounts`.
pub trait Extra: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Sync + 'static {
    /// The `SELECT`, as above: `"SELECT p.display_name FROM profiles p WHERE
    /// p.account_id = accounts.id"`, or `"SELECT accounts.beta AS beta"` for a column
    /// of the app's own on `accounts`.
    const QUERY: &'static str;
}

/// [`by_id_in_epoch`], with what `X` reads beside the account in the same query.
pub async fn by_id_in_epoch_with<X: Extra>(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
) -> sqlx::Result<Option<(Account, X)>> {
    use sqlx::FromRow;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS}, extra.* FROM accounts LEFT JOIN LATERAL ({}) extra ON true
         WHERE accounts.id = $1 AND accounts.is_active AND accounts.session_epoch = $2",
        X::QUERY
    )))
    .bind(id)
    .bind(epoch)
    .fetch_optional(db)
    .await?;
    row.map(|row| Ok((Account::from_row(&row)?, X::from_row(&row)?)))
        .transpose()
}

/// The account with this username, active or not: a deactivated account is found
/// too, so this is not the account to sign in as. Sign-in goes through
/// [`authenticate`], which finds active accounts only; code that looks a person up
/// by name to act as them checks [`Account::is_active`] first.
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
        "SELECT {COLUMNS} FROM accounts WHERE email <> '' AND lower(email) = $1 AND is_active"
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

/// SQL true when the row has a password: the table holds an Argon2id hash or
/// nothing, so a stored hash is one that can open the account.
pub(crate) const USABLE_PASSWORD: &str = "password_hash <> ''";

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
    // Only over the hash just checked: a reset by staff while this ran (answering a
    // compromise, say) stands, and this change is refused rather than undoing it.
    if replace_password(pool, account, new, stored.as_deref()).await? {
        Ok(true)
    } else {
        Err(Refused::CurrentPassword.into())
    }
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
    replace_password(db, account, password, None).await
}

/// [`set_password`], only while the stored hash is still `expected` (when given).
async fn replace_password(
    db: impl PgExecutor<'_>,
    account: &Account,
    password: &str,
    expected: Option<&str>,
) -> Result<bool> {
    let problems = password::check(password, &[&account.username, &account.email]);
    if !problems.is_empty() {
        return Err(Refused::Password(problems).into());
    }
    let hash = owt_auth::password::hash(password)
        .await
        .map_err(Error::Hash)?;
    let done = sqlx::query(
        "WITH target AS (
            SELECT id FROM accounts
            WHERE id = $2 AND ($3::text IS NULL OR password_hash = $3) FOR UPDATE),
         voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id IN (SELECT id FROM target) AND used_at IS NULL)
         UPDATE accounts SET password_hash = $1, session_epoch = session_epoch + 1
         WHERE id IN (SELECT id FROM target)",
    )
    .bind(&hash)
    .bind(account.id)
    .bind(expected)
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

    /// What a form hears is what `create` would say: the name as typed, normalized.
    #[test]
    fn a_username_problem_is_the_refusal_create_gives() {
        let refused = |name: &str| username_problem(name) == Some(Refused::Username);
        assert_eq!(username_problem("alice"), None);
        assert_eq!(username_problem("  ＡＬＩＣＥ "), None);
        assert!(refused("alice@example.com"));
        assert!(refused("two words"));
        assert!(refused("   "));
        assert!(refused("p\u{430}ypal"));
        assert!(refused(&"a".repeat(MAX_USERNAME_CHARS + 1)));
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
            "admin\u{2bc}",
            "a\u{301}\u{301}min",
            "r\u{335}oot",
            "admi\u{331}n",
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
