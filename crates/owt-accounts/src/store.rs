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
    /// A query of the app's own that does not select it reads none: it fails closed.
    /// Select [`COLUMNS`] to read them.
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

/// Every refusal [`create`] would give `new`, at once, for a sign-up form that shows
/// them all: the username's shape, the email's, each password rule it breaks, and
/// a username or email another account has or a username too like another's. In
/// that order; a username of the wrong shape is not looked up. `create` still
/// decides, by the constraints: a sign-up racing this one can take a name first, and
/// a name too like an account [`migrations::complete`](crate::migrations::complete)
/// has yet to key is refused there alone.
///
/// It says whether a username or an email has an account, as `create` does: charge
/// [`owt_auth::throttle::Throttle::attempt`] for the client's address first.
///
/// # Errors
///
/// The database.
pub async fn problems(db: impl PgExecutor<'_>, new: &New<'_>) -> sqlx::Result<Vec<Refused>> {
    let username = normalize(new.username);
    let email = normalize(new.email);
    let mut refused = Vec::new();
    let shaped = valid_username(&username);
    if !shaped {
        refused.push(Refused::Username);
    }
    if !email.is_empty() && !valid_email(&email) {
        refused.push(Refused::Email);
    }
    if let Some(password) = new.password {
        let broken = password::check(password, &[&username, &email]);
        if !broken.is_empty() {
            refused.push(Refused::Password(broken));
        }
    }
    let (name, lookalike, address): (bool, bool, bool) = sqlx::query_as(
        "SELECT $4 AND EXISTS (SELECT 1 FROM accounts WHERE username = $1),
                $4 AND EXISTS (SELECT 1 FROM accounts
                               WHERE username_skeleton = $2 AND username <> $1),
                $3 <> '' AND EXISTS (SELECT 1 FROM accounts WHERE email <> '' AND lower(email) = $3)",
    )
    .bind(&username)
    .bind(skeleton(&username))
    .bind(&email)
    .bind(shaped)
    .fetch_one(db)
    .await?;
    if name {
        refused.push(Refused::UsernameTaken(username.clone()));
    } else if lookalike {
        refused.push(Refused::UsernameLookalike(username.clone()));
    }
    if address {
        refused.push(Refused::EmailTaken(email));
    }
    Ok(refused)
}

/// Stamp the account's `last_sign_in`, which the admin shows. Every way in owt
/// signs an account in through does: [`authenticate`],
/// [`identities::arrive`](crate::identities::arrive),
/// [`identities::arrive_as`](crate::identities::arrive_as) and
/// [`links::redeem`](crate::links::redeem). An app's own way in calls it too.
///
/// # Errors
///
/// The database.
pub async fn signed_in(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE accounts SET last_sign_in = now() WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
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
                .map_err(Error::hash)?
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
/// An account [`set_password_sign_in`] turned off is never found, by either name.
///
/// A login that matches no account, or an account with no password, still costs a
/// full Argon2 check, so the time taken does not say which accounts exist. A hash with
/// outdated Argon2 parameters is replaced once the password has proved itself, and the
/// account's `last_sign_in` is stamped.
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
    authenticate_as(pool, login, password, true).await
}

/// [`authenticate`] without stamping `last_sign_in`: for a way in that is not complete
/// until a second factor passes ([`crate::mfa`] stamps it then), so that a password
/// alone does not move the time the admin shows. The password is checked, and an
/// outdated hash replaced, exactly as in [`authenticate`]. Throttle first, the same.
pub async fn check_password(pool: &PgPool, login: &str, password: &str) -> Result<Option<Account>> {
    authenticate_as(pool, login, password, false).await
}

async fn authenticate_as(
    pool: &PgPool,
    login: &str,
    password: &str,
    stamp: bool,
) -> Result<Option<Account>> {
    let login = normalize(login);
    // At most one row: no username has an `@`, every email does, and each is unique.
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM accounts
         WHERE is_active AND password_sign_in
           AND (username = $1 OR (email <> '' AND lower(email) = $1))",
    )
    .bind(&login)
    .fetch_optional(pool)
    .await?;
    let stored = row
        .as_ref()
        .map(|(_, hash)| hash.as_str())
        .filter(|hash| !hash.is_empty());
    let checked = owt_auth::password::check_or_decoy(password, stored).await?;
    if !checked.matched() {
        return Ok(None);
    }
    let Some((id, hash)) = row else {
        return Ok(None);
    };
    let mut current = hash;
    // Also a hash of the password as typed, made before passwords were normalized.
    if (owt_auth::password::needs_rehash(&current)
        || checked == owt_auth::password::Check::MatchRaw)
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
    let stamped = if stamp {
        "last_sign_in = now()"
    } else {
        "last_sign_in = last_sign_in"
    };
    Ok(sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "UPDATE accounts SET {stamped}
         WHERE id = $1 AND is_active AND password_sign_in AND password_hash = $2
         RETURNING {COLUMNS}"
    )))
    .bind(id)
    .bind(&current)
    .fetch_optional(pool)
    .await?)
}

/// The active account with this id, its `last_sign_in` stamped: for a way in that
/// has checked a credential of its own (`session::password_gate`).
pub(crate) async fn open_active(pool: &PgPool, id: i64) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "UPDATE accounts SET last_sign_in = now() WHERE id = $1 AND is_active
         RETURNING {COLUMNS}"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
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

/// The active account with this id, if `epoch` is still its current one and the
/// session with id `session` (when given) was not signed out ([`revoke_session`]): the
/// session's question.
pub async fn by_id_in_epoch(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
    session: Option<&str>,
) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE id = $1 AND is_active AND session_epoch = $2
         AND NOT EXISTS (SELECT 1 FROM revoked_sessions r WHERE r.id = $3)"
    )))
    .bind(id)
    .bind(epoch)
    .bind(session)
    .fetch_optional(db)
    .await
}

/// Record the session with id `session` as signed out, so its cookie opens it no more
/// even if someone kept a copy; `expires` (Unix seconds) is when the cookie could no
/// longer open it anyway, after which the row is pointless. Rows past their expiry
/// are deleted on the way, a bounded batch per call.
pub async fn revoke_session(
    db: impl PgExecutor<'_>,
    session: &str,
    expires: u64,
) -> sqlx::Result<()> {
    let expires = i64::try_from(expires).unwrap_or(i64::MAX);
    sqlx::query(
        "WITH pruned AS (
             DELETE FROM revoked_sessions WHERE id IN (
                 SELECT id FROM revoked_sessions WHERE expires_at < now() LIMIT 1000
             )
         )
         INSERT INTO revoked_sessions (id, expires_at) VALUES ($1, to_timestamp($2))
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(session)
    .bind(expires)
    .execute(db)
    .await?;
    Ok(())
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
/// SELECT account.*, extra.* FROM accounts
/// CROSS JOIN LATERAL (SELECT COLUMNS) account
/// LEFT JOIN LATERAL (QUERY) extra ON true
/// WHERE accounts.id = $1 AND accounts.is_active AND accounts.session_epoch = $2
/// AND NOT EXISTS (SELECT 1 FROM revoked_sessions r WHERE r.id = $3)
/// ```
///
/// The type is decoded from the same row as the [`Account`], by column name, so the
/// query names its columns apart from [`COLUMNS`]' (`AS display_name`, not
/// `username`). A row with two columns of one name fails the load like a database
/// error, so an extra `roles` or `is_staff` can never stand in for the account's.
/// The accounts layer reads two columns of its own in that row, `owt_has_factor` and
/// `owt_accepted`, so those names are taken too.
/// A query that finds no row reads as `NULL` in each column, so a field it may miss
/// is an `Option`; a column that fails to decode fails the load too. It yields at
/// most one row: several fail the load as well, rather than pass one of them off as
/// the viewer's. So join on a key or end it with `LIMIT 1`, and never name `accounts`
/// in its own `FROM`: that reads the whole table, not the viewer's row.
///
/// `QUERY` is SQL pasted into the statement as it is, so it is a constant of the app's
/// code: never built from anything a visitor sends. It binds no parameters of its own
/// (`$1` to `$3` are the library's); it reads the account through `accounts`.
pub trait Extra: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Sync + 'static {
    /// The `SELECT`, as above: `"SELECT p.display_name FROM profiles p WHERE
    /// p.account_id = accounts.id"`, or `"SELECT accounts.beta"` for a column of the
    /// app's own on `accounts`.
    const QUERY: &'static str;
}

/// [`by_id_in_epoch`], with what `X` reads beside the account in the same query.
pub async fn by_id_in_epoch_with<X: Extra>(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
    session: Option<&str>,
) -> sqlx::Result<Option<(Account, X)>> {
    use sqlx::FromRow;
    let Some(row) = row_in_epoch(db, id, epoch, session, Some(Queried::of::<X>()), false).await?
    else {
        return Ok(None);
    };
    Ok(Some((Account::from_row(&row)?, X::from_row(&row)?)))
}

/// What the accounts layer's gates need to know about the signed-in account, read in
/// the query that loads it: whether it holds a second factor (for the MFA gate) and
/// which policy versions it last accepted (for the policies gate).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Standing {
    /// A confirmed authenticator: [`Factors::any`](crate::mfa::Factors::any).
    pub(crate) has_factor: bool,
    /// The `policy_acceptances` version ids, one per document the account accepted.
    pub(crate) accepted: Vec<i64>,
}

/// The columns [`standing_in_epoch`] reads for [`Standing`]. Both lookups are on a primary
/// key: `account_totp (account_id)` and the `(account_id, kind)` prefix of
/// `policy_acceptances`.
const STANDING: &str = "SELECT
             EXISTS (SELECT 1 FROM account_totp t
                     WHERE t.account_id = accounts.id AND t.confirmed_at IS NOT NULL)
               AS owt_has_factor,
             ARRAY(SELECT p.version_id FROM policy_acceptances p
                   WHERE p.account_id = accounts.id) AS owt_accepted";

/// The layer's one query for a signed-in request under [`Accounts::load`](crate::Accounts::load):
/// [`by_id_in_epoch`] and the account's [`Standing`], in a single statement.
pub(crate) async fn standing_in_epoch(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
    session: Option<&str>,
) -> sqlx::Result<Option<(Account, Standing)>> {
    use sqlx::FromRow;
    let Some(row) = row_in_epoch(db, id, epoch, session, None, true).await? else {
        return Ok(None);
    };
    Ok(Some((Account::from_row(&row)?, Standing::from_row(&row)?)))
}

/// [`standing_in_epoch`] under [`Accounts::load_with`](crate::Accounts::load_with): also what
/// `X` reads, as [`by_id_in_epoch_with`] does.
pub(crate) async fn standing_in_epoch_with<X: Extra>(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
    session: Option<&str>,
) -> sqlx::Result<Option<(Account, X, Standing)>> {
    use sqlx::FromRow;
    let Some(row) = row_in_epoch(db, id, epoch, session, Some(Queried::of::<X>()), true).await?
    else {
        return Ok(None);
    };
    Ok(Some((
        Account::from_row(&row)?,
        X::from_row(&row)?,
        Standing::from_row(&row)?,
    )))
}

impl Standing {
    fn from_row(row: &sqlx::postgres::PgRow) -> sqlx::Result<Self> {
        use sqlx::Row;
        Ok(Self {
            has_factor: row.try_get("owt_has_factor")?,
            accepted: row.try_get("owt_accepted")?,
        })
    }
}

/// The `QUERY` of an [`Extra`] and its type's name, for the errors.
struct Queried {
    query: &'static str,
    name: &'static str,
}

impl Queried {
    fn of<X: Extra>() -> Self {
        Self {
            query: X::QUERY,
            name: std::any::type_name::<X>(),
        }
    }
}

/// The row of the active account `id` in `epoch` whose session `session` stands, with
/// `extra`'s columns and, if `standing`, [`STANDING`]'s beside [`COLUMNS`]'.
async fn row_in_epoch(
    db: impl PgExecutor<'_>,
    id: i64,
    epoch: i32,
    session: Option<&str>,
    extra: Option<Queried>,
    standing: bool,
) -> sqlx::Result<Option<sqlx::postgres::PgRow>> {
    use sqlx::{Column, Row};
    // The account's columns are computed in a lateral of their own, which sees only
    // `accounts`: an extra column named `id` does not make them ambiguous. The newline
    // before each `)` keeps a `--` comment ending QUERY from swallowing it.
    // LIMIT 2: enough to tell one row from several.
    let (standing_cols, standing_join) = if standing {
        (
            ", standing.*",
            format!("CROSS JOIN LATERAL ({STANDING}\n) standing"),
        )
    } else {
        ("", String::new())
    };
    let (extra_cols, extra_join) = match &extra {
        Some(e) => (
            ", extra.*",
            format!("LEFT JOIN LATERAL ({}\n) extra ON true", e.query),
        ),
        None => ("", String::new()),
    };
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT account.*{standing_cols}{extra_cols} FROM accounts
         CROSS JOIN LATERAL (SELECT {COLUMNS}\n) account
         {standing_join}
         {extra_join}
         WHERE accounts.id = $1 AND accounts.is_active AND accounts.session_epoch = $2
         AND NOT EXISTS (SELECT 1 FROM revoked_sessions r WHERE r.id = $3)
         LIMIT 2"
    )))
    .bind(id)
    .bind(epoch)
    .bind(session)
    .fetch_all(db)
    .await?;
    let name = extra.as_ref().map_or("the account", |e| e.name);
    if rows.len() > 1 {
        return Err(sqlx::Error::Decode(
            format!("the Extra::QUERY of {name} yields several rows for one account").into(),
        ));
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    // Decoding by name reads the last column of a name: refuse any name twice, so
    // the extra cannot replace what the account says (its roles, its staff flag) or
    // what the gates read (`owt_has_factor`, `owt_accepted`).
    let mut names = std::collections::HashSet::new();
    if let Some(twice) = row.columns().iter().find(|c| !names.insert(c.name())) {
        return Err(sqlx::Error::Decode(
            format!(
                "the Extra::QUERY of {name} names a column {:?}, which the row already has",
                twice.name()
            )
            .into(),
        ));
    }
    Ok(Some(row))
}

/// The account with this username, active or not: a deactivated account is found
/// too, so this is not the account to sign in as. Sign-in goes through
/// [`authenticate`], which finds active accounts only (and none that
/// [`set_password_sign_in`] turned off); code that looks a person up by name to act
/// as them checks [`Account::is_active`] first.
pub async fn by_username(db: impl PgExecutor<'_>, username: &str) -> sqlx::Result<Option<Account>> {
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts WHERE username = $1"
    )))
    .bind(normalize(username))
    .fetch_optional(db)
    .await
}

/// The active account with this email, if the email is set and is a sign-in name: an
/// account [`set_password_sign_in`] turned off is not found by it, so a reset by email
/// cannot reach one.
pub async fn by_email(db: impl PgExecutor<'_>, email: &str) -> sqlx::Result<Option<Account>> {
    let email = normalize(email);
    if email.is_empty() {
        return Ok(None);
    }
    sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM accounts
         WHERE email <> '' AND lower(email) = $1 AND is_active AND password_sign_in"
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
/// a link does): an Argon2 hash, not an empty one.
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
/// nothing, so a stored hash is one that can open the account, unless password
/// sign-in is off.
pub(crate) const USABLE_PASSWORD: &str = "password_sign_in AND password_hash <> ''";

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
    if !owt_auth::password::verify_or_decoy(current, stored.as_deref()).await? {
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
/// own change is [`change_password`]. Refuses a password that breaks a rule, the
/// similarity rule included (the account is passed, not its id, so its username and
/// email are there to check against), and [`Refused::NoPasswordSignIn`] when
/// [`set_password_sign_in`] turned password sign-in off for the account.
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
        .map_err(Error::hash)?;
    // The row's flag, read under its lock: whether it took the password.
    let allowed = sqlx::query_scalar::<_, bool>(
        "WITH target AS (
            SELECT id, password_sign_in FROM accounts
            WHERE id = $2 AND ($3::text IS NULL OR password_hash = $3) FOR UPDATE),
         voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id IN (SELECT id FROM target WHERE password_sign_in)
              AND used_at IS NULL),
         updated AS (
            UPDATE accounts SET password_hash = $1, session_epoch = session_epoch + 1
            WHERE id IN (SELECT id FROM target WHERE password_sign_in))
         SELECT password_sign_in FROM target",
    )
    .bind(&hash)
    .bind(account.id)
    .bind(expected)
    .fetch_optional(db)
    .await?;
    match allowed {
        Some(false) => Err(Refused::NoPasswordSignIn.into()),
        found => Ok(found.is_some()),
    }
}

/// Turn password sign-in on or off for the account: off, no password opens it
/// ([`authenticate`] and [`by_email`] never find it, and [`set_password`] refuses
/// it), so it is reached only by a provider identity, a local identity
/// ([`identities::arrive_as`](crate::identities::arrive_as)) or a sign-in link.
/// Turning it off clears the password and signs the account out everywhere: every
/// session ends and its unused sign-in links are void, so nothing handed out for the
/// way in it closes outlives it (an operator may mint a new link after). Turning it
/// off again, or back on, changes nothing else, and sets no password.
pub async fn set_password_sign_in(
    db: impl PgExecutor<'_>,
    id: i64,
    allowed: bool,
) -> sqlx::Result<()> {
    // `turned_off` is read under the row's lock, so it is the latest committed flag
    // (not this statement's snapshot): when two changes race, whichever turns it off
    // both moves the epoch and voids the links.
    sqlx::query(
        "WITH target AS (
            SELECT id, password_sign_in AND NOT $2 AS turned_off FROM accounts
            WHERE id = $1 FOR UPDATE),
         voided AS (
            UPDATE sign_in_links SET used_at = now(), used_from = 'voided'
            WHERE account_id IN (SELECT id FROM target WHERE turned_off)
              AND used_at IS NULL)
         UPDATE accounts SET session_epoch = session_epoch + target.turned_off::int,
                password_hash = CASE WHEN $2 THEN password_hash ELSE '' END,
                password_sign_in = $2
         FROM target WHERE accounts.id = target.id",
    )
    .bind(id)
    .bind(allowed)
    .execute(db)
    .await?;
    Ok(())
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
