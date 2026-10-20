//! The tables, migrated by the library itself into a ledger of its own.
//!
//! [`run`] applies [`ALL`] with a sqlx [`Migrator`] whose ledger is the table
//! [`LEDGER`] (`_owt_accounts_migrations`), beside the app's `_sqlx_migrations` in the
//! same schema. The app awaits it at start, under the library's advisory lock and
//! before its own migrator, since its tables reference `accounts(id)`; its own
//! `migrations/` holds none of the library's files, and an app's `sqlx migrate run`
//! never touches the library's tables.
//!
//! An app that holds copies of the files in its `migrations/` has them in
//! `_sqlx_migrations` under versions of its own. [`run`] recognises each copy by its checksum (sqlx's SHA-384 of the file, the same bytes
//! as [`ALL`]'s) and records it in [`LEDGER`] as applied, without running it again;
//! a copy whose checksum differs, or that failed, is refused by name. The app then
//! deletes its copies, and its migrator ignores the versions it no longer has (see
//! the README's upgrade notes, and [`forget_copies`]).
//!
//! **A shipped migration is frozen.** sqlx records each applied migration's checksum,
//! here and in an app that adopted copies, and refuses a migration whose text
//! changed. Every change to the schema is a new entry appended to [`ALL`]; a test pins
//! each file's SHA-256.
//!
//! A migration moves the rows already there as well as the schema, so an app that
//! has run the library's migrations for a while is in the same state as a new one.
//! What SQL cannot do exactly (normalizing old rows as sign-in does, a username's
//! lookalike key) [`complete`] does: await it after the migrations run and before
//! serving, at every start (it does next to nothing once done). [`start`] is the whole
//! sequence: [`run`], the app's migrator, [`complete`].
//!
//! The migrations create their tables under fixed names (`accounts`, `account_roles`,
//! `policy_versions`, ...) in the schema they run in. An app that already holds one
//! renames its own first; [`conflicts`] names each that is held.

use std::borrow::Cow;

use sqlx::migrate::{MigrateError, Migration as SqlxMigration, MigrationType, Migrator};
use sqlx::{PgConnection, PgPool, SqlStr};

/// A migration this crate ships.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    /// Its name: the description [`LEDGER`] records, and the file name an app gave its
    /// copy (`<version>_<name>.sql`).
    pub name: &'static str,
    /// Its SQL.
    pub sql: &'static str,
}

/// Every migration, in order: entry `i` is version `i + 1` in [`LEDGER`]. Append;
/// never edit a shipped entry (see the module docs).
pub const ALL: &[Migration] = &[
    Migration {
        name: "owt_accounts",
        sql: include_str!("../migrations/0001_accounts.sql"),
    },
    Migration {
        name: "owt_accounts_roles",
        sql: include_str!("../migrations/0002_account_roles.sql"),
    },
    Migration {
        name: "owt_accounts_constraints",
        sql: include_str!("../migrations/0003_account_constraints.sql"),
    },
    Migration {
        name: "owt_accounts_policies",
        sql: include_str!("../migrations/0004_policies.sql"),
    },
    Migration {
        name: "owt_accounts_local",
        sql: include_str!("../migrations/0005_local_identities.sql"),
    },
];

/// The table [`run`] records the library's migrations in, in the schema they run in
/// (the first on the `search_path`), beside the app's `_sqlx_migrations`.
pub const LEDGER: &str = "_owt_accounts_migrations";

/// The advisory lock [`run`] holds while it adopts and migrates, so replicas starting
/// together migrate once and the rest wait. Distinct from any lock an app's own
/// migrator takes (sqlx also takes its database-wide lock inside it).
pub const LOCK_ID: i64 = 0x6f77_745f_6163_6374;

/// [`ALL`] as a sqlx migrator on [`LEDGER`]: entry `i` is version `i + 1`, described by
/// its name. [`run`] is the way to apply it; this is for inspecting it.
#[must_use]
pub fn migrator() -> Migrator {
    let migrations = ALL
        .iter()
        .zip(1..)
        .map(|(m, version)| {
            SqlxMigration::new(
                version,
                Cow::Borrowed(m.name),
                MigrationType::Simple,
                SqlStr::from_static(m.sql),
                false,
            )
        })
        .collect();
    let mut migrator = Migrator::with_migrations(migrations);
    migrator.dangerous_set_table_name(LEDGER);
    migrator
}

/// What [`run`] did, by the names of [`ALL`]'s entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Migrated {
    /// Entries found applied as the app's copies, and recorded in [`LEDGER`] without
    /// running them.
    pub adopted: Vec<&'static str>,
    /// Entries run now.
    pub applied: Vec<&'static str>,
}

/// Why [`run`] stopped. Nothing was adopted or applied by the call that failed, except
/// migrations sqlx had applied before one failed (each runs in its own transaction).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MigrationError {
    /// The app's `_sqlx_migrations` holds a copy of an entry under that entry's name
    /// whose checksum is not the entry's: the copy was edited, so the schema it made
    /// is not the one the library expects. Nothing is adopted.
    #[error(
        "the app's migration {version} ({description:?}) is owt-accounts' `{name}` with other contents: \
         restore the table it made to the library's, or rename the migration, then retry"
    )]
    EditedCopy {
        /// Its version in `_sqlx_migrations`.
        version: i64,
        /// Its description there.
        description: String,
        /// The entry of [`ALL`] it is named for.
        name: &'static str,
    },
    /// The app's copy of an entry is recorded as failed (`success = false`).
    #[error(
        "the app's migration {version} ({description:?}), owt-accounts' `{name}`, is recorded as failed: \
         repair it as sqlx's \"dirty\" state, then retry"
    )]
    FailedCopy {
        /// Its version in `_sqlx_migrations`.
        version: i64,
        /// Its description there.
        description: String,
        /// The entry of [`ALL`] it is a copy of.
        name: &'static str,
    },
    /// The app applied a copy of a later entry without an earlier one, so there is no
    /// order to adopt in.
    #[error(
        "the app applied owt-accounts' `{applied}` but not the earlier `{missing}`: apply the missing copy, \
         or restore the database, then retry"
    )]
    Gap {
        /// The entry not applied.
        missing: &'static str,
        /// A later entry that was.
        applied: &'static str,
    },
    /// sqlx refused or failed a migration, or [`LEDGER`] records one with another
    /// checksum (`VersionMismatch`, an edited shipped migration) or one this release
    /// does not have (`VersionMissing`, a database a newer release migrated).
    #[error("owt-accounts' migrations: {0}")]
    Migrate(#[from] MigrateError),
    /// The database.
    #[error("owt-accounts' migrations: {0}")]
    Database(#[from] sqlx::Error),
}

/// Apply [`ALL`] to the database, recording them in [`LEDGER`]; await it at every
/// start, before the app's own migrator and [`complete`]. It holds the advisory lock
/// [`LOCK_ID`] on one connection throughout, so replicas starting together migrate
/// once, and the others find nothing to do.
///
/// First it adopts the app's copies: an entry not yet in [`LEDGER`] whose exact text
/// `_sqlx_migrations` records as successfully applied (by sqlx's checksum, under any
/// version and description) is recorded as applied without running. Copies must
/// form an unbroken run from the first entry not yet recorded. A row there named as an
/// entry (`owt_accounts_roles`, as sqlx describes `0006_owt_accounts_roles.sql`)
/// whose checksum differs, or that failed, stops it with an error naming the row.
/// Then it runs the entries still missing, in order. The app's `_sqlx_migrations` is
/// read, never written. Calling it again changes nothing; a run cut short (a pod
/// killed mid-start) leaves every adopted or applied entry recorded, and the next
/// resumes from there.
///
/// A copy is recognised by its text, or refused by its name; one both edited and
/// renamed is neither. Copies before it are adopted, and the entry it was is applied
/// anew and fails at the first name it holds (`relation "accounts" already
/// exists`); [`conflicts`] names them.
///
/// # Errors
///
/// [`MigrationError`]: an edited, failed or out-of-order copy, sqlx refusing the
/// ledger (an edited shipped entry, a newer release's), or the database. The
/// connection is closed rather than pooled after a failure, so no lock outlives it.
pub async fn run(pool: &PgPool) -> Result<Migrated, MigrationError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_ID)
        .execute(&mut *conn)
        .await?;
    let result = run_locked(&mut conn).await;
    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_ID)
        .execute(&mut *conn)
        .await;
    if result.is_err() || unlocked.is_err() {
        // A failed sqlx run returns before releasing its own advisory lock, and a
        // failed unlock leaves this one: closing the connection ends both.
        conn.close_on_drop();
    }
    let done = result?;
    unlocked?;
    if !done.adopted.is_empty() || !done.applied.is_empty() {
        tracing::info!(adopted = ?done.adopted, applied = ?done.applied, "owt-accounts migrations");
    }
    Ok(done)
}

/// The versions [`LEDGER`] records, or none when it does not exist yet.
async fn recorded(conn: &mut PgConnection) -> Result<Vec<i64>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(LEDGER)
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT version FROM {LEDGER} WHERE success ORDER BY version"
    )))
    .fetch_all(&mut *conn)
    .await
}

/// The rows of the app's `_sqlx_migrations` (found on the `search_path`, as sqlx finds
/// it): version, description, success, checksum.
async fn app_ledger(
    conn: &mut PgConnection,
) -> Result<Vec<(i64, String, bool, Vec<u8>)>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT version, description, success, checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *conn)
    .await
}

/// The entry an app's copy describes, as sqlx describes a file: the name after the
/// version, underscores as spaces.
fn named(description: &str) -> Option<(usize, &'static Migration)> {
    ALL.iter()
        .enumerate()
        .find(|(_, m)| m.name.replace('_', " ") == description || m.name == description)
}

/// The version [`LEDGER`] gives entry `i` of [`ALL`].
fn version_of(i: usize) -> i64 {
    i64::try_from(i).map_or(i64::MAX, |i| i + 1)
}

async fn run_locked(conn: &mut PgConnection) -> Result<Migrated, MigrationError> {
    let migrator = migrator();
    let before = recorded(conn).await?;
    let rows = app_ledger(conn).await?;
    let pending = |i: usize| !before.contains(&version_of(i));

    // A copy under an entry's name must be that entry, applied.
    for (version, description, success, checksum) in &rows {
        let Some((i, m)) = named(description) else {
            continue;
        };
        if !pending(i) {
            continue;
        }
        if !success {
            return Err(MigrationError::FailedCopy {
                version: *version,
                description: description.clone(),
                name: m.name,
            });
        }
        if checksum[..] != migrator.migrations[i].checksum[..] {
            return Err(MigrationError::EditedCopy {
                version: *version,
                description: description.clone(),
                name: m.name,
            });
        }
    }

    // The pending entries the app applied as copies, by checksum.
    let copied: Vec<usize> = (0..ALL.len())
        .filter(|&i| pending(i))
        .filter(|&i| {
            rows.iter()
                .any(|(_, _, ok, c)| *ok && c[..] == migrator.migrations[i].checksum[..])
        })
        .collect();
    let mut adopted = Vec::new();
    if let Some(&last) = copied.last() {
        if let Some(missing) = (0..=last).find(|&i| pending(i) && !copied.contains(&i)) {
            return Err(MigrationError::Gap {
                missing: ALL[missing].name,
                applied: ALL[last].name,
            });
        }
        migrator
            .run_direct(Some(version_of(last)), &mut *conn, true)
            .await?;
        adopted = copied.iter().map(|&i| ALL[i].name).collect();
    }

    migrator.run_direct(None, &mut *conn, false).await?;
    let after = recorded(conn).await?;
    let applied = after
        .iter()
        .filter(|v| !before.contains(v))
        .filter_map(|v| usize::try_from(*v - 1).ok())
        .filter(|i| !copied.contains(i))
        .filter_map(|i| ALL.get(i).map(|m| m.name))
        .collect();
    Ok(Migrated { adopted, applied })
}

/// Delete from the app's `_sqlx_migrations` the rows of copies [`LEDGER`] has adopted,
/// returning their versions. Optional, and only once no running binary still carries
/// the copies (after a full rollout): a binary that does would see its copies as not
/// applied and run them again, failing at `CREATE TABLE accounts`. Afterwards the app's
/// migrator no longer needs `set_ignore_missing(true)` for them. It takes no lock: it
/// deletes only rows of copies [`LEDGER`] has recorded, so a concurrent [`run`] finds
/// the same entries recorded either way.
///
/// # Errors
///
/// The database.
pub async fn forget_copies(pool: &PgPool) -> sqlx::Result<Vec<i64>> {
    let mut conn = pool.acquire().await?;
    let recorded = recorded(&mut conn).await?;
    let rows = app_ledger(&mut conn).await?;
    let migrator = migrator();
    let adopted: Vec<Vec<u8>> = recorded
        .iter()
        .filter_map(|v| usize::try_from(*v - 1).ok())
        .filter_map(|i| migrator.migrations.get(i))
        .map(|m| m.checksum.to_vec())
        .collect();
    let versions: Vec<i64> = rows
        .iter()
        .filter(|(_, _, ok, c)| *ok && adopted.contains(c))
        .map(|(v, ..)| *v)
        .collect();
    if !versions.is_empty() {
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ANY($1)")
            .bind(&versions)
            .execute(&mut *conn)
            .await?;
    }
    Ok(versions)
}

/// The start-up sequence, in the order the tables need: [`run`] (the library's own
/// migrator), then `app` (the app's migrations, such as
/// `owt_runtime::db::migrate_locked(&pool, &MIGRATOR, LOCK)`), then [`complete`]. Await
/// it at every start and before serving; a `migrate` subcommand for CI and
/// `just migrate` calls the same function. [`run`] and [`complete`] log what they did;
/// the first failure stops the sequence and is returned, its context naming the step, for
/// the caller to report once (print it with `{err:#}` for the whole chain).
///
/// An app whose own migrations must partly run before the library's (one that renamed
/// an `accounts` of its own out of the way) cannot be expressed as one step before
/// [`run`] and one after: it calls `migrate_locked_to`, [`run`], `migrate_locked` and
/// [`complete`] itself. Through `start`, such an app stops in [`run`], which fails on the
/// name its own table already holds.
///
/// # Errors
///
/// The step that failed, named in the error's context: [`MigrationError`] from the
/// library's migrations, `app`'s own error, or the database from [`complete`].
pub async fn start<F, Fut, E>(pool: &PgPool, app: F) -> anyhow::Result<Completed>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Into<anyhow::Error>,
{
    use anyhow::Context as _;

    run(pool).await.context("owt-accounts migrations")?;
    app()
        .await
        .map_err(Into::into)
        .context("the app's migrations")?;
    complete(pool)
        .await
        .context("completing the accounts tables")
}

/// What [`complete`] changed, for the operator to read (it is logged too). An owner
/// whose username was renamed signs in with the new one, or by email or a provider;
/// tell them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Completed {
    /// Accounts whose username changed: normalized to the form sign-in looks up, and
    /// given a suffix where that form was another account's.
    pub renamed: Vec<Renamed>,
    /// Accounts whose email was cleared: not an address, or the same address as
    /// another account's once normalized.
    pub emails_cleared: Vec<i64>,
    /// Accounts whose password hash was cleared: one the library cannot verify (a
    /// legacy format), which never opened the account.
    pub passwords_cleared: Vec<i64>,
    /// Accounts given their lookalike key.
    pub keyed: u64,
    /// Accounts that could not be completed this time (the error is logged); the next
    /// call tries them again.
    pub failed: Vec<i64>,
    /// Every constraint of [`ALL`] now holds for every row.
    pub validated: bool,
}

/// An account [`complete`] renamed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Renamed {
    /// The account.
    pub id: i64,
    /// Its username before.
    pub from: String,
    /// Its username now.
    pub to: String,
}

/// The constraints `0003` and `0005` add `NOT VALID`, by table, validated once the rows
/// hold them.
const DEFERRED: &[(&str, &str)] = &[
    ("accounts", "accounts_password_hash_form"),
    ("accounts", "accounts_username_nfkc"),
    ("accounts", "accounts_email_form"),
    ("accounts", "accounts_session_epoch_check"),
    ("accounts", "accounts_password_sign_in_hash"),
    ("account_identities", "account_identities_named"),
    ("sign_in_links", "sign_in_links_lifetime"),
    ("sign_in_links", "sign_in_links_digest"),
];

/// Finish what [`ALL`] cannot do in SQL, and await it before serving: move every
/// account made before `0003` to the form the library stores, in Rust, as sign-in
/// normalizes what is typed (SQL's `normalize` and `lower` differ from it at the
/// edges: the final sigma, a database's locale, its Unicode version). For each
/// account without a lookalike key, in its own short transaction:
///
/// - the username is [normalized](crate::store::normalize) (`@` becomes `-`); one
///   that would become another account's takes its id as a suffix (`admin-42`), or
///   the first free name after it;
/// - the email is normalized, and cleared when it is not an address or would become
///   another account's;
/// - a password hash the library cannot verify is cleared (it opened nothing);
/// - a negative session epoch becomes 0;
/// - the lookalike key ([`store::skeleton`](crate::store::skeleton)) is stored; an old
///   account whose name is a lookalike of an earlier one keeps it, under a key that
///   carries its id, so only new names are held to the rule.
///
/// Then identities with no provider or subject are deleted, sign-in links are cut to 30
/// days (one whose token is not a SHA-256 digest is deleted), and the constraints `0003` and `0005` added are validated (which locks no writer
/// out). Call it at every start: once done it reads one index and the catalog. An
/// account it cannot complete is logged and left for the next call; it never fails
/// the start over one row.
///
/// # Errors
///
/// The database, for anything but one account's completion.
pub async fn complete(pool: &sqlx::PgPool) -> sqlx::Result<Completed> {
    let mut done = Completed::default();
    let mut after = i64::MIN;
    loop {
        let batch: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM accounts WHERE username_skeleton IS NULL AND id > $1
             ORDER BY id LIMIT 500",
        )
        .bind(after)
        .fetch_all(pool)
        .await?;
        let Some(&last) = batch.last() else { break };
        after = last;
        for id in batch {
            if complete_account(pool, id, &mut done).await.is_err() {
                done.failed.push(id);
            }
        }
    }
    // Once more for those that failed: most often a race (another replica, or a
    // sign-up, took the free name or address first), which a second look resolves.
    for id in std::mem::take(&mut done.failed) {
        if let Err(e) = complete_account(pool, id, &mut done).await {
            tracing::error!(account = id, error = %e, "could not complete an account");
            done.failed.push(id);
        }
    }
    let pending: Vec<(String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text, conname FROM pg_constraint
         WHERE NOT convalidated AND conname = ANY($1)",
    )
    .bind(DEFERRED.iter().map(|(_, c)| *c).collect::<Vec<_>>())
    .fetch_all(pool)
    .await?;
    let unkeyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE username_skeleton IS NULL)",
    )
    .fetch_one(pool)
    .await?;
    let mut validated = true;
    for (table, constraint) in DEFERRED {
        if !pending.iter().any(|(_, c)| c == constraint) {
            continue;
        }
        if *table == "accounts" && unkeyed {
            // Rows not yet moved (an older replica still writing, or a failed one).
            validated = false;
            continue;
        }
        match *constraint {
            "account_identities_named" => {
                let gone = sqlx::query(
                    "DELETE FROM account_identities WHERE provider = '' OR subject = ''",
                )
                .execute(pool)
                .await?
                .rows_affected();
                if gone > 0 {
                    tracing::info!(gone, "deleted identities with no subject");
                }
            }
            "sign_in_links_lifetime" => {
                sqlx::query(
                    "UPDATE sign_in_links SET expires_at = created_at + interval '30 days'
                     WHERE expires_at > created_at + interval '30 days'",
                )
                .execute(pool)
                .await?;
            }
            // Not a SHA-256: no token could ever match it.
            "sign_in_links_digest" => {
                sqlx::query("DELETE FROM sign_in_links WHERE octet_length(token_sha256) <> 32")
                    .execute(pool)
                    .await?;
            }
            _ => {}
        }
        // Each name is one of DEFERRED's, never input.
        let sql = format!("ALTER TABLE {table} VALIDATE CONSTRAINT {constraint}");
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(sql)).execute(pool).await {
            tracing::warn!(constraint, error = %e, "a constraint does not hold for every row yet");
            validated = false;
        }
    }
    done.validated = validated;
    if done.keyed > 0 || !done.failed.is_empty() {
        tracing::info!(
            renamed = ?done.renamed,
            emails_cleared = ?done.emails_cleared,
            passwords_cleared = ?done.passwords_cleared,
            keyed = done.keyed,
            failed = ?done.failed,
            validated = done.validated,
            "completed the accounts tables"
        );
    }
    Ok(done)
}

/// A unique violation of `constraint`.
fn violates(e: &sqlx::Error, constraint: &str) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation() && d.constraint() == Some(constraint))
}

/// The first of `base`, `base-<id>`, `base-<id>-<n>` no other account has.
async fn free_username(conn: &mut sqlx::PgConnection, base: &str, id: i64) -> sqlx::Result<String> {
    let mut name = base.to_owned();
    for n in 1.. {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE username = $1 AND id <> $2)",
        )
        .bind(&name)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
        if !taken {
            break;
        }
        name = if n == 1 {
            format!("{base}-{id}")
        } else {
            format!("{base}-{id}-{n}")
        };
    }
    Ok(name)
}

/// Store `key` as the account's lookalike key; an old lookalike's carries its id,
/// which no username's can (`@` is in none, so in no skeleton of one), with a count
/// after if even that is somehow held.
async fn store_skeleton(conn: &mut sqlx::PgConnection, id: i64, key: &str) -> sqlx::Result<()> {
    let mut candidate = key.to_owned();
    for n in 1..=100 {
        let mut attempt = sqlx::Connection::begin(&mut *conn).await?;
        let set = sqlx::query("UPDATE accounts SET username_skeleton = $2 WHERE id = $1")
            .bind(id)
            .bind(&candidate)
            .execute(&mut *attempt)
            .await;
        match set {
            Ok(_) => return attempt.commit().await,
            Err(e) if violates(&e, "accounts_username_skeleton_key") => {
                attempt.rollback().await?;
                candidate = if n == 1 {
                    format!("{key}@{id}")
                } else {
                    format!("{key}@{id}@{n}")
                };
            }
            Err(e) => return Err(e),
        }
    }
    Err(sqlx::Error::Protocol(format!(
        "no free lookalike key for account {id}"
    )))
}

/// One account, in its own transaction, under its row's lock.
async fn complete_account(pool: &sqlx::PgPool, id: i64, done: &mut Completed) -> sqlx::Result<()> {
    use crate::store::{normalize, skeleton};
    let mut tx = pool.begin().await?;
    let Some((username, email, hash)) = sqlx::query_as::<_, (String, String, String)>(
        "SELECT username, email, password_hash FROM accounts
         WHERE id = $1 AND username_skeleton IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(());
    };

    // The username: the first of its stored form, then that with the id, then with a
    // count, that no other account has.
    let base = match normalize(&username).replace('@', "-") {
        b if b.is_empty() => format!("user-{id}"),
        b => b,
    };
    let name = if base == username {
        base
    } else {
        free_username(&mut tx, &base, id).await?
    };

    // The email: stored form, an address, and no one else's.
    let mut address = normalize(&email);
    let shaped = address
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty());
    if !shaped {
        address.clear();
    } else if address != email {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts
                            WHERE email <> '' AND lower(email) = lower($1) AND id <> $2)",
        )
        .bind(&address)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            address.clear();
        }
    }

    let hash_kept = hash.is_empty() || owt_auth::password::usable(&hash);
    sqlx::query(
        "UPDATE accounts SET username = $2, email = $3,
                password_hash = CASE WHEN $4 THEN password_hash ELSE '' END,
                session_epoch = greatest(session_epoch, 0)
         WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&address)
    .bind(hash_kept)
    .execute(&mut *tx)
    .await?;

    store_skeleton(&mut tx, id, &skeleton(&name)).await?;
    tx.commit().await?;

    if name != username {
        done.renamed.push(Renamed {
            id,
            from: username,
            to: name,
        });
    }
    if address.is_empty() && !email.is_empty() {
        done.emails_cleared.push(id);
    }
    if !hash_kept {
        done.passwords_cleared.push(id);
    }
    done.keyed += 1;
    Ok(())
}

/// The SHA-256 of each of [`ALL`], in order, as released. A changed digest means a
/// shipped migration was edited, which breaks every app's next deploy: revert it and
/// write the change as a new file, pinned here as a new entry.
#[cfg(test)]
const SHIPPED_SHA256: &[&str] = &[
    "743f8095a1df80c56eccc7a101df0e6ad6bcbaf567a68dc82f50d2f5f2f631b4",
    "0e6d42a67ddabfb50f56650fe85ff0bc810c4b3230a1115706db467ea27b2338",
    "4e910454cfdd01ef4559772fd8b4140f39d887383ebb2de06c920924161152e0",
    "629cca392e80505f93a71a9eb9d13683ef82f31790d682363d346ebfb2f32f52",
    "2952542fa9af6f8c1c7ee21987676fd1ed42cb0d18c752b485d4f315f4eccb18",
];

/// The names each of [`ALL`] gives a relation (table, index, sequence) in the schema
/// it runs in, by migration. Those Postgres picks itself (a key's index, an identity's
/// sequence) are here too: when one is held, Postgres picks another silently, and the
/// library matches a unique violation on `accounts_username_key`.
const RELATIONS: &[(&str, &[&str])] = &[
    (
        "owt_accounts",
        &[
            "accounts",
            "accounts_pkey",
            "accounts_id_seq",
            "accounts_username_key",
            "accounts_email_key",
            "account_identities",
            "account_identities_pkey",
            "account_identities_id_seq",
            "account_identities_provider_subject_key",
            "account_identities_account",
            "sign_in_links",
            "sign_in_links_pkey",
            "sign_in_links_account",
        ],
    ),
    (
        "owt_accounts_roles",
        &["account_roles", "account_roles_pkey", "account_roles_role"],
    ),
    (
        "owt_accounts_constraints",
        &["accounts_username_skeleton_key"],
    ),
    (
        "owt_accounts_policies",
        &[
            "policy_versions",
            "policy_versions_pkey",
            "policy_versions_id_seq",
            "policy_versions_kind_version_key",
            "policy_acceptances",
            "policy_acceptances_pkey",
            "policy_acceptances_version",
            "policy_acceptance_events",
            "policy_acceptance_events_pkey",
            "policy_acceptance_events_id_seq",
            "policy_acceptance_events_account",
        ],
    ),
    (
        "owt_accounts_local",
        &[
            "account_local_identities",
            "account_local_identities_pkey",
            "account_local_identities_account",
        ],
    ),
];

/// The functions (of no arguments) each of [`ALL`] creates, by migration.
const FUNCTIONS: &[(&str, &[&str])] = &[(
    "owt_accounts_policies",
    &["policy_versions_immutable", "policy_versions_keep_current"],
)];

/// The columns each of [`ALL`] adds to a table an earlier one created, as
/// `table.column`, by migration.
const COLUMNS: &[(&str, &[&str])] = &[
    ("owt_accounts_constraints", &["accounts.username_skeleton"]),
    ("owt_accounts_local", &["accounts.password_sign_in"]),
];

/// The constraints each of [`ALL`] adds to a table an earlier one created, as
/// `table.constraint`, by migration.
const CONSTRAINTS: &[(&str, &[&str])] = &[
    (
        "owt_accounts_constraints",
        &[
            "accounts.accounts_username_skeleton_form",
            "accounts.accounts_password_hash_form",
            "accounts.accounts_username_nfkc",
            "accounts.accounts_email_form",
            "accounts.accounts_session_epoch_check",
            "account_identities.account_identities_named",
            "sign_in_links.sign_in_links_lifetime",
            "sign_in_links.sign_in_links_digest",
        ],
    ),
    (
        "owt_accounts_local",
        &["accounts.accounts_password_sign_in_hash"],
    ),
];

/// A name one of [`ALL`] takes that something of the app's already holds, from
/// [`conflicts`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Conflict {
    /// The migration that takes the name ([`Migration::name`]).
    pub migration: &'static str,
    /// The name; a column or constraint's as `table.name`.
    pub name: &'static str,
    /// The schema it is held in: the one the migrations create their objects in.
    pub schema: String,
    /// What holds it now: `table`, `index`, `sequence`, `view`, `materialized view`,
    /// `foreign table`, `type`, `function`, `column` or `constraint`.
    pub held_by: &'static str,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{schema}.{name} is already a {held_by}, and owt-accounts' `{migration}` migration \
             creates {name}: rename the app's in a migration placed before owt-accounts' files",
            schema = self.schema,
            name = self.name,
            held_by = self.held_by,
            migration = self.migration,
        )
    }
}

/// The checksums of the migrations applied, in the library's ledger or as the app's
/// copies in its own: sqlx's checksum, the SHA-384 of the text, either way.
async fn applied_checksums(pool: &sqlx::PgPool) -> sqlx::Result<Vec<Vec<u8>>> {
    let mut applied = Vec::new();
    for table in [LEDGER, "_sqlx_migrations"] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(pool)
            .await?;
        if exists {
            applied.extend(
                sqlx::query_scalar::<_, Vec<u8>>(sqlx::AssertSqlSafe(format!(
                    "SELECT checksum FROM {table} WHERE success"
                )))
                .fetch_all(pool)
                .await?,
            );
        }
    }
    Ok(applied)
}

/// The names [`ALL`] would take that the database already gives something else, in
/// the schema the migrations run in (`current_schema()`, the first on the
/// `search_path`). Empty when there is nothing in the way.
///
/// A migration [`LEDGER`] records as applied, or the app's `_sqlx_migrations` records
/// as a copy (by its checksum; both found on the `search_path` as sqlx finds them), is
/// installed, and what it created is the library's own; the names of every other
/// migration are checked against the tables, indexes, sequences, views, types and
/// functions there, and the columns and constraints it adds to an existing table (an
/// `accounts.password_sign_in` of the app's own) against that table's. A held table,
/// index, column or constraint name fails that migration; a held name Postgres would
/// have picked itself (a key's index, an identity's sequence) is taken silently with a
/// suffix instead, so the library does not recognize the key. Call it when the
/// migrations fail, to say why, or from a test against a copy of the app's schema
/// before adopting the crate.
///
/// # Errors
///
/// The database.
///
/// ```no_run
/// # async fn start(pool: sqlx::PgPool) -> anyhow::Result<()> {
/// if let Err(e) = owt_accounts::migrations::run(&pool).await {
///     for clash in owt_accounts::migrations::conflicts(&pool).await? {
///         tracing::error!(%clash, "a name owt-accounts needs is taken");
///     }
///     return Err(e.into());
/// }
/// # Ok(()) }
/// ```
pub async fn conflicts(pool: &sqlx::PgPool) -> sqlx::Result<Vec<Conflict>> {
    use sha2::{Digest, Sha384};

    let applied = applied_checksums(pool).await?;
    let pending = |name: &str| {
        ALL.iter()
            .any(|m| m.name == name && !applied.iter().any(|c| c[..] == Sha384::digest(m.sql)[..]))
    };
    let names =
        |of: &[(&'static str, &'static [&'static str])]| -> Vec<(&'static str, &'static str)> {
            of.iter()
                .filter(|(migration, _)| pending(migration))
                .flat_map(|(migration, names)| names.iter().map(move |n| (*migration, *n)))
                .collect()
        };
    let relations = names(RELATIONS);
    let functions = names(FUNCTIONS);
    let columns = names(COLUMNS);
    let constraints = names(CONSTRAINTS);
    if [&relations, &functions, &columns, &constraints]
        .iter()
        .all(|n| n.is_empty())
    {
        return Ok(Vec::new());
    }

    // What holds each name in the current schema: a relation (by its kind; a
    // composite type is one too), another type (`T`), a function of no arguments
    // (`F`), or a column (`C`) or constraint (`K`) of the table named before the dot.
    let held: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT current_schema()::text, relname::text, relkind::text FROM pg_class
         WHERE relnamespace = current_schema()::regnamespace AND relname = ANY($1)
         UNION ALL
         SELECT current_schema()::text, typname::text, 'T' FROM pg_type
         WHERE typnamespace = current_schema()::regnamespace AND typrelid = 0
           AND typname = ANY($1)
         UNION ALL
         SELECT current_schema()::text, proname::text, 'F' FROM pg_proc
         WHERE pronamespace = current_schema()::regnamespace AND pronargs = 0
           AND proname = ANY($2)
         UNION ALL
         SELECT current_schema()::text, m.name, 'C' FROM unnest($3::text[]) AS m(name)
         JOIN pg_attribute a
           ON a.attrelid = to_regclass(quote_ident(current_schema()) || '.'
                                       || quote_ident(split_part(m.name, '.', 1)))
          AND a.attname = split_part(m.name, '.', 2) AND a.attnum > 0 AND NOT a.attisdropped
         UNION ALL
         SELECT current_schema()::text, m.name, 'K' FROM unnest($4::text[]) AS m(name)
         JOIN pg_constraint k
           ON k.conrelid = to_regclass(quote_ident(current_schema()) || '.'
                                       || quote_ident(split_part(m.name, '.', 1)))
          AND k.conname = split_part(m.name, '.', 2)",
    )
    .bind(relations.iter().map(|(_, n)| *n).collect::<Vec<_>>())
    .bind(functions.iter().map(|(_, n)| *n).collect::<Vec<_>>())
    .bind(columns.iter().map(|(_, n)| *n).collect::<Vec<_>>())
    .bind(constraints.iter().map(|(_, n)| *n).collect::<Vec<_>>())
    .fetch_all(pool)
    .await?;

    let every = || {
        relations
            .iter()
            .chain(&functions)
            .chain(&columns)
            .chain(&constraints)
    };
    let mut found = Vec::new();
    for (schema, name, kind) in held {
        let Some(&(migration, name)) = every().find(|(_, n)| *n == name) else {
            continue;
        };
        found.push(Conflict {
            migration,
            name,
            schema,
            held_by: match kind.as_str() {
                "r" | "p" => "table",
                "i" | "I" => "index",
                "S" => "sequence",
                "v" => "view",
                "m" => "materialized view",
                "f" => "foreign table",
                "F" => "function",
                "C" => "column",
                "K" => "constraint",
                _ => "type",
            },
        });
    }
    // In the order the migrations take the names.
    found.sort_by_key(|c| every().position(|(_, n)| *n == c.name));
    Ok(found)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn shipped_migrations_are_frozen() {
        assert_eq!(
            ALL.len(),
            SHIPPED_SHA256.len(),
            "pin each migration's SHA-256 in SHIPPED_SHA256, in order"
        );
        for (migration, pinned) in ALL.iter().zip(SHIPPED_SHA256) {
            let digest = Sha256::digest(migration.sql.as_bytes());
            let hex = digest.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
            assert_eq!(
                &hex, pinned,
                "the shipped `{}` migration changed. Every database that applied it records \
                 its checksum, and sqlx then refuses to start, so revert the edit and write \
                 the change as a new migration file (then pin that one)",
                migration.name
            );
        }
    }
}
