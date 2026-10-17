//! The tables, as SQL the app installs.
//!
//! sqlx keeps one ledger of applied migrations per database, so a library cannot run
//! a migrator of its own beside the app's. Instead the app copies each file here into
//! its `migrations/` directory, under a version of its choosing (first: the app's
//! tables reference `accounts`), and a test calls [`assert_installed`] so an edited
//! or missing copy fails the build rather than the deploy.
//!
//! **A shipped migration is frozen.** sqlx records each applied file's checksum, and
//! `migrate run` refuses a file whose checksum changed. An app re-copies these files
//! when it upgrades, so a changed byte here (a comment, even) would fail every app's
//! next deploy against a database that applied the old text. Every change to the
//! schema is a new file appended to [`ALL`]; a test pins each file's SHA-256.
//!
//! A migration moves the rows already there as well as the schema, so an app that
//! has run the library's migrations for a while is in the same state as a new one.
//! What SQL cannot do exactly (normalizing old rows as sign-in does, a username's
//! lookalike key) [`complete`] does: await it after the migrations run and before
//! serving, at every start (it does next to nothing once done).
//!
//! The migrations create their tables under fixed names (`accounts`, `account_roles`,
//! `policy_versions`, ...) in the schema they run in. An app that already holds one
//! renames its own first; [`conflicts`] names each that is held.

use std::path::Path;

/// A migration this crate ships.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    /// Its name, for the file the app writes (`<version>_<name>.sql`).
    pub name: &'static str,
    /// Its SQL, to copy byte for byte.
    pub sql: &'static str,
}

/// Every migration, in order. Append; never edit a shipped entry (see the module
/// docs).
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
/// Then identities with no subject are deleted, sign-in links are cut to 30 days,
/// and the constraints `0003` and `0005` added are validated (which locks no writer
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

/// Each of [`ALL`] is present, unaltered, in the app's migrations directory `dir`;
/// panics naming the first that is not. Call it from a test.
///
/// # Panics
///
/// When `dir` cannot be read, or a migration is missing from it or differs.
///
/// ```no_run
/// #[test]
/// fn the_accounts_migrations_are_installed() {
///     owt_accounts::migrations::assert_installed("migrations");
/// }
/// ```
pub fn assert_installed(dir: impl AsRef<Path>) {
    let dir = dir.as_ref();
    let files: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|x| x == "sql"))
        .map(|entry| {
            let path = entry.path();
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            (path.display().to_string(), body)
        })
        .collect();
    for migration in ALL {
        let exact = files.iter().any(|(_, body)| body == migration.sql);
        if exact {
            continue;
        }
        // Name the nearest culprit: a file carrying the first line's marker.
        let marker = migration.sql.lines().next().unwrap_or_default();
        let edited = files
            .iter()
            .find(|(_, body)| body.lines().next() == Some(marker))
            .map(|(path, _)| path.as_str());
        match edited {
            Some(path) => panic!(
                "{path} differs from owt-accounts' `{}` migration: copy it again unaltered \
                 (add columns in a migration of the app's own)",
                migration.name
            ),
            None => panic!(
                "owt-accounts' `{}` migration is not in {}: write owt_accounts::migrations::ALL[..].sql \
                 to a file there, under its next unused version (never one already applied)",
                migration.name,
                dir.display()
            ),
        }
    }
}

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

/// The names [`ALL`] would take that the database already gives something else, in
/// the schema the migrations run in (`current_schema()`, the first on the
/// `search_path`). Empty when there is nothing in the way.
///
/// A migration sqlx's ledger (`_sqlx_migrations`, found on the `search_path` as sqlx
/// finds it) records as applied, by its checksum, is installed, and what it created
/// is the library's own; the names of every other migration are checked against the
/// tables, indexes, sequences, views, types and functions there, and the columns and
/// constraints it adds to an existing table (an `accounts.password_sign_in` of the
/// app's own) against that table's. A held table, index, column or constraint name
/// fails that migration; a held name Postgres would have
/// picked itself (a key's index, an identity's sequence) is taken silently with a
/// suffix instead, so the library no longer recognizes the key. Call it when the
/// migrations fail, to say why, or from a test against a copy of the app's schema
/// before adopting the crate.
///
/// # Errors
///
/// The database.
///
/// ```no_run
/// # async fn start(pool: sqlx::PgPool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
/// if let Err(e) = owt_runtime::db::migrate_locked(&pool, migrator, 8_531_207).await {
///     for clash in owt_accounts::migrations::conflicts(&pool).await? {
///         tracing::error!(%clash, "a name owt-accounts needs is taken");
///     }
///     return Err(e);
/// }
/// # Ok(()) }
/// ```
pub async fn conflicts(pool: &sqlx::PgPool) -> sqlx::Result<Vec<Conflict>> {
    use sha2::{Digest, Sha384};

    let ledger: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    let applied: Vec<Vec<u8>> = if ledger {
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE success")
            .fetch_all(pool)
            .await?
    } else {
        Vec::new()
    };
    // sqlx's checksum is the SHA-384 of the file, which assert_installed holds to
    // ALL's text byte for byte.
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
                "the shipped `{}` migration changed. Apps re-copy it and sqlx then refuses \
                 the file at deploy, so revert the edit and write the change as a new \
                 migration file (then pin that one)",
                migration.name
            );
        }
    }

    #[test]
    fn an_exact_copy_passes_and_an_edited_one_is_named() {
        let dir = std::env::temp_dir().join(format!("owt-accounts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("0001_owt_accounts.sql");
        std::fs::write(&file, ALL[0].sql).unwrap();
        let roles = dir.join("0002_owt_accounts_roles.sql");
        std::fs::write(&roles, ALL[1].sql).unwrap();
        let constraints = dir.join("0003_owt_accounts_constraints.sql");
        std::fs::write(&constraints, ALL[2].sql).unwrap();
        let policies = dir.join("0004_owt_accounts_policies.sql");
        std::fs::write(&policies, ALL[3].sql).unwrap();
        let local = dir.join("0005_owt_accounts_local.sql");
        std::fs::write(&local, ALL[4].sql).unwrap();
        assert_installed(&dir);
        std::fs::write(&file, format!("{}\n-- edited", ALL[0].sql)).unwrap();
        let err = std::panic::catch_unwind(|| assert_installed(&dir)).unwrap_err();
        let text = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(
            text.contains("differs") && text.contains("0001_owt_accounts.sql"),
            "{text}"
        );
        std::fs::remove_file(&file).unwrap();
        let err = std::panic::catch_unwind(|| assert_installed(&dir)).unwrap_err();
        let text = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(text.contains("is not in"), "{text}");
        std::fs::remove_file(&roles).unwrap();
        std::fs::remove_file(&constraints).unwrap();
        std::fs::remove_file(&policies).unwrap();
        std::fs::remove_file(&local).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
