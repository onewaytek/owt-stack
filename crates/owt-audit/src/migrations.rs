//! The tables, migrated by the library into a ledger of its own.

use std::borrow::Cow;

use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{PgPool, SqlStr};

/// The table [`migrate`] records the library's migrations in, beside the app's
/// `_sqlx_migrations`.
pub const LEDGER: &str = "_owt_audit_migrations";

/// The advisory lock [`migrate`] holds while it migrates.
pub const LOCK_ID: i64 = 0x6f77_745f_6175_6474;

/// Every migration, in order: entry `i` is version `i + 1` in [`LEDGER`]. Append
/// only; a shipped entry is never edited (a test pins each one).
const ALL: &[(&str, &str)] = &[("owt_audit", include_str!("../migrations/0001_audit.sql"))];

/// The migrations as a sqlx migrator on [`LEDGER`], for inspection; [`migrate`]
/// applies it.
#[must_use]
pub fn migrator() -> Migrator {
    let migrations = ALL
        .iter()
        .zip(1..)
        .map(|((name, sql), version)| {
            Migration::new(
                version,
                Cow::Borrowed(*name),
                MigrationType::Simple,
                SqlStr::from_static(sql),
                false,
            )
        })
        .collect();
    let mut migrator = Migrator::with_migrations(migrations);
    migrator.dangerous_set_table_name(LEDGER);
    migrator
}

/// Create or update the tables in the pool's schema, under [`LOCK_ID`]. Run it as
/// the role that owns the schema (the migration role), not the app's role.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    owt_runtime::db::migrate_locked(pool, &migrator(), LOCK_ID).await
}

/// Narrow the app's runtime `role` on the audit tables to what the README's least
/// privilege names: `SELECT` and `INSERT` on `owt_audit_events`, `SELECT` on
/// `owt_audit_anchors`, nothing else (no `UPDATE`, `DELETE`, `TRUNCATE`, `TRIGGER`).
/// Run it as the schema's owner after [`migrate`] and after
/// [`owt_runtime::db::grant_runtime`], which grants every table more. The role that
/// anchors is another, given `INSERT` on the anchors by hand. Calling it again
/// changes nothing.
///
/// # Errors
///
/// When `role` is not a role name or a statement fails (the tables not migrated yet).
pub async fn grant_runtime(pool: &PgPool, role: &str) -> anyhow::Result<()> {
    let role = owt_runtime::db::quoted_role(role)?;
    let mut tx = pool.begin().await?;
    for sql in [
        format!("REVOKE ALL ON owt_audit_events, owt_audit_anchors FROM {role}"),
        format!("GRANT SELECT, INSERT ON owt_audit_events TO {role}"),
        format!("GRANT SELECT ON owt_audit_anchors TO {role}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    /// A shipped migration is frozen: a changed file fails here before it fails in
    /// an app's ledger.
    #[test]
    fn shipped_migrations_are_unchanged() {
        let pinned = ["aa2393319e619ff1b02fc6678849d968c7ef7bca94aa355a61c0735aad8df23f"];
        assert_eq!(super::ALL.len(), pinned.len());
        for ((name, sql), want) in super::ALL.iter().zip(pinned) {
            assert_eq!(crate::hex(&Sha256::digest(sql.as_bytes())), want, "{name}");
        }
    }
}
