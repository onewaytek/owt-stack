//! The tables, migrated by the library into a ledger of its own.

use std::borrow::Cow;

use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{PgPool, SqlStr};

/// The table [`migrate`] records the library's migrations in, beside the app's
/// `_sqlx_migrations`.
pub const LEDGER: &str = "_owt_crypt_migrations";

/// The advisory lock [`migrate`] holds while it migrates.
pub const LOCK_ID: i64 = 0x6f77_745f_6372_7970;

/// Every migration, in order: entry `i` is version `i + 1` in [`LEDGER`]. Append
/// only; a shipped entry is never edited (a test pins each one).
const ALL: &[(&str, &str)] = &[("owt_crypt", include_str!("../migrations/0001_keys.sql"))];

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

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |s, x| s + &format!("{x:02x}"))
    }

    /// A shipped migration is frozen: a changed file fails here before it fails in
    /// an app's ledger.
    #[test]
    fn shipped_migrations_are_unchanged() {
        let pinned = ["2f5067efb07a581dad7ec38dc70cb879c3e631cb5ebb2bd44a7e6ec1d3e349f6"];
        assert_eq!(super::ALL.len(), pinned.len());
        for ((name, sql), want) in super::ALL.iter().zip(pinned) {
            assert_eq!(hex(&Sha256::digest(sql.as_bytes())), want, "{name}");
        }
    }
}
