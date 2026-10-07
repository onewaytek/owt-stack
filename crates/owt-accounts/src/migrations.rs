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
pub const ALL: &[Migration] = &[Migration {
    name: "owt_accounts",
    sql: include_str!("../migrations/0001_accounts.sql"),
}];

/// The SHA-256 of each of [`ALL`], in order, as released. A changed digest means a
/// shipped migration was edited, which breaks every app's next deploy: revert it and
/// write the change as a new file, pinned here as a new entry.
#[cfg(test)]
const SHIPPED_SHA256: &[&str] =
    &["743f8095a1df80c56eccc7a101df0e6ad6bcbaf567a68dc82f50d2f5f2f631b4"];

/// For this crate's own tests only. Do not run it against an app's database: sqlx
/// keeps one migration ledger per database, and this one would fight the app's.
#[doc(hidden)]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
                 to a file there (first, before the app's tables)",
                migration.name,
                dir.display()
            ),
        }
    }
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
        std::fs::remove_dir(&dir).unwrap();
    }
}
