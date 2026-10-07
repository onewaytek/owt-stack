//! The tables, as SQL the app installs.
//!
//! sqlx keeps one ledger of applied migrations per database, so a library cannot run
//! a migrator of its own beside the app's. Instead the app copies each file here into
//! its `migrations/` directory, under a version of its choosing (first: the app's
//! tables reference `accounts`), and a test calls [`assert_installed`] so an edited
//! or missing copy fails the build rather than the deploy.

use std::path::Path;

/// A migration this crate ships.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    /// Its name, for the file the app writes (`<version>_<name>.sql`).
    pub name: &'static str,
    /// Its SQL, to copy byte for byte.
    pub sql: &'static str,
}

/// Every migration, in order.
pub const ALL: &[Migration] = &[Migration {
    name: "owt_accounts",
    sql: include_str!("../migrations/0001_accounts.sql"),
}];

/// For this crate's own tests: the migrations as a migrator.
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
    use super::*;

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
