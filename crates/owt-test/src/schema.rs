//! A schema of a test's own, named for its checkout and process.
//!
//! `#[sqlx::test]` names each test database from a hash of the test's module path
//! alone, and creates it on the server `DATABASE_URL` points at. The same test run
//! from two worktrees, or from two apps whose tests share a path, therefore asks one
//! server for one name twice: the second run drops the first's database under it, or
//! fails with "database already exists". Pointing `DATABASE_URL` at another database
//! of the same server changes nothing, because database names are server-wide.
//!
//! [`TestSchema`] takes a schema named `owt_test_<checkout>_<process>_<sequence>`,
//! where `<checkout>` is eight hex digits of a hash of the app's `CARGO_MANIFEST_DIR`,
//! so two worktrees (two paths) never share a name and neither do two processes of
//! one worktree or two tests of one process. Its pool's connections put the schema
//! first on the `search_path`, and dropping it drops the schema with its contents. A
//! schema costs a catalog entry where `DROP DATABASE` forces a checkpoint, which on
//! a server shared by many test runs is the slower and the more contended of the two.

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// Postgres truncates identifiers longer than this many bytes.
pub const MAX_NAME_LEN: usize = 63;

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Eight hex digits identifying a checkout by its manifest directory.
#[must_use]
pub fn checkout_tag(manifest_dir: &str) -> String {
    let digest = Sha256::digest(manifest_dir.as_bytes());
    digest[..4].iter().fold(String::new(), |mut tag, byte| {
        use std::fmt::Write;
        let _ = write!(tag, "{byte:02x}");
        tag
    })
}

/// The name of the schema for the `sequence`-th test of process `pid` in the
/// checkout at `manifest_dir`: lower-case letters, digits and underscores, at most
/// [`MAX_NAME_LEN`] bytes, so it needs no quoting.
#[must_use]
pub fn schema_name(manifest_dir: &str, pid: u32, sequence: u32) -> String {
    format!("owt_test_{}_{pid}_{sequence}", checkout_tag(manifest_dir))
}

/// A schema made for one test, dropped with the value.
///
/// Created in the database `DATABASE_URL` names; the role needs `CREATE` on it.
#[derive(Debug)]
pub struct TestSchema {
    pool: PgPool,
    name: String,
    admin: PgConnectOptions,
}

impl TestSchema {
    /// Create an empty schema named for `manifest_dir` (pass
    /// `env!("CARGO_MANIFEST_DIR")`), this process and this call. `None` when
    /// `DATABASE_URL` is unset, so a test can skip as the rest of the suite does.
    ///
    /// # Panics
    /// When `DATABASE_URL` is not a Postgres URL or the server refuses the schema.
    pub async fn create(manifest_dir: &str) -> Option<Self> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|u| !u.is_empty())?;
        let admin = PgConnectOptions::from_str(&url).expect("DATABASE_URL is a Postgres URL");
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = schema_name(manifest_dir, std::process::id(), sequence);
        let control = PgPool::connect_with(admin.clone())
            .await
            .expect("DATABASE_URL connects");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}")))
            .execute(&control)
            .await
            .expect("the server creates the test schema");
        control.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(admin.clone().options([("search_path", name.as_str())]))
            .await
            .expect("the test schema connects");
        Some(Self { pool, name, admin })
    }

    /// A pool whose connections have the schema first on their `search_path`.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The schema's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        // Drop cannot await, and the caller's runtime may be single-threaded and
        // ending, so a thread of its own runs the cleanup and is joined.
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async {
                if let Ok(control) = PgPool::connect_with(admin).await {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                        "DROP SCHEMA IF EXISTS {name} CASCADE"
                    )))
                    .execute(&control)
                    .await;
                    control.close().await;
                }
            });
        })
        .join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkouts_get_different_names() {
        let a = schema_name("/home/u/wt-a/app", 10, 0);
        let b = schema_name("/home/u/wt-b/app", 10, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn processes_and_tests_get_different_names() {
        let dir = "/home/u/wt-a/app";
        assert_ne!(schema_name(dir, 10, 0), schema_name(dir, 11, 0));
        assert_ne!(schema_name(dir, 10, 0), schema_name(dir, 10, 1));
    }

    #[test]
    fn a_name_is_stable_and_fits_an_identifier() {
        let dir = "/a/very/long/path/".repeat(50);
        let name = schema_name(&dir, u32::MAX, u32::MAX);
        assert_eq!(name, schema_name(&dir, u32::MAX, u32::MAX));
        assert!(name.len() <= MAX_NAME_LEN, "{name}");
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
    }

    #[tokio::test]
    async fn a_schema_exists_while_held_and_not_after() {
        let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
            return;
        };
        let name = db.name().to_owned();
        let other = TestSchema::create(env!("CARGO_MANIFEST_DIR"))
            .await
            .expect("set");
        assert_ne!(name, other.name());
        let current: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(current, name);
        let admin = other.admin.clone();
        drop(db);
        drop(other);
        let control = PgPool::connect_with(admin).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_namespace WHERE nspname = $1")
            .bind(&name)
            .fetch_one(&control)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}
