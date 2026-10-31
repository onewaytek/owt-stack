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
//! where `<checkout>` is eight hex digits of a hash of the host name and the app's
//! `CARGO_MANIFEST_DIR`, so two worktrees (two paths) or two hosts never share a name
//! and neither do two processes of one worktree or two tests of one process. A
//! schema costs a catalog entry where `DROP DATABASE` forces a checkpoint, which on
//! a server shared by many test runs is the slower and the more contended of the two.
//!
//! Its pool's connections carry the schema's name as their `application_name` and
//! have `search_path` set to `<schema>, public`: the app's tables land in the schema,
//! and extensions installed in `public` resolve. `CREATE EXTENSION` installs into the
//! first schema on the path, so a migration that creates an extension names
//! `SCHEMA public` (or the extension is installed there beforehand); otherwise the
//! first test's schema holds it, other schemas miss its types, and dropping that
//! schema removes it.
//!
//! [`TestSchema::close`] drops the schema; dropping the value does the same from a
//! thread of its own. Both end the pool's server sessions (found by
//! `application_name`) before `DROP SCHEMA`, under a `lock_timeout` and an overall
//! time limit, so a transaction left open, or a pool clone still held, cannot keep the
//! drop waiting. Creating a schema first drops one left under the same name, and the
//! schemas of this checkout whose process is no longer running (a test run that was
//! killed or aborted never drops its own). The process check reads `/proc`, so the
//! sweep of other processes' schemas runs on Linux only; the host name in the
//! checkout hash keeps it to schemas of this host.

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};

/// Postgres truncates identifiers longer than this many bytes.
pub const MAX_NAME_LEN: usize = 63;

/// The longest any one cleanup (close or drop) takes before it gives up.
const CLEANUP_LIMIT: Duration = Duration::from_secs(30);

/// How long [`TestSchema::close`] waits for the pool's connections to come back
/// before ending their sessions.
const POOL_CLOSE_LIMIT: Duration = Duration::from_secs(5);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Eight hex digits identifying a checkout by its host and manifest directory.
#[must_use]
pub fn checkout_tag(host: &str, manifest_dir: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(host.as_bytes());
    hasher.update([0]);
    hasher.update(manifest_dir.as_bytes());
    let digest = hasher.finalize();
    digest[..4].iter().fold(String::new(), |mut tag, byte| {
        use std::fmt::Write;
        let _ = write!(tag, "{byte:02x}");
        tag
    })
}

/// The name of the schema for the `sequence`-th test of process `pid` in the
/// checkout at `manifest_dir` on `host`: lower-case letters, digits and underscores,
/// at most [`MAX_NAME_LEN`] bytes, so it needs no quoting.
#[must_use]
pub fn schema_name(host: &str, manifest_dir: &str, pid: u32, sequence: u32) -> String {
    format!(
        "owt_test_{}_{pid}_{sequence}",
        checkout_tag(host, manifest_dir)
    )
}

/// This machine's host name, or empty when none can be read.
fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

/// The process of a schema of checkout `tag`, or `None` when `name` is not one.
fn schema_pid(name: &str, tag: &str) -> Option<u32> {
    let rest = name.strip_prefix("owt_test_")?.strip_prefix(tag)?;
    let (pid, sequence) = rest.strip_prefix('_')?.split_once('_')?;
    sequence.parse::<u32>().ok()?;
    pid.parse().ok()
}

/// Whether process `pid` of this host may still be running. Without `/proc` every
/// process may be.
fn may_be_running(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    } else {
        true
    }
}

/// A connection for creating and dropping schemas, whose statements give up on a
/// held lock instead of waiting for it.
async fn control(admin: &PgConnectOptions) -> Result<PgConnection, sqlx::Error> {
    let mut conn = PgConnection::connect_with(admin).await?;
    sqlx::raw_sql("SET lock_timeout = '5s'; SET statement_timeout = '20s'")
        .execute(&mut conn)
        .await?;
    Ok(conn)
}

/// End the sessions whose `application_name` is `name`, then drop the schema.
async fn drop_schema(conn: &mut PgConnection, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE application_name = $1 AND pid <> pg_backend_pid()",
    )
    .bind(name)
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {name} CASCADE"
    )))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Drop the schema `name`, within [`CLEANUP_LIMIT`].
async fn clean_up(admin: &PgConnectOptions, name: &str) {
    let run = async {
        let mut conn = control(admin).await?;
        drop_schema(&mut conn, name).await?;
        conn.close().await
    };
    match tokio::time::timeout(CLEANUP_LIMIT, run).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("owt-test: schema {name} not dropped: {e}"),
        Err(_) => eprintln!("owt-test: schema {name} not dropped within {CLEANUP_LIMIT:?}"),
    }
}

/// Drop `own` if a dead process left it, and the schemas of checkout `tag` whose
/// process is not running, in both cases only when no session uses them.
async fn sweep(conn: &mut PgConnection, tag: &str, own: &str) {
    let me = std::process::id();
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT nspname::text FROM pg_namespace n WHERE nspname LIKE $1 \
         AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.application_name = n.nspname)",
    )
    .bind(format!("owt\\_test\\_{tag}\\_%"))
    .fetch_all(&mut *conn)
    .await
    .unwrap_or_default();
    for name in found {
        let leaked = name == own
            || schema_pid(&name, tag).is_some_and(|pid| pid != me && !may_be_running(pid));
        if leaked {
            // Another process may sweep the same schema at once; either drop suffices.
            let _ = drop_schema(conn, &name).await;
        }
    }
}

/// A schema made for one test, dropped by [`close`](Self::close) or with the value.
///
/// Created in the database `DATABASE_URL` names; the role needs `CREATE` on it.
#[derive(Debug)]
pub struct TestSchema {
    pool: PgPool,
    name: String,
    admin: PgConnectOptions,
    closed: bool,
}

impl TestSchema {
    /// Create an empty schema named for `manifest_dir` (pass
    /// `env!("CARGO_MANIFEST_DIR")`), this host, this process and this call, after
    /// sweeping the schemas this checkout leaked. `None` when `DATABASE_URL` is
    /// unset, so a test can skip as the rest of the suite does.
    ///
    /// # Panics
    /// When `DATABASE_URL` is not a Postgres URL or the server refuses the schema.
    pub async fn create(manifest_dir: &str) -> Option<Self> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|u| !u.is_empty())?;
        let admin = PgConnectOptions::from_str(&url).expect("DATABASE_URL is a Postgres URL");
        let host = host_name();
        let tag = checkout_tag(&host, manifest_dir);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = schema_name(&host, manifest_dir, std::process::id(), sequence);
        // The pool connects before the schema exists, so a failure here leaks nothing.
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(
                admin
                    .clone()
                    .application_name(&name)
                    .options([("search_path", format!("{name},public"))]),
            )
            .await
            .expect("DATABASE_URL connects");
        let mut conn = control(&admin).await.expect("DATABASE_URL connects");
        sweep(&mut conn, &tag, &name).await;
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}")))
            .execute(&mut conn)
            .await
            .expect("the server creates the test schema");
        let _ = conn.close().await;
        Some(Self {
            pool,
            name,
            admin,
            closed: false,
        })
    }

    /// A pool whose connections have `search_path` set to `<schema>, public`.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The schema's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the pool and drop the schema; a test ends with this. It waits on the
    /// test's own runtime, where sqlx returns connections (rolling back transactions
    /// dropped open), and after a few seconds ends the sessions of any connection
    /// still out. Errors are printed, not returned, as a drop's are.
    pub async fn close(mut self) {
        self.closed = true;
        let _ = tokio::time::timeout(POOL_CLOSE_LIMIT, self.pool.close()).await;
        clean_up(&self.admin, &self.name).await;
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let admin = self.admin.clone();
        let name = self.name.clone();
        // Drop cannot await, and the caller's runtime may be single-threaded (and
        // blocked here), so a thread of its own runs the cleanup and is joined. The
        // cleanup ends the pool's sessions rather than waiting for the caller's
        // runtime to return their connections, and gives up after `CLEANUP_LIMIT`.
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(clean_up(&admin, &name));
        })
        .join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "host-a";

    #[test]
    fn checkouts_and_hosts_get_different_names() {
        let a = schema_name(HOST, "/home/u/wt-a/app", 10, 0);
        let b = schema_name(HOST, "/home/u/wt-b/app", 10, 0);
        let c = schema_name("host-b", "/home/u/wt-a/app", 10, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn processes_and_tests_get_different_names() {
        let dir = "/home/u/wt-a/app";
        assert_ne!(schema_name(HOST, dir, 10, 0), schema_name(HOST, dir, 11, 0));
        assert_ne!(schema_name(HOST, dir, 10, 0), schema_name(HOST, dir, 10, 1));
    }

    #[test]
    fn a_name_is_stable_and_fits_an_identifier() {
        let dir = "/a/very/long/path/".repeat(50);
        let name = schema_name(HOST, &dir, u32::MAX, u32::MAX);
        assert_eq!(name, schema_name(HOST, &dir, u32::MAX, u32::MAX));
        assert!(name.len() <= MAX_NAME_LEN, "{name}");
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
    }

    #[test]
    fn a_swept_name_yields_its_process() {
        let tag = checkout_tag(HOST, "/d");
        assert_eq!(schema_pid(&schema_name(HOST, "/d", 42, 7), &tag), Some(42));
        assert_eq!(schema_pid(&schema_name(HOST, "/e", 42, 7), &tag), None);
        assert_eq!(schema_pid(&format!("owt_test_{tag}_42"), &tag), None);
        assert_eq!(schema_pid(&format!("owt_test_{tag}_x_1"), &tag), None);
    }

    fn admin() -> Option<PgConnectOptions> {
        let url = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())?;
        Some(PgConnectOptions::from_str(&url).unwrap())
    }

    async fn schema_count(admin: &PgConnectOptions, name: &str) -> i64 {
        let mut conn = PgConnection::connect_with(admin).await.unwrap();
        sqlx::query_scalar("SELECT count(*) FROM pg_namespace WHERE nspname = $1")
            .bind(name)
            .fetch_one(&mut conn)
            .await
            .unwrap()
    }

    /// Run `body` on a current-thread runtime of its own, as `#[tokio::test]` does,
    /// failing when it takes longer than `limit`.
    fn within(limit: Duration, body: impl Future<Output = ()> + Send + 'static) {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(body);
            let _ = done.send(());
        });
        match finished.recv_timeout(limit) {
            Ok(()) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past {limit:?}"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the body panicked"),
        }
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
        other.close().await;
        assert_eq!(schema_count(&admin, &name).await, 0);
    }

    #[test]
    fn dropping_an_open_transaction_then_the_schema_finishes() {
        within(Duration::from_secs(60), async {
            let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
                return;
            };
            let (name, admin) = (db.name().to_owned(), db.admin.clone());
            sqlx::query("CREATE TABLE t (x int)")
                .execute(db.pool())
                .await
                .unwrap();
            let mut tx = db.pool().begin().await.unwrap();
            sqlx::query("INSERT INTO t VALUES (1)")
                .execute(&mut *tx)
                .await
                .unwrap();
            drop(tx);
            drop(db);
            assert_eq!(schema_count(&admin, &name).await, 0);
        });
    }

    #[test]
    fn closing_with_a_transaction_still_held_finishes() {
        within(Duration::from_secs(60), async {
            let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
                return;
            };
            let (name, admin) = (db.name().to_owned(), db.admin.clone());
            sqlx::query("CREATE TABLE t (x int)")
                .execute(db.pool())
                .await
                .unwrap();
            let mut tx = db.pool().begin().await.unwrap();
            sqlx::query("INSERT INTO t VALUES (1)")
                .execute(&mut *tx)
                .await
                .unwrap();
            db.close().await;
            drop(tx);
            assert_eq!(schema_count(&admin, &name).await, 0);
        });
    }

    #[tokio::test]
    async fn public_follows_the_schema_on_the_search_path() {
        let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
            return;
        };
        let path: String = sqlx::query_scalar("SHOW search_path")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(path.replace(' ', ""), format!("{},public", db.name()));
        db.close().await;
    }

    #[tokio::test]
    async fn the_library_migrations_land_in_the_schema() {
        let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
            return;
        };
        owt_accounts::migrations::start(db.pool(), || async { Ok::<(), std::io::Error>(()) })
            .await
            .unwrap();
        let tables: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_tables WHERE schemaname = $1 AND tablename = 'accounts'",
        )
        .bind(db.name())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(tables, 1);
        db.close().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn creating_sweeps_a_dead_process_schema() {
        let Some(admin) = admin() else {
            return;
        };
        // Above any pid_max, so no process of this host has it.
        let leaked = schema_name(&host_name(), env!("CARGO_MANIFEST_DIR"), u32::MAX - 1, 0);
        let mut conn = PgConnection::connect_with(&admin).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE SCHEMA IF NOT EXISTS {leaked}"
        )))
        .execute(&mut conn)
        .await
        .unwrap();
        let db = TestSchema::create(env!("CARGO_MANIFEST_DIR"))
            .await
            .expect("set");
        assert_eq!(schema_count(&admin, &leaked).await, 0);
        db.close().await;
    }
}
