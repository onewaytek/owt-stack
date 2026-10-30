//! The library's own migration ledger against a real Postgres (`DATABASE_URL`);
//! skipped without it. Each test takes a schema of its own, and an app's
//! `migrations/` is a temporary directory holding copies of the library's files
//! beside migrations of the app's own, for the adoption tests.

use std::path::PathBuf;

use owt_accounts::migrations::{self, ALL, LEDGER, MigrationError};
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgConnectOptions;

struct Db {
    pool: PgPool,
    schema: String,
    admin: PgPool,
    url: String,
    dir: PathBuf,
}

impl Db {
    async fn new() -> Option<Self> {
        let url = owt_runtime::env::var("DATABASE_URL")?;
        let schema = format!(
            "owt_ledger_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        );
        let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(&schema);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = Self::pool_on(&url, &schema, 4).await;
        Some(Self {
            pool,
            schema,
            admin,
            url,
            dir,
        })
    }

    async fn pool_on(url: &str, schema: &str, max: u32) -> PgPool {
        let opts: PgConnectOptions = url.parse().unwrap();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max)
            .connect_with(opts.options([("search_path", schema)]))
            .await
            .unwrap()
    }

    /// Write a migration file into the app's `migrations/`.
    fn write(&self, file: &str, sql: &str) {
        std::fs::write(self.dir.join(file), sql).unwrap();
    }

    fn remove(&self, file: &str) {
        std::fs::remove_file(self.dir.join(file)).unwrap();
    }

    /// The app's migrator over its `migrations/` as it stands, ignoring versions it
    /// no longer has (the copies it deleted), as an adopted app's is.
    async fn app(&self) -> Migrator {
        let mut m = Migrator::new(self.dir.as_path()).await.unwrap();
        m.set_ignore_missing(true);
        m
    }

    async fn ledger(&self) -> Vec<(i64, String)> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT version, description FROM {LEDGER} ORDER BY version"
        )))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An app's table that references the library's, as every app's does.
const APP_TABLE: &str = "CREATE TABLE notes (id bigint PRIMARY KEY, \
                         account_id bigint NOT NULL REFERENCES accounts ON DELETE CASCADE);";

/// The file names an app gave the copies, under versions of its own: the library's
/// first, then its own table, then the later entries, as apps interleaved them.
fn copy_file(i: usize) -> String {
    let version = if i == 0 { 1 } else { 5 + i };
    format!("{version:04}_{}.sql", ALL[i].name)
}

/// Every table the library makes, so a test can tell the schema is complete.
async fn tables(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema()
         AND tablename NOT LIKE '\\_%' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

const LIBRARY_TABLES: &[&str] = &[
    "account_identities",
    "account_local_identities",
    "account_recovery_codes",
    "account_roles",
    "account_totp",
    "accounts",
    "policy_acceptance_events",
    "policy_acceptances",
    "policy_versions",
    "sign_in_links",
];

#[tokio::test]
async fn a_fresh_database_gets_every_entry_once() {
    let Some(db) = Db::new().await else { return };
    let done = migrations::run(&db.pool).await.unwrap();
    assert_eq!(done.adopted, Vec::<&str>::new());
    assert_eq!(done.applied, ALL.iter().map(|m| m.name).collect::<Vec<_>>());
    let names: Vec<(i64, String)> = ALL
        .iter()
        .zip(1..)
        .map(|(m, v)| (v, m.name.to_owned()))
        .collect();
    assert_eq!(db.ledger().await, names);
    assert_eq!(tables(&db.pool).await, LIBRARY_TABLES);

    // Idempotent: nothing to do the second time.
    let again = migrations::run(&db.pool).await.unwrap();
    assert_eq!(again, migrations::Migrated::default());

    // The app's own migrations come after, with no copies.
    db.write("0001_notes.sql", APP_TABLE);
    let mut app = Migrator::new(db.dir.as_path()).await.unwrap();
    app.set_ignore_missing(false);
    owt_runtime::db::migrate_locked(&db.pool, &app, 8_531_207)
        .await
        .unwrap();
    let done = migrations::complete(&db.pool).await.unwrap();
    assert!(done.validated, "{done:?}");
    db.drop().await;
}

#[tokio::test]
async fn an_apps_applied_copies_are_adopted_never_run_again() {
    let Some(db) = Db::new().await else { return };
    // The app as it was: every entry copied, its own table between them, a row in it.
    for (i, m) in ALL.iter().enumerate() {
        db.write(&copy_file(i), m.sql);
    }
    db.write("0002_notes.sql", APP_TABLE);
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    sqlx::raw_sql(
        "WITH a AS (INSERT INTO accounts (username) VALUES ('ada') RETURNING id)
         INSERT INTO notes SELECT 1, id FROM a;",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    // The new binary: the copies are deleted, the library migrates itself.
    for i in 0..ALL.len() {
        db.remove(&copy_file(i));
    }
    let done = migrations::run(&db.pool).await.unwrap();
    assert_eq!(done.adopted, ALL.iter().map(|m| m.name).collect::<Vec<_>>());
    assert!(done.applied.is_empty(), "{done:?}");
    // Recorded under the library's versions, the rows untouched, and the app's own
    // ledger as it was.
    assert_eq!(db.ledger().await.len(), ALL.len());
    let ada: String = sqlx::query_scalar(
        "SELECT a.username FROM accounts a JOIN notes n ON n.account_id = a.id WHERE n.id = 1",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(ada, "ada");
    let app_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        app_rows,
        i64::try_from(ALL.len()).unwrap() + 1,
        "the app's ledger is read, never written"
    );
    // The app's migrator runs without its copies, ignoring their versions.
    owt_runtime::db::migrate_locked(&db.pool, &db.app().await, 8_531_207)
        .await
        .unwrap();
    assert!(migrations::complete(&db.pool).await.unwrap().validated);
    // And again: nothing.
    assert_eq!(
        migrations::run(&db.pool).await.unwrap(),
        migrations::Migrated::default()
    );

    // Once no binary carries the copies, their rows can go, and the app's migrator
    // no longer needs to ignore them.
    let forgotten = migrations::forget_copies(&db.pool).await.unwrap();
    assert_eq!(forgotten, [1, 6, 7, 8, 9, 10, 11, 12]);
    let left: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(left, [2], "the app's own migration stays");
    let mut strict = Migrator::new(db.dir.as_path()).await.unwrap();
    strict.set_ignore_missing(false);
    strict.run(&db.pool).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn a_partly_applied_set_of_copies_is_adopted_and_the_rest_applied() {
    let Some(db) = Db::new().await else { return };
    // An app whose copies stop at the third entry, all applied.
    for (i, m) in ALL.iter().enumerate().take(3) {
        db.write(&copy_file(i), m.sql);
    }
    db.write("0002_notes.sql", APP_TABLE);
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    for i in 0..3 {
        db.remove(&copy_file(i));
    }
    let done = migrations::run(&db.pool).await.unwrap();
    assert_eq!(done.adopted, [ALL[0].name, ALL[1].name, ALL[2].name]);
    assert_eq!(
        done.applied,
        [
            ALL[3].name,
            ALL[4].name,
            ALL[5].name,
            ALL[6].name,
            ALL[7].name
        ]
    );
    assert_eq!(tables(&db.pool).await.len(), LIBRARY_TABLES.len() + 1);
    assert!(migrations::complete(&db.pool).await.unwrap().validated);
    db.drop().await;
}

#[tokio::test]
async fn an_edited_copy_is_refused_by_name_and_nothing_is_adopted() {
    let Some(db) = Db::new().await else { return };
    db.write(&copy_file(0), ALL[0].sql);
    // The roles copy with an extra column of the app's: the same name, other text.
    let edited = format!(
        "{}\nALTER TABLE account_roles ADD COLUMN note text;\n",
        ALL[1].sql
    );
    db.write(&copy_file(1), &edited);
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    let err = migrations::run(&db.pool).await.unwrap_err();
    match &err {
        MigrationError::EditedCopy {
            version,
            description,
            name,
        } => {
            assert_eq!(
                (*version, description.as_str(), *name),
                (6, "owt accounts roles", ALL[1].name)
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(err.to_string().contains("other contents"), "{err}");
    // Nothing recorded: the ledger is empty or absent.
    let recorded: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {LEDGER}"
    )))
    .fetch_optional(&db.pool)
    .await
    .unwrap_or(None);
    assert!(recorded.unwrap_or(0) == 0, "{recorded:?}");
    // Refused again, loudly, on every start until the app deals with it.
    assert!(matches!(
        migrations::run(&db.pool).await,
        Err(MigrationError::EditedCopy { .. })
    ));
    db.drop().await;
}

#[tokio::test]
async fn copies_applied_out_of_order_are_a_gap() {
    let Some(db) = Db::new().await else { return };
    // Entries 1 and 3 applied as copies, 2 not: an app that skipped one.
    db.write(&copy_file(0), ALL[0].sql);
    db.write(&copy_file(2), ALL[2].sql);
    let app = Migrator::new(db.dir.as_path()).await.unwrap();
    app.run(&db.pool).await.unwrap();
    let err = migrations::run(&db.pool).await.unwrap_err();
    assert!(
        matches!(err, MigrationError::Gap { missing, applied } if missing == ALL[1].name && applied == ALL[2].name),
        "{err:?}"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_copy_recorded_as_failed_is_refused() {
    let Some(db) = Db::new().await else { return };
    db.write(&copy_file(0), ALL[0].sql);
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    let err = migrations::run(&db.pool).await.unwrap_err();
    assert!(
        matches!(err, MigrationError::FailedCopy { version: 1, .. }),
        "{err:?}"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_ledger_entry_with_another_checksum_is_refused() {
    let Some(db) = Db::new().await else { return };
    migrations::run(&db.pool).await.unwrap();
    // As if a shipped migration had been edited after this database applied it.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {LEDGER} SET checksum = '\\x00' WHERE version = 2"
    )))
    .execute(&db.pool)
    .await
    .unwrap();
    let err = migrations::run(&db.pool).await.unwrap_err();
    assert!(
        matches!(
            err,
            MigrationError::Migrate(sqlx::migrate::MigrateError::VersionMismatch(2))
        ),
        "{err:?}"
    );
    // The failed run's connection is closed, not pooled holding sqlx's lock: the pool
    // still migrates something else at once.
    let other = Db::new().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        migrations::run(&other.pool),
    )
    .await
    .expect("no lock left held")
    .unwrap();
    other.drop().await;
    db.drop().await;
}

#[tokio::test]
async fn two_starters_at_once_migrate_once() {
    let Some(db) = Db::new().await else { return };
    // Half the replicas find copies to adopt as the other half start: both run
    // against an app that had applied the first two copies.
    for (i, m) in ALL.iter().enumerate().take(2) {
        db.write(&copy_file(i), m.sql);
    }
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    let pools = [
        Db::pool_on(&db.url, &db.schema, 2).await,
        Db::pool_on(&db.url, &db.schema, 2).await,
        Db::pool_on(&db.url, &db.schema, 2).await,
    ];
    let runs = futures_join(&pools).await;
    let mut adopted = 0;
    let mut applied = 0;
    for r in &runs {
        let done = r.as_ref().expect("every starter succeeds");
        adopted += done.adopted.len();
        applied += done.applied.len();
    }
    assert_eq!(adopted, 2, "adopted once: {runs:?}");
    assert_eq!(applied, ALL.len() - 2, "applied once: {runs:?}");
    assert_eq!(db.ledger().await.len(), ALL.len());
    for p in pools {
        p.close().await;
    }
    db.drop().await;
}

async fn futures_join(pools: &[PgPool]) -> Vec<Result<migrations::Migrated, MigrationError>> {
    let handles: Vec<_> = pools
        .iter()
        .cloned()
        .map(|p| tokio::spawn(async move { migrations::run(&p).await }))
        .collect();
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test]
async fn start_runs_the_library_then_the_app_then_completes() {
    let Some(db) = Db::new().await else { return };
    db.write("0001_notes.sql", APP_TABLE);
    let app = db.app().await;
    let started = migrations::start(&db.pool, || {
        owt_runtime::db::migrate_locked(&db.pool, &app, 8_531_207)
    })
    .await
    .unwrap();
    assert!(started.validated, "{started:?}");
    assert_eq!(db.ledger().await.len(), ALL.len());
    let mut want: Vec<String> = LIBRARY_TABLES.iter().map(|s| (*s).to_owned()).collect();
    want.push("notes".to_owned());
    want.sort();
    assert_eq!(tables(&db.pool).await, want);

    // At every start: a second one changes nothing and still succeeds.
    migrations::start(&db.pool, || {
        owt_runtime::db::migrate_locked(&db.pool, &app, 8_531_207)
    })
    .await
    .unwrap();
    db.drop().await;
}

#[tokio::test]
async fn start_stops_at_the_step_that_failed_and_names_it() {
    let Some(db) = Db::new().await else { return };
    // The app's step fails: the library's migrations were applied, `complete` was not
    // reached (an account made before keying stays unkeyed).
    let err = migrations::start(&db.pool, || async {
        Err::<(), _>(anyhow::anyhow!("no such file"))
    })
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "the app's migrations");
    assert_eq!(format!("{err:#}"), "the app's migrations: no such file");
    assert_eq!(db.ledger().await.len(), ALL.len());

    // The library's step fails (a tampered ledger): the app's step never runs.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {LEDGER} SET checksum = '\\x00' WHERE version = 1"
    )))
    .execute(&db.pool)
    .await
    .unwrap();
    let ran = std::sync::atomic::AtomicBool::new(false);
    let err = migrations::start(&db.pool, || async {
        ran.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "owt-accounts migrations");
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    db.drop().await;
}

#[tokio::test]
async fn start_refuses_an_app_whose_own_accounts_table_is_in_the_way() {
    let Some(db) = Db::new().await else { return };
    sqlx::query("CREATE TABLE accounts (id serial PRIMARY KEY, goods int)")
        .execute(&db.pool)
        .await
        .unwrap();
    let ran = std::sync::atomic::AtomicBool::new(false);
    let err = migrations::start(&db.pool, || async {
        ran.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "owt-accounts migrations");
    assert!(format!("{err:#}").contains("already exists"), "{err:#}");
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    db.drop().await;
}

#[tokio::test]
async fn an_app_whose_own_migrations_come_first_runs_them_to_a_version() {
    let Some(db) = Db::new().await else { return };
    // An app with an `accounts` of its own, renamed out of the way before the
    // library's: its migrator runs to the rename, then the library's, then the rest.
    db.write(
        "0001_shop.sql",
        "CREATE TABLE accounts (id serial PRIMARY KEY, goods int);",
    );
    db.write(
        "0002_rename.sql",
        "ALTER TABLE accounts RENAME TO holdings;
         ALTER INDEX accounts_pkey RENAME TO holdings_pkey;
         ALTER SEQUENCE accounts_id_seq RENAME TO holdings_id_seq;",
    );
    db.write("0003_notes.sql", APP_TABLE);
    let app = db.app().await;
    owt_runtime::db::migrate_locked_to(&db.pool, &app, 2, 8_531_207)
        .await
        .unwrap();
    migrations::run(&db.pool).await.unwrap();
    owt_runtime::db::migrate_locked(&db.pool, &app, 8_531_207)
        .await
        .unwrap();
    let mut want: Vec<String> = LIBRARY_TABLES.iter().map(|s| (*s).to_owned()).collect();
    want.extend(["holdings".to_owned(), "notes".to_owned()]);
    want.sort();
    assert_eq!(tables(&db.pool).await, want);
    db.drop().await;
}

#[tokio::test]
async fn an_adoption_cut_short_resumes() {
    let Some(db) = Db::new().await else { return };
    for (i, m) in ALL.iter().enumerate() {
        db.write(&copy_file(i), m.sql);
    }
    Migrator::new(db.dir.as_path())
        .await
        .unwrap()
        .run(&db.pool)
        .await
        .unwrap();
    migrations::run(&db.pool).await.unwrap();
    // As if the start had been killed after recording the first three.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {LEDGER} WHERE version > 3"
    )))
    .execute(&db.pool)
    .await
    .unwrap();
    let done = migrations::run(&db.pool).await.unwrap();
    assert_eq!(
        done.adopted,
        [
            ALL[3].name,
            ALL[4].name,
            ALL[5].name,
            ALL[6].name,
            ALL[7].name
        ]
    );
    assert_eq!(done.applied, Vec::<&str>::new());
    assert_eq!(db.ledger().await.len(), ALL.len());
    db.drop().await;
}

#[tokio::test]
async fn replicas_running_the_whole_start_at_once_all_succeed() {
    let Some(db) = Db::new().await else { return };
    db.write("0001_notes.sql", APP_TABLE);
    let app = std::sync::Arc::new(db.app().await);
    let mut starts = Vec::new();
    for _ in 0..3 {
        let pool = Db::pool_on(&db.url, &db.schema, 2).await;
        let app = app.clone();
        starts.push(tokio::spawn(async move {
            migrations::run(&pool).await.unwrap();
            owt_runtime::db::migrate_locked(&pool, &app, 8_531_207)
                .await
                .unwrap();
            migrations::complete(&pool).await.unwrap();
            pool.close().await;
        }));
    }
    for s in starts {
        tokio::time::timeout(std::time::Duration::from_secs(60), s)
            .await
            .expect("no start waits forever")
            .unwrap();
    }
    assert_eq!(db.ledger().await.len(), ALL.len());
    db.drop().await;
}
