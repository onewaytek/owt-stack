//! `owt_runtime::db` against a real Postgres (`DATABASE_URL`); skipped when it is
//! unset. The test takes a schema of its own and leaves nothing.

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// A migration that fails stops `migrate_locked` without leaving an advisory lock
/// held: neither its own nor sqlx's, which sqlx's failed run never releases. Left on a
/// pooled connection, sqlx's would make every later migration of the database wait.
#[tokio::test]
async fn a_failed_migration_leaves_no_lock_held() {
    let Some(url) = owt_runtime::env::var("DATABASE_URL") else {
        return;
    };
    let name = format!("owt_db_{}_{}", std::process::id(), rand::random::<u32>());
    let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let dir = std::env::temp_dir().join(&name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("0001_fails.sql"), "SELECT 1 / 0;").unwrap();
    let migrator = Migrator::new(dir.as_path()).await.unwrap();

    // One connection, so a lock left on it would still be held after the call; the
    // application name finds its session.
    let opts: PgConnectOptions = url.parse().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            opts.options([("search_path", name.as_str())])
                .application_name(&name),
        )
        .await
        .unwrap();
    let lock_id = i64::from(rand::random::<u32>());
    assert!(
        owt_runtime::db::migrate_locked(&pool, &migrator, lock_id)
            .await
            .is_err()
    );
    // The session ends a moment after the connection's close.
    let mut held = i64::MAX;
    for _ in 0..50 {
        held = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
             WHERE l.locktype = 'advisory' AND a.application_name = $1",
        )
        .bind(&name)
        .fetch_one(&admin)
        .await
        .unwrap();
        if held == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(held, 0, "an advisory lock outlived the failed migration");
    // The pool still serves.
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);

    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {name} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
