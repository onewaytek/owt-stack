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

/// A database that becomes reachable while `connect` waits is connected to; one that
/// refuses the password is not retried.
#[tokio::test]
async fn connect_waits_for_a_database_that_comes_up() {
    use std::time::{Duration, Instant};
    let Some(url) = owt_runtime::env::var("DATABASE_URL") else {
        return;
    };
    let opts: PgConnectOptions = url.parse().unwrap();
    let upstream = format!("{}:{}", opts.get_host(), opts.get_port());
    // A port nothing listens on yet; a forwarder to the real server opens on it later.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let forwarder = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let mut server = tokio::net::TcpStream::connect(upstream).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    let config = owt_runtime::db::PoolConfig {
        max: 1,
        min: 0,
        acquire_timeout: Duration::from_millis(200),
        ..owt_runtime::db::PoolConfig::default()
    };
    let moved = opts.clone().host("127.0.0.1").port(port);
    let via = format!(
        "postgres://{}:{}@127.0.0.1:{port}/{}",
        moved.get_username(),
        url_password(&url),
        moved.get_database().unwrap_or("postgres"),
    );
    let started = Instant::now();
    let pool = config
        .clone()
        .connect_within(&via, Duration::from_secs(20))
        .await
        .expect("connected once the forwarder listened");
    assert!(started.elapsed() >= Duration::from_millis(1_000));
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);
    pool.close().await;

    // A wrong password is the server's refusal, never retried. The acquire timeout
    // is long, so a slow SCRAM exchange under load is not a timeout; a retry would
    // end in the timeout rather than the server's code.
    let wrong = format!(
        "postgres://{}:not-the-password@127.0.0.1:{port}/{}",
        moved.get_username(),
        moved.get_database().unwrap_or("postgres"),
    );
    let patient = owt_runtime::db::PoolConfig {
        acquire_timeout: Duration::from_secs(10),
        ..config
    };
    let error = patient
        .connect_within(&wrong, Duration::from_secs(20))
        .await
        .unwrap_err();
    let code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    assert_eq!(code.as_deref(), Some("28P01"), "{error}");
    forwarder.abort();
}

/// The password in a `postgres://user:password@…` URL ("" when there is none).
fn url_password(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let userinfo = rest.split_once('@').map_or("", |(u, _)| u);
    userinfo.split_once(':').map_or("", |(_, p)| p).to_owned()
}
