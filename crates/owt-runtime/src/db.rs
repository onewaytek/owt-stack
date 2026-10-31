//! The Postgres pool and migrations.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// Pool sizing and the server-side limits each connection carries. The defaults suit
/// a small app on one replica; size a busy one from measurement (connections are the
/// scarcest resource a replica holds).
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Most connections open at once.
    pub max: u32,
    /// Connections kept open when idle.
    pub min: u32,
    /// How long a caller waits for a connection before failing (5 s by default). A
    /// saturated pool then fails a request in seconds, as a 503, instead of holding
    /// it for the whole request deadline.
    pub acquire_timeout: Duration,
    /// Postgres's `statement_timeout` for every connection (30 s by default, the
    /// `owt_web::Limits` request deadline): a query whose request has timed out stops
    /// on the server too, instead of running on, holding its locks. `None` leaves the
    /// server's setting. Migrations through [`migrate_locked`] run without it; other
    /// long work sets its own with `SET LOCAL statement_timeout` in its transaction, or
    /// runs on a pool built with `None`.
    pub statement_timeout: Option<Duration>,
    /// Postgres's `idle_in_transaction_session_timeout` for every connection (60 s by
    /// default): a transaction left open while its task awaits something else ends,
    /// and so do its locks and its connection. `None` leaves the server's setting.
    pub idle_in_transaction_timeout: Option<Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max: 10,
            min: 1,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Some(Duration::from_secs(30)),
            idle_in_transaction_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl PoolConfig {
    fn options(&self) -> PgPoolOptions {
        PgPoolOptions::new()
            .max_connections(self.max)
            .min_connections(self.min)
            .acquire_timeout(self.acquire_timeout)
    }

    /// `opts` with this config's server-side limits as startup parameters, which win
    /// over the same ones in the URL's `options`.
    fn limits(&self, opts: PgConnectOptions) -> PgConnectOptions {
        let ms = |d: Duration| d.as_millis().to_string();
        let mut params = Vec::new();
        if let Some(t) = self.statement_timeout {
            params.push(("statement_timeout", ms(t)));
        }
        if let Some(t) = self.idle_in_transaction_timeout {
            params.push(("idle_in_transaction_session_timeout", ms(t)));
        }
        if params.is_empty() {
            opts
        } else {
            opts.options(params)
        }
    }

    /// Connect to `url` now, as [`connect_within`](Self::connect_within) does with
    /// [`STARTUP_PATIENCE`]: startup survives a database that is unreachable for a
    /// minute (an offline backup's fence, a switchover) and fails after that.
    pub async fn connect(&self, url: &str) -> sqlx::Result<PgPool> {
        self.connect_within(url, STARTUP_PATIENCE).await
    }

    /// Connect to `url` now, trying again while the database is unreachable until
    /// `patience` has passed since the first attempt; [`Duration::ZERO`] tries once.
    /// Unreachable is a network error, a connection attempt that timed out, or
    /// Postgres refusing connections while it starts or stops; each retry logs a
    /// warning. Anything else (a refused password, a database that does not exist, a
    /// certificate that does not verify) fails at once, as it would on every
    /// attempt. Each attempt also retries a refused connection within
    /// `acquire_timeout`, so the last can end that long after `patience`. Warns when
    /// the connection's TLS is not verified (see [`unverified_tls`]).
    pub async fn connect_within(&self, url: &str, patience: Duration) -> sqlx::Result<PgPool> {
        let opts = self.limits(url.parse()?);
        warn_if_unverified(&opts);
        let deadline = tokio::time::Instant::now() + patience;
        let mut wait = Duration::from_millis(500);
        loop {
            match self.options().connect_with(opts.clone()).await {
                Ok(pool) => return Ok(pool),
                Err(error)
                    if unreachable(&error) && tokio::time::Instant::now() + wait < deadline =>
                {
                    tracing::warn!(%error, retry_in = ?wait, "the database is unreachable; trying again");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(Duration::from_secs(5));
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// A pool that connects on first use: startup survives a slow database. Warns
    /// as [`PoolConfig::connect`] does.
    pub fn connect_lazy(&self, url: &str) -> sqlx::Result<PgPool> {
        let opts = self.limits(url.parse()?);
        warn_if_unverified(&opts);
        Ok(self.options().connect_lazy_with(opts))
    }

    /// A second pool on the same database and settings as `pool`, with its own
    /// connections and this sizing and limits, connecting on first use. For work that
    /// must never queue behind the general traffic.
    #[must_use]
    pub fn reserve_beside(&self, pool: &PgPool) -> PgPool {
        let opts = self.limits((*pool.connect_options()).clone());
        self.options().connect_lazy_with(opts)
    }
}

/// How long [`PoolConfig::connect`] keeps trying an unreachable database at start: an
/// offline snapshot's fence lasts seconds, and the `OpenShift` template's startup
/// probe allows five minutes.
pub const STARTUP_PATIENCE: Duration = Duration::from_secs(60);

/// Whether `error` says the database could not be reached, rather than that it
/// refused this client: worth another attempt.
fn unreachable(error: &sqlx::Error) -> bool {
    use std::io::ErrorKind as K;
    match error {
        // The network's errors only: rustls reports a certificate that does not
        // verify as `InvalidData`, which no retry changes.
        sqlx::Error::Io(e) => matches!(
            e.kind(),
            K::ConnectionRefused
                | K::ConnectionReset
                | K::ConnectionAborted
                | K::NotConnected
                | K::BrokenPipe
                | K::TimedOut
                | K::UnexpectedEof
                | K::HostUnreachable
                | K::NetworkUnreachable
                | K::AddrNotAvailable
        ),
        sqlx::Error::PoolTimedOut => true,
        // Class 08, connection exception; 57P01-57P03, the server shutting down or
        // starting up.
        sqlx::Error::Database(db) => db
            .code()
            .is_some_and(|c| c.starts_with("08") || matches!(&*c, "57P01" | "57P02" | "57P03")),
        _ => false,
    }
}

/// Whether a connection to anywhere but this machine would go without TLS that
/// checks the server's certificate and name (`sslmode` other than `verify-full`, which
/// is also sqlx's default of `prefer`): on a network another workload shares, the
/// credentials and every query could be read or changed on the way. Set
/// `PGSSLMODE=verify-full` and `PGSSLROOTCERT` (the `OpenShift` template does).
#[must_use]
pub fn unverified_tls(opts: &PgConnectOptions) -> bool {
    use sqlx::postgres::PgSslMode;
    // sqlx keeps an IPv6 host in brackets, as it was written in the URL.
    let local = matches!(opts.get_host(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
        || opts.get_host().starts_with('/');
    !local && !matches!(opts.get_ssl_mode(), PgSslMode::VerifyFull)
}

fn warn_if_unverified(opts: &PgConnectOptions) {
    if unverified_tls(opts) {
        tracing::warn!(
            host = opts.get_host(),
            "Postgres TLS is not verified (sslmode is not verify-full)"
        );
    }
}

/// Apply `migrator` under the advisory lock `lock_id`, held on one connection for the
/// whole run, so replicas starting together (or a migrate Job racing a rollout)
/// migrate once and the rest wait. sqlx takes its own lock too; an explicit id lets
/// another migrator (a predecessor app on the same schema) exclude this one. When the
/// run fails, that connection is closed rather than pooled: sqlx's failed run leaves
/// its lock held on it, so the pool stays usable (to retry, or to ask what failed).
pub async fn migrate_locked(
    pool: &PgPool,
    migrator: &Migrator,
    lock_id: i64,
) -> anyhow::Result<()> {
    locked(pool, migrator, None, lock_id).await
}

/// [`migrate_locked`], applying `migrator`'s migrations up to and including version
/// `target` only. For an app whose own migrations must partly run before a library's
/// (one that renames a table of its own out of the way of the library's), and the
/// rest after.
pub async fn migrate_locked_to(
    pool: &PgPool,
    migrator: &Migrator,
    target: i64,
    lock_id: i64,
) -> anyhow::Result<()> {
    locked(pool, migrator, Some(target), lock_id).await
}

async fn locked(
    pool: &PgPool,
    migrator: &Migrator,
    target: Option<i64>,
    lock_id: i64,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    // Waiting on another replica's migration and building an index both outlast any
    // request's `statement_timeout`; the connection's own setting comes back with
    // `RESET` below, or the connection is closed.
    sqlx::query("SET statement_timeout = 0")
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await?;
    // On the connection itself, not through `Acquire`, so the future is `Send` for any
    // lifetime and a start can be spawned.
    let result = migrator.run_direct(target, &mut *conn, false).await;
    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await;
    let reset = sqlx::query("RESET statement_timeout")
        .execute(&mut *conn)
        .await;
    if result.is_err() || unlocked.is_err() || reset.is_err() {
        // A failed run returns before sqlx releases its own advisory lock (one per
        // database), and a failed unlock leaves this one: back in the pool, the
        // connection would hold them, and every later migration would wait on it. So
        // it is closed instead, which ends the session and its locks.
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.close()).await;
    }
    result?;
    unlocked?;
    reset?;
    tracing::info!("migrations applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_side_limits_are_startup_parameters() {
        let opts: PgConnectOptions = "postgres://u@localhost/db".parse().unwrap();
        let set = PoolConfig::default().limits(opts.clone());
        assert_eq!(
            set.get_options(),
            Some("-c statement_timeout=30000 -c idle_in_transaction_session_timeout=60000")
        );
        let none = PoolConfig {
            statement_timeout: None,
            idle_in_transaction_timeout: None,
            ..PoolConfig::default()
        }
        .limits(opts);
        assert_eq!(none.get_options(), None);
    }

    #[test]
    fn a_certificate_that_does_not_verify_is_not_unreachable() {
        use std::io::{Error, ErrorKind};
        let io = |kind| sqlx::Error::Io(Error::new(kind, "x"));
        assert!(
            !unreachable(&io(ErrorKind::InvalidData)),
            "rustls's InvalidCertificate"
        );
        assert!(!unreachable(&sqlx::Error::Configuration("x".into())));
        assert!(unreachable(&io(ErrorKind::ConnectionRefused)));
        assert!(unreachable(&io(ErrorKind::HostUnreachable)));
        assert!(unreachable(&sqlx::Error::PoolTimedOut));
    }

    #[tokio::test]
    async fn an_unreachable_database_is_tried_until_patience_runs_out() {
        // Port 1 on loopback refuses at once; sqlx retries that within its acquire
        // timeout, so keep that short.
        let config = PoolConfig {
            acquire_timeout: Duration::from_millis(100),
            ..PoolConfig::default()
        };
        let started = std::time::Instant::now();
        let error = config
            .connect_within(
                "postgres://u:p@127.0.0.1:1/app",
                Duration::from_millis(1_200),
            )
            .await
            .unwrap_err();
        let took = started.elapsed();
        assert!(unreachable(&error), "{error}");
        assert!(took >= Duration::from_millis(500), "retried: {took:?}");
        assert!(took < Duration::from_secs(5), "bounded: {took:?}");

        let started = std::time::Instant::now();
        config
            .connect_within("postgres://u:p@127.0.0.1:1/app", Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "zero tries once"
        );
    }

    #[test]
    fn only_verify_full_counts_as_verified_off_this_machine() {
        let unverified = |url: &str| unverified_tls(&url.parse().unwrap());
        assert!(unverified("postgres://u:p@db.example/app"));
        assert!(unverified("postgres://u:p@db.example/app?sslmode=require"));
        assert!(unverified(
            "postgres://u:p@db.example/app?sslmode=verify-ca"
        ));
        assert!(!unverified(
            "postgres://u:p@db.example/app?sslmode=verify-full"
        ));
        assert!(!unverified("postgres://u:p@localhost/app"));
        assert!(!unverified("postgres://u:p@[::1]/app"), "IPv6 loopback");
        assert!(!unverified("postgres://u:p@127.0.0.1:5432/app"));
    }
}
