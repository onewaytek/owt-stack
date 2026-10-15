//! The Postgres pool and migrations.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// Pool sizing. The defaults suit a small app on one replica; size a busy one from
/// measurement (connections are the scarcest resource a replica holds).
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Most connections open at once.
    pub max: u32,
    /// Connections kept open when idle.
    pub min: u32,
    /// How long a caller waits for a connection before failing.
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max: 10,
            min: 1,
            acquire_timeout: Duration::from_secs(30),
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

    /// Connect to `url` now: startup fails if the database is unreachable. Warns
    /// when the connection's TLS is not verified (see [`unverified_tls`]).
    pub async fn connect(&self, url: &str) -> sqlx::Result<PgPool> {
        let opts: PgConnectOptions = url.parse()?;
        warn_if_unverified(&opts);
        self.options().connect_with(opts).await
    }

    /// A pool that connects on first use: startup survives a slow database. Warns
    /// as [`PoolConfig::connect`] does.
    pub fn connect_lazy(&self, url: &str) -> sqlx::Result<PgPool> {
        let opts: PgConnectOptions = url.parse()?;
        warn_if_unverified(&opts);
        Ok(self.options().connect_lazy_with(opts))
    }

    /// A second pool on the same database and settings as `pool`, with its own
    /// connections and this sizing, connecting on first use. For work that must never
    /// queue behind the general traffic.
    #[must_use]
    pub fn reserve_beside(&self, pool: &PgPool) -> PgPool {
        let opts: PgConnectOptions = (*pool.connect_options()).clone();
        self.options().connect_lazy_with(opts)
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
    let local = matches!(opts.get_host(), "localhost" | "127.0.0.1" | "::1")
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
/// another migrator (a predecessor app on the same schema) exclude this one.
pub async fn migrate_locked(
    pool: &PgPool,
    migrator: &Migrator,
    lock_id: i64,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await?;
    let result = migrator.run(&mut *conn).await;
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await?;
    result?;
    tracing::info!("migrations applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!unverified("postgres://u:p@127.0.0.1:5432/app"));
    }
}
