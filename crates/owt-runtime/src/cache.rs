//! A Redis read-through cache that can never fail a request (feature `redis`).
//!
//! Strictly an optimization: every operation is fail-open, so an absent, slow or
//! erroring Redis degrades to recomputation, never to an error. Connecting happens
//! in the background, so the app neither blocks startup nor crash-loops on Redis,
//! and a round trip slower than the response budget counts as a miss: past that
//! budget the cache costs more than the recomputation it saves.
//!
//! **Key discipline.** Nothing is invalidated by deleting keys: staleness is made
//! unrepresentable by the key itself. A key is either content-addressed (it carries
//! a fingerprint or format version of what produced the value, and lives until
//! Redis's LRU evicts it: [`Expiry::Lru`]) or scoped to a moment (it expires exactly
//! when the value stops being true: [`Expiry::At`]). [`Expiry::For`] is the escape
//! hatch for values that are merely allowed to be a little stale.
//!
//! Run Redis for it as production does: no persistence, bounded, LRU-evicted
//! (`--save "" --appendonly no --maxmemory … --maxmemory-policy allkeys-lru`).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use tokio::sync::OnceCell;

/// How long a cached value lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// Content-addressed: never stale; left to `maxmemory-policy allkeys-lru`.
    Lru,
    /// Until this moment, exactly (a tick, a scheduled publish).
    At(SystemTime),
    /// For this long.
    For(Duration),
}

/// Timeouts; the defaults suit a cache next to the app.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// A round trip slower than this is a miss.
    pub response_timeout: Duration,
    /// How long one connection attempt may take.
    pub connect_timeout: Duration,
    /// The longest wait between reconnection attempts.
    pub max_backoff: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_millis(100),
            connect_timeout: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// The cache. Cheap to clone; [`Cache::disabled`] is always correct.
#[derive(Clone, Default)]
pub struct Cache {
    /// `None`: disabled. An unset cell: configured, not connected yet.
    conn: Option<Arc<OnceCell<ConnectionManager>>>,
    prefix: Arc<str>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("enabled", &self.conn.is_some())
            .field("connected", &self.is_connected())
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl Cache {
    /// No cache: every read misses, every write is dropped.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Start connecting to `url` in the background and return at once. Every key is
    /// stored under `<prefix>:`, so several apps (or test runs) can share a Redis.
    /// Once established, the connection reconnects on its own.
    ///
    /// Must be called inside a Tokio runtime.
    pub fn connect(url: &str, prefix: &str, options: Options) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        let cell = Arc::new(OnceCell::new());
        let slot = cell.clone();
        tokio::spawn(async move {
            let config = ConnectionManagerConfig::new()
                .set_response_timeout(Some(options.response_timeout))
                .set_connection_timeout(Some(options.connect_timeout));
            let mut backoff = Duration::from_millis(500);
            loop {
                match client
                    .get_connection_manager_with_config(config.clone())
                    .await
                {
                    Ok(manager) => {
                        let _ = slot.set(manager);
                        tracing::info!("redis cache connected");
                        return;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, retry_in = ?backoff, "redis unavailable; serving uncached");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(options.max_backoff);
                    }
                }
            }
        });
        Ok(Self {
            conn: Some(cell),
            prefix: Arc::from(format!("{prefix}:")),
        })
    }

    fn manager(&self) -> Option<ConnectionManager> {
        self.conn.as_ref()?.get().cloned()
    }

    /// Whether reads can hit yet.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.manager().is_some()
    }

    fn key(&self, k: &str) -> String {
        format!("{}{k}", self.prefix)
    }

    /// Many keys in one round trip. Misses and errors are both `None`.
    pub async fn mget(&self, keys: &[String]) -> Vec<Option<Vec<u8>>> {
        let misses = || vec![None; keys.len()];
        let Some(mut conn) = self.manager() else {
            return misses();
        };
        if keys.is_empty() {
            return Vec::new();
        }
        let prefixed: Vec<String> = keys.iter().map(|k| self.key(k)).collect();
        match redis::cmd("MGET")
            .arg(&prefixed)
            .query_async::<Vec<Option<Vec<u8>>>>(&mut conn)
            .await
        {
            Ok(values) if values.len() == keys.len() => values,
            Ok(_) => misses(),
            Err(err) => {
                tracing::warn!(error = %err, "redis MGET failed; treating as a miss");
                misses()
            }
        }
    }

    /// One key; a miss or an error is `None`.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.mget(&[key.to_owned()]).await.pop().flatten()
    }

    /// Write entries and wait for Redis to take them (or fail, which is logged and
    /// otherwise ignored). Handlers usually want [`Cache::set_detached`].
    pub async fn set(&self, entries: Vec<(String, Vec<u8>)>, expiry: Expiry) {
        let Some(mut conn) = self.manager() else {
            return;
        };
        if entries.is_empty() {
            return;
        }
        let mut pipe = redis::pipe();
        for (key, value) in entries {
            let key = self.key(&key);
            match expiry {
                Expiry::Lru => {
                    pipe.set(&key, value).ignore();
                }
                Expiry::For(ttl) => {
                    let ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
                    pipe.cmd("SET")
                        .arg(&key)
                        .arg(value)
                        .arg("PX")
                        .arg(ms)
                        .ignore();
                }
                Expiry::At(at) => {
                    // Milliseconds: EXPIREAT's whole seconds would truncate the moment
                    // and expire a value up to a second early.
                    let unix_ms = at
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    pipe.set(&key, value)
                        .ignore()
                        .cmd("PEXPIREAT")
                        .arg(&key)
                        .arg(unix_ms)
                        .ignore();
                }
            }
        }
        if let Err(err) = pipe.query_async::<()>(&mut conn).await {
            tracing::warn!(error = %err, "redis write failed; ignoring");
        }
    }

    /// Write entries without holding up the caller: the response that computed them
    /// is not held hostage to the cache write.
    pub fn set_detached(&self, entries: Vec<(String, Vec<u8>)>, expiry: Expiry) {
        if self.manager().is_none() || entries.is_empty() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move { this.set(entries, expiry).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_disabled_cache_misses_and_drops_writes() {
        let c = Cache::disabled();
        c.set(vec![("k".into(), b"v".to_vec())], Expiry::Lru).await;
        assert_eq!(c.get("k").await, None);
        assert_eq!(c.mget(&["a".into(), "b".into()]).await, vec![None, None]);
        assert!(!c.is_connected());
    }

    /// A Redis that isn't there costs nothing: startup doesn't wait and reads miss.
    #[tokio::test]
    async fn an_unreachable_redis_is_a_miss_not_an_error() {
        let started = std::time::Instant::now();
        let c = Cache::connect("redis://127.0.0.1:9/0", "t", Options::default()).unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "connect returned at once"
        );
        assert_eq!(c.get("k").await, None);
        c.set_detached(vec![("k".into(), b"v".to_vec())], Expiry::Lru);
        assert!(Cache::connect("not a url", "t", Options::default()).is_err());
    }

    /// Needs `REDIS_URL`; skipped without it (or with it blank).
    #[tokio::test]
    async fn values_round_trip_under_the_prefix_and_expire() {
        let Some(url) = crate::env::var("REDIS_URL") else {
            return;
        };
        let prefix = format!("owt-cache-test-{}", std::process::id());
        let c = Cache::connect(&url, &prefix, Options::default()).unwrap();
        for _ in 0..100 {
            if c.is_connected() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(c.is_connected());
        c.set(
            vec![("a".into(), b"1".to_vec()), ("b".into(), b"2".to_vec())],
            Expiry::Lru,
        )
        .await;
        assert_eq!(
            c.mget(&["a".into(), "x".into(), "b".into()]).await,
            vec![Some(b"1".to_vec()), None, Some(b"2".to_vec())]
        );
        let other = Cache::connect(&url, &format!("{prefix}-other"), Options::default()).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(other.get("a").await, None, "another prefix sees nothing");

        c.set(
            vec![("short".into(), b"s".to_vec())],
            Expiry::For(Duration::from_millis(150)),
        )
        .await;
        c.set(
            vec![("moment".into(), b"m".to_vec())],
            Expiry::At(SystemTime::now() + Duration::from_secs(1)),
        )
        .await;
        assert_eq!(c.get("short").await, Some(b"s".to_vec()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(c.get("short").await, None, "For expires");
        assert_eq!(c.get("moment").await, Some(b"m".to_vec()));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(c.get("moment").await, None, "At expires at the moment");
    }
}
