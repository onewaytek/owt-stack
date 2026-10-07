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
    /// Until this moment, exactly (a tick, a scheduled publish), by Redis's clock:
    /// keep the app's and Redis's clocks in sync (NTP), or expiry shifts by their
    /// skew. A moment already past writes nothing.
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

/// Milliseconds, clamped to what Redis accepts (an i64): `For(Duration::MAX)` caches
/// for ~292 million years rather than failing its whole batch.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis())
        .unwrap_or(u64::MAX)
        .min(i64::MAX as u64 / 2)
}

/// The cache. Cheap to clone; [`Cache::disabled`] is always correct.
#[derive(Clone, Default)]
pub struct Cache {
    /// `None`: disabled. An unset cell: configured, not connected yet.
    conn: Option<Arc<OnceCell<ConnectionManager>>>,
    prefix: Arc<str>,
    /// The most any one round trip may take, reconnecting included.
    budget: Duration,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("enabled", &self.conn.is_some())
            .field("connected", &self.is_connected())
            .field("prefix", &self.prefix)
            .field("budget", &self.budget)
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
    /// Once established, the connection reconnects on its own; until it has, every
    /// call returns within the response budget as a miss. The background attempts
    /// stop when the last clone of the cache is dropped.
    ///
    /// # Panics
    /// Outside a Tokio runtime.
    pub fn connect(url: &str, prefix: &str, options: Options) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        let cell = Arc::new(OnceCell::new());
        let slot = Arc::downgrade(&cell);
        tokio::spawn(async move {
            // The manager's own reconnect is bounded too, but the request path does
            // not rely on it: every call is wrapped in the budget (`within`). Without
            // that, a call during an outage waits out the manager's whole retry
            // schedule, 9 s against a refused port and 23 s against a silent one.
            let config = ConnectionManagerConfig::new()
                .set_response_timeout(Some(options.response_timeout))
                .set_connection_timeout(Some(options.connect_timeout))
                .set_number_of_retries(2)
                .set_max_delay(Duration::from_secs(1));
            let mut backoff = Duration::from_millis(500);
            loop {
                match client
                    .get_connection_manager_with_config(config.clone())
                    .await
                {
                    Ok(manager) => {
                        if let Some(slot) = slot.upgrade() {
                            let _ = slot.set(manager);
                        }
                        tracing::info!("redis cache connected");
                        return;
                    }
                    Err(err) => {
                        if slot.strong_count() == 0 {
                            return;
                        }
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
            budget: options.response_timeout,
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
        let mut cmd = redis::cmd("MGET");
        cmd.arg(&prefixed);
        let query = cmd.query_async::<Vec<Option<Vec<u8>>>>(&mut conn);
        match tokio::time::timeout(self.budget, query).await {
            Ok(Ok(values)) if values.len() == keys.len() => values,
            Ok(Ok(_)) => misses(),
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "redis MGET failed; treating as a miss");
                misses()
            }
            Err(_) => {
                tracing::debug!(budget = ?self.budget, "redis MGET over budget; treating as a miss");
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
        // Every expiry is part of its SET (PX, PXAT), so a dropped connection can't
        // leave a value written without the TTL that bounds it.
        let mut pipe = redis::pipe();
        let mut any = false;
        for (key, value) in entries {
            let mut cmd = redis::cmd("SET");
            cmd.arg(self.key(&key)).arg(value);
            match expiry {
                Expiry::Lru => {}
                Expiry::For(ttl) => {
                    cmd.arg("PX").arg(millis(ttl).max(1));
                }
                Expiry::At(at) => {
                    // A moment already past: the value is stale before it's written.
                    let Ok(unix) = at.duration_since(UNIX_EPOCH) else {
                        continue;
                    };
                    if at <= SystemTime::now() {
                        continue;
                    }
                    // Milliseconds: whole seconds would truncate the moment and
                    // expire a value up to a second early.
                    cmd.arg("PXAT").arg(millis(unix));
                }
            }
            pipe.add_command(cmd).ignore();
            any = true;
        }
        if !any {
            return;
        }
        match tokio::time::timeout(self.budget, pipe.query_async::<()>(&mut conn)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!(error = %err, "redis write failed; ignoring"),
            Err(_) => tracing::debug!(budget = ?self.budget, "redis write over budget; dropped"),
        }
    }

    /// Write entries without holding up the caller: the response that computed them
    /// is not held hostage to the cache write.
    ///
    /// # Panics
    /// Outside a Tokio runtime.
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
        let minute = Expiry::For(Duration::from_secs(60));
        c.set(
            vec![("a".into(), b"1".to_vec()), ("b".into(), b"2".to_vec())],
            minute,
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

    /// Values that can't be stored aren't: a moment already past writes nothing, and
    /// an absurd lifetime is clamped instead of failing the batch it is in.
    #[tokio::test]
    async fn past_moments_write_nothing_and_huge_lifetimes_still_store() {
        let Some(url) = crate::env::var("REDIS_URL") else {
            return;
        };
        let c = connected(&url, &format!("owt-cache-edges-{}", std::process::id())).await;
        c.set(
            vec![("past".into(), b"p".to_vec())],
            Expiry::At(SystemTime::now() - Duration::from_secs(5)),
        )
        .await;
        assert_eq!(c.get("past").await, None);
        c.set(
            vec![
                ("huge".into(), b"h".to_vec()),
                ("also".into(), b"a".to_vec()),
            ],
            Expiry::For(Duration::MAX),
        )
        .await;
        assert_eq!(
            c.mget(&["huge".into(), "also".into()]).await,
            vec![Some(b"h".to_vec()), Some(b"a".to_vec())]
        );
        c.set(
            vec![
                ("huge".into(), b"h".to_vec()),
                ("also".into(), b"a".to_vec()),
            ],
            Expiry::For(Duration::from_millis(1)),
        )
        .await;
    }

    async fn connected(url: &str, prefix: &str) -> Cache {
        let c = Cache::connect(url, prefix, Options::default()).unwrap();
        for _ in 0..100 {
            if c.is_connected() {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("never connected to {url}");
    }

    /// What the proxy in front of Redis does with connections.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Forward,
        /// Accept, then hang up at once: a Redis that refuses.
        Refuse,
        /// Accept and never answer: a Redis behind a dead network path.
        Blackhole,
    }

    /// A TCP proxy to `upstream` whose behaviour can be switched mid-test; switching
    /// away from Forward cuts the connections already open.
    async fn proxy(upstream: std::net::SocketAddr) -> (u16, tokio::sync::watch::Sender<Mode>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::watch::channel(Mode::Forward);
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                let mut rx = rx.clone();
                tokio::spawn(async move {
                    let now = *rx.borrow_and_update();
                    match now {
                        Mode::Refuse => {}
                        Mode::Blackhole => {
                            let _ = rx.changed().await;
                            std::future::pending::<()>().await;
                        }
                        Mode::Forward => {
                            let Ok(mut out) = tokio::net::TcpStream::connect(upstream).await else {
                                return;
                            };
                            tokio::select! {
                                _ = tokio::io::copy_bidirectional(&mut inbound, &mut out) => {}
                                _ = rx.changed() => {}
                            }
                        }
                    }
                });
            }
        });
        (port, tx)
    }

    /// A Redis that goes away after the cache connected costs each call its budget,
    /// not the connection manager's reconnect schedule (which was 9 s against a
    /// refused port and 23 s against a silent one), and the cache recovers.
    #[tokio::test]
    async fn an_outage_after_connecting_costs_each_call_its_budget() {
        let Some(url) = crate::env::var("REDIS_URL") else {
            return;
        };
        let parsed = url::Url::parse(&url).unwrap();
        let upstream = format!(
            "{}:{}",
            parsed.host_str().unwrap(),
            parsed.port().unwrap_or(6379)
        );
        let upstream = tokio::net::lookup_host(upstream)
            .await
            .unwrap()
            .next()
            .unwrap();
        let (port, mode) = proxy(upstream).await;
        let db = parsed.path().trim_start_matches('/');
        let via = format!("redis://127.0.0.1:{port}/{db}");
        let c = connected(&via, &format!("owt-cache-outage-{}", std::process::id())).await;
        c.set(
            vec![("k".into(), b"v".to_vec())],
            Expiry::For(Duration::from_secs(60)),
        )
        .await;
        assert_eq!(c.get("k").await, Some(b"v".to_vec()));

        let budget = Options::default().response_timeout + Duration::from_millis(150);
        for broken in [Mode::Refuse, Mode::Blackhole] {
            mode.send(broken).unwrap();
            for _ in 0..3 {
                let started = std::time::Instant::now();
                assert_eq!(c.get("k").await, None);
                c.set(
                    vec![("w".into(), b"w".to_vec())],
                    Expiry::For(Duration::from_secs(1)),
                )
                .await;
                assert!(
                    started.elapsed() < budget * 2,
                    "a get and a set took {:?}",
                    started.elapsed()
                );
            }
            mode.send(Mode::Forward).unwrap();
            let healed = std::time::Instant::now();
            while c.get("k").await.is_none() {
                assert!(
                    healed.elapsed() < Duration::from_secs(15),
                    "never recovered"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
