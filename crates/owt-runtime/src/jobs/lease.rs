//! Leases in Redis: which replica owns a piece of work, until it stops renewing.
//!
//! A lease is a Redis key holding its holder's id, set with `NX` and a TTL. Renewal and
//! release are compare-and-set Lua scripts, so a replica can never extend or delete a
//! lease another replica has since taken: after a long pause (GC, a stalled node) the
//! old holder's renewal fails instead of stealing the lease back.
//!
//! Size the TTL for the failure it covers. A short one means a dead holder's work
//! resumes elsewhere within seconds; it must still outlast the gap between renewals,
//! or ownership flaps between replicas. A Redis error is "not held": a replica that
//! can't reach Redis does the leased work nowhere, rather than everywhere.
//!
//! Lifted from epicpartygame-rs's per-session clock and loop leases.

use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use redis::aio::ConnectionManager;
use tokio_util::sync::CancellationToken;

use super::{Every, Jobs, Outcome};

const RENEW_IF_HELD: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0";

const RELEASE_IF_HELD: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0";

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// This replica's view of the lease table. Cheap to clone.
#[derive(Clone)]
pub struct Leases {
    redis: ConnectionManager,
    holder: Arc<str>,
    prefix: Arc<str>,
    renew: Arc<redis::Script>,
    release: Arc<redis::Script>,
}

impl Leases {
    /// Leases held as `holder` (unique per replica: [`Leases::new_holder_id`]), under
    /// keys `<prefix>:lease:<name>`. The prefix keeps deployments that share a Redis
    /// apart.
    #[must_use]
    pub fn new(redis: ConnectionManager, holder: impl Into<String>, prefix: &str) -> Self {
        Self {
            redis,
            holder: Arc::from(holder.into()),
            prefix: Arc::from(prefix),
            renew: Arc::new(redis::Script::new(RENEW_IF_HELD)),
            release: Arc::new(redis::Script::new(RELEASE_IF_HELD)),
        }
    }

    /// `"<hostname>:<8 hex>"`: the pod's name (Kubernetes sets `HOSTNAME`) and a
    /// random suffix, so a restarted pod with the same name is a new holder.
    #[must_use]
    pub fn new_holder_id() -> String {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "host".into());
        format!("{host}:{:08x}", rand::rng().random::<u32>())
    }

    /// This replica's holder id.
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    fn key(&self, name: &str) -> String {
        format!("{}:lease:{name}", self.prefix)
    }

    /// Take the lease `name` for `ttl`, or confirm this replica already holds it.
    /// Confirming does not extend it: call [`Leases::renew`] for that.
    pub async fn acquire(&self, name: &str, ttl: Duration) -> bool {
        let mut conn = self.redis.clone();
        let key = self.key(name);
        let set: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg(&*self.holder)
            .arg("NX")
            .arg("PX")
            .arg(millis(ttl))
            .query_async(&mut conn)
            .await;
        match set {
            Ok(Some(_)) => true,
            Ok(None) => {
                let current: redis::RedisResult<Option<String>> =
                    redis::cmd("GET").arg(&key).query_async(&mut conn).await;
                matches!(current, Ok(Some(h)) if *h == *self.holder)
            }
            Err(e) => {
                tracing::warn!(lease = name, error = %e, "lease acquire failed, Redis unreachable");
                false
            }
        }
    }

    /// Extend the lease to `ttl` from now, if this replica still holds it.
    pub async fn renew(&self, name: &str, ttl: Duration) -> bool {
        let mut conn = self.redis.clone();
        let result: redis::RedisResult<i64> = self
            .renew
            .key(self.key(name))
            .arg(&*self.holder)
            .arg(millis(ttl))
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok(n) => n == 1,
            Err(e) => {
                tracing::warn!(lease = name, error = %e, "lease renew failed, Redis unreachable");
                false
            }
        }
    }

    /// Give the lease up, if this replica holds it.
    pub async fn release(&self, name: &str) {
        let mut conn = self.redis.clone();
        let result: redis::RedisResult<i64> = self
            .release
            .key(self.key(name))
            .arg(&*self.holder)
            .invoke_async(&mut conn)
            .await;
        if let Err(e) = result {
            tracing::warn!(lease = name, error = %e, "lease release failed, Redis unreachable");
        }
    }

    /// True only for the first caller within `ttl`, cluster-wide: "do this once per
    /// window", such as one replica repairing a stuck session per sweep.
    pub async fn first_within(&self, name: &str, ttl: Duration) -> redis::RedisResult<bool> {
        let mut conn = self.redis.clone();
        let set: Option<String> = redis::cmd("SET")
            .arg(format!("{}:once:{name}", self.prefix))
            .arg("1")
            .arg("NX")
            .arg("PX")
            .arg(millis(ttl))
            .query_async(&mut conn)
            .await?;
        Ok(set.is_some())
    }
}

/// A leased run's hold on its lease. The lease is renewed in the background while
/// the run lasts; if a renewal fails (it expired and another replica took it, or Redis
/// went away), [`Held::lost`] resolves and the run should stop doing owner-only work.
#[derive(Clone, Debug)]
pub struct Held {
    lost: CancellationToken,
}

impl Held {
    /// The lease was lost during this run.
    #[must_use]
    pub fn is_lost(&self) -> bool {
        self.lost.is_cancelled()
    }

    /// Resolves when the lease is lost: `select!` on it in a long run.
    pub async fn lost(&self) {
        self.lost.cancelled().await;
    }
}

impl Jobs {
    /// Run `task` every period on the replica holding the lease `lease`; the others
    /// skip. A replica that holds it keeps it while it runs: the TTL is renewed at each
    /// tick, every third of the TTL during a run, and once more when the run ends, so
    /// the lease always has a full TTL in hand when the wait for the next tick starts
    /// and the work stays put. When its holder dies the lease expires and the next
    /// replica to tick takes it. On shutdown the lease is released, so a deploy hands
    /// over at once.
    ///
    /// `ttl` must outlast the period plus jitter, or ownership lapses between ticks and
    /// flaps between replicas; a shorter one is logged.
    pub fn leased<F, Fut>(
        &self,
        name: &'static str,
        every: Every,
        leases: Leases,
        lease: impl Into<String>,
        ttl: Duration,
        task: F,
    ) where
        F: Fn(Held) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let lease: Arc<str> = Arc::from(lease.into());
        if ttl <= every.period + every.jitter {
            tracing::warn!(job = name, ?ttl, period = ?every.period, "lease TTL does not outlast the period; ownership will flap");
        }
        let this = self.clone();
        self.spawn(async move {
            let mut first = true;
            while this.wait(every, std::mem::take(&mut first)).await {
                if !(leases.acquire(&lease, ttl).await && leases.renew(&lease, ttl).await) {
                    this.record(name, Outcome::Skipped, None);
                    tracing::trace!(job = name, outcome = Outcome::Skipped.as_str(), "job tick");
                    continue;
                }
                let held = Held {
                    lost: CancellationToken::new(),
                };
                let renewer = tokio::spawn(renew_while_running(
                    leases.clone(),
                    lease.clone(),
                    ttl,
                    held.lost.clone(),
                ));
                let outcome = this.run(name, task(held.clone())).await;
                renewer.abort();
                // The renewer last ran up to a third of the TTL ago, and the wait for
                // the next tick is the period plus jitter: without this renewal, a TTL
                // between two thirds of that wait and the wait itself expires between
                // ticks and hands the work to another replica.
                if !held.is_lost() && !leases.renew(&lease, ttl).await {
                    held.lost.cancel();
                }
                if held.is_lost() {
                    tracing::warn!(job = name, lease = &*lease, "lease lost during the run");
                }
                tracing::trace!(job = name, outcome = outcome.as_str(), "job tick");
            }
            leases.release(&lease).await;
            tracing::debug!(job = name, "job stopped");
        });
    }
}

/// Renew every third of the TTL until aborted; on a failed renewal, mark the lease
/// lost and stop.
async fn renew_while_running(
    leases: Leases,
    lease: Arc<str>,
    ttl: Duration,
    lost: CancellationToken,
) {
    // `interval` panics on a zero period; a TTL that short is a misconfiguration
    // already warned about, not a reason to take the process down.
    let mut tick = tokio::time::interval((ttl / 3).max(Duration::from_millis(1)));
    tick.tick().await;
    loop {
        tick.tick().await;
        if !leases.renew(&lease, ttl).await {
            lost.cancel();
            return;
        }
    }
}
