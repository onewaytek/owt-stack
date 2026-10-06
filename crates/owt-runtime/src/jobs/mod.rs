//! Background work across replicas.
//!
//! Every replica runs the same binary, so every periodic task runs on every replica
//! unless something says otherwise. Three ways to say it:
//!
//! | mode | runs on | for |
//! |---|---|---|
//! | [`Jobs::every_replica`] | each replica, each period | idempotent work: the task takes its rows with `FOR UPDATE SKIP LOCKED`, so replicas share it |
//! | [`Jobs::singleton`] | at most one replica at a time | work that must not overlap (a simulation driver): a Postgres advisory lock, tried and skipped, never waited on |
//! | [`Jobs::leased`] (feature `redis`) | one replica, the same one while it lives | work whose owner should stick (a clock): a Redis lease with a TTL, renewed while held, taken over when its holder dies |
//!
//! All three share a loop:
//!
//! * **Jitter.** The first run waits a random part of the jitter, and each later run
//!   waits the period plus a random part of it, so replicas started together do not
//!   hit the database in lockstep.
//! * **Isolation.** Each run is its own task. An error or a panic in one run is logged
//!   and counted (`failed`), and the loop goes on: one bad week must not stop the
//!   clock for good.
//! * **Shutdown.** Cancelling the [`CancellationToken`] stops every loop at its next
//!   wait; a run in progress finishes first. [`Jobs::stopped`] resolves when all have.
//!   A leased job releases its lease on the way out, so another replica takes over
//!   at once instead of after the TTL.
//! * **Metrics** (feature `metrics`): names are the app's ([`JobMetrics::prefixed`]),
//!   runs counted by `job` and `outcome` (`ran`, `skipped`, `failed`), run time timed
//!   by `job`.

#[cfg(feature = "redis")]
pub mod lease;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;

/// How often a job runs.
#[derive(Clone, Copy, Debug)]
pub struct Every {
    period: Duration,
    jitter: Duration,
}

impl Every {
    /// Once per `period`, with a tenth of it as jitter. A zero period is raised to
    /// a millisecond: a loop with no wait would spin a core.
    #[must_use]
    pub fn new(period: Duration) -> Self {
        let period = period.max(Duration::from_millis(1));
        Self {
            period,
            jitter: period / 10,
        }
    }

    /// Wait up to `jitter` extra before each run (zero for an exact period).
    #[must_use]
    pub fn jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// The period.
    #[must_use]
    pub fn period(&self) -> Duration {
        self.period
    }

    fn spread(&self) -> Duration {
        if self.jitter.is_zero() {
            return Duration::ZERO;
        }
        self.jitter.mul_f64(rand::rng().random_range(0.0..1.0))
    }
}

/// What one tick of a job did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The task ran to completion.
    Ran,
    /// Another replica held the lock or lease; nothing ran here.
    Skipped,
    /// The task returned an error or panicked.
    Failed,
}

impl Outcome {
    /// The metric label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ran => "ran",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

/// Where jobs record what they do.
#[cfg(feature = "metrics")]
#[derive(Clone, Debug)]
pub struct JobMetrics {
    runs: String,
    seconds: String,
}

#[cfg(feature = "metrics")]
impl JobMetrics {
    /// `<prefix>_job_runs_total{job,outcome}` and `<prefix>_job_seconds{job}`.
    #[must_use]
    pub fn prefixed(prefix: &str) -> Self {
        Self {
            runs: format!("{prefix}_job_runs_total"),
            seconds: format!("{prefix}_job_seconds"),
        }
    }

    /// Describe the metrics to the recorder.
    pub fn describe(&self) {
        metrics::describe_counter!(
            self.runs.clone(),
            "Background job ticks, by `job` and `outcome` (ran, skipped, failed)."
        );
        metrics::describe_histogram!(
            self.seconds.clone(),
            metrics::Unit::Seconds,
            "Time a background job's run took, by `job` (skipped ticks are not timed)."
        );
    }
}

/// This replica's background jobs. Cheap to clone; clones share the jobs and the
/// shutdown token.
#[derive(Clone)]
pub struct Jobs {
    shutdown: CancellationToken,
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<JobMetrics>>,
}

impl Jobs {
    /// Jobs that stop when `shutdown` is cancelled.
    #[must_use]
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            shutdown,
            handles: Arc::default(),
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    /// Record runs under these names.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn metrics(mut self, metrics: JobMetrics) -> Self {
        self.metrics = Some(Arc::new(metrics));
        self
    }

    /// The shutdown token, for tasks that want to stop early themselves.
    #[must_use]
    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// Resolves when every job's loop has stopped (after cancellation).
    pub async fn stopped(&self) {
        let handles = std::mem::take(
            &mut *self
                .handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for h in handles {
            let _ = h.await;
        }
    }

    #[cfg_attr(
        not(feature = "metrics"),
        expect(clippy::unused_self, reason = "records only with metrics")
    )]
    fn record(&self, name: &'static str, outcome: Outcome, took: Option<Duration>) {
        #[cfg(feature = "metrics")]
        if let Some(m) = &self.metrics {
            metrics::counter!(m.runs.clone(), "job" => name, "outcome" => outcome.as_str())
                .increment(1);
            if let Some(t) = took {
                metrics::histogram!(m.seconds.clone(), "job" => name).record(t.as_secs_f64());
            }
        }
        #[cfg(not(feature = "metrics"))]
        let _ = (name, outcome, took);
    }

    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let h = tokio::spawn(fut);
        self.handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(h);
    }

    /// Run `task` on every replica, every period. For idempotent work.
    pub fn every_replica<F, Fut>(&self, name: &'static str, every: Every, task: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let this = self.clone();
        self.spawn(async move {
            let mut first = true;
            while this.wait(every, std::mem::take(&mut first)).await {
                let outcome = this.run(name, task()).await;
                tracing::trace!(job = name, outcome = outcome.as_str(), "job tick");
            }
            tracing::debug!(job = name, "job stopped");
        });
    }

    /// Run `task` every period on whichever replica takes the Postgres advisory lock
    /// `lock_id` first; the others skip that tick. The lock is held on a connection of
    /// its own for exactly the run, and that connection is closed rather than pooled
    /// if the unlock fails, so a lock can never leak into the pool. The run holds that
    /// connection throughout, so a task that also takes connections from `pool` needs
    /// a pool of at least two, or it waits on itself.
    pub fn singleton<F, Fut>(
        &self,
        name: &'static str,
        every: Every,
        pool: sqlx::PgPool,
        lock_id: i64,
        task: F,
    ) where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let this = self.clone();
        self.spawn(async move {
            let mut first = true;
            while this.wait(every, std::mem::take(&mut first)).await {
                let outcome = match try_lock(&pool, lock_id).await {
                    Ok(Some(mut conn)) => {
                        let outcome = this.run(name, task()).await;
                        let unlocked =
                            sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
                                .bind(lock_id)
                                .fetch_one(&mut *conn)
                                .await;
                        if !matches!(unlocked, Ok(true)) {
                            tracing::warn!(
                                job = name,
                                "advisory unlock failed; closing its connection"
                            );
                            conn.close_on_drop();
                        }
                        outcome
                    }
                    Ok(None) => Outcome::Skipped,
                    Err(e) => {
                        tracing::warn!(job = name, error = %e, "could not try the job's lock");
                        this.record(name, Outcome::Failed, None);
                        Outcome::Failed
                    }
                };
                if outcome == Outcome::Skipped {
                    this.record(name, outcome, None);
                }
                tracing::trace!(job = name, outcome = outcome.as_str(), "job tick");
            }
            tracing::debug!(job = name, "job stopped");
        });
    }

    /// Run one tick of `task` as its own task, so a panic is a failed run, not a dead
    /// loop. Records the outcome and the time.
    async fn run<Fut>(&self, name: &'static str, fut: Fut) -> Outcome
    where
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let started = Instant::now();
        let outcome = match tokio::spawn(fut).await {
            Ok(Ok(())) => Outcome::Ran,
            Ok(Err(e)) => {
                tracing::error!(job = name, error = ?e, "background job failed");
                Outcome::Failed
            }
            Err(join) => {
                tracing::error!(
                    job = name,
                    panic = join.is_panic(),
                    "background job panicked or was cancelled"
                );
                Outcome::Failed
            }
        };
        self.record(name, outcome, Some(started.elapsed()));
        outcome
    }

    /// Sleep until the next tick: a random part of the jitter first (`first`), else the
    /// period plus one. False once shutdown is requested.
    async fn wait(&self, every: Every, first: bool) -> bool {
        let delay = if first {
            every.spread()
        } else {
            every.period + every.spread()
        };
        tokio::select! {
            () = self.shutdown.cancelled() => false,
            () = tokio::time::sleep(delay) => !self.shutdown.is_cancelled(),
        }
    }
}

/// The advisory lock on a connection of its own, or `None` if another session holds it.
async fn try_lock(
    pool: &sqlx::PgPool,
    lock_id: i64,
) -> sqlx::Result<Option<sqlx::pool::PoolConnection<sqlx::Postgres>>> {
    let mut conn = pool.acquire().await?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(got.then_some(conn))
}
