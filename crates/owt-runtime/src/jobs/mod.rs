//! Background work across replicas.
//!
//! Every replica runs the same binary, so every periodic task runs on every replica
//! unless something says otherwise. Three ways to say it:
//!
//! | mode | runs on | for |
//! |---|---|---|
//! | [`Jobs::every_replica`] | each replica, each period | idempotent work: the task takes its rows with `FOR UPDATE SKIP LOCKED`, so replicas share it |
//! | [`Jobs::singleton`] | at most one replica at a time | work that must not overlap (a simulation driver): a Postgres advisory lock, tried and skipped, never waited on; a run whose lock's connection drops is stopped |
//! | [`Jobs::leased`] (feature `redis`) | one replica, the same one while it lives | work whose owner should stick (a clock): a Redis lease with a TTL, renewed while held, taken over when its holder dies |
//!
//! All three share a loop:
//!
//! * **Jitter.** The first run waits a random part of the jitter, and each later run
//!   waits the period plus a random part of it, so replicas started together do not
//!   hit the database in lockstep.
//! * **Boundaries.** An [`Every::aligned`] job runs at fixed times by the wall clock
//!   instead ("at 03:00 UTC", "every Monday"): each run waits for the next boundary,
//!   then a random part of the jitter, so replicas do not stampede it.
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngExt;
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;

/// How often a job runs: once per period from when its loop starts ([`Every::new`]),
/// or at fixed boundaries by the wall clock ([`Every::aligned`]).
#[derive(Clone, Copy, Debug)]
pub struct Every {
    period: Duration,
    jitter: Duration,
    /// Aligned: the boundaries are the UNIX epoch's multiples of the period, plus this.
    offset: Option<Duration>,
}

/// The most an aligned schedule's default jitter is.
const ALIGNED_JITTER: Duration = Duration::from_secs(10);

/// The longest an aligned wait sleeps before it reads the wall clock again: tokio's
/// clock is monotonic, so a wall clock stepped forward (a host resumed from suspend,
/// a corrected clock) would otherwise be noticed only at the end of a long sleep.
const ALIGNED_NAP: Duration = Duration::from_secs(60);

impl Every {
    /// Once per `period`, with a tenth of it as jitter. A zero period is raised to
    /// a millisecond: a loop with no wait would spin a core.
    #[must_use]
    pub fn new(period: Duration) -> Self {
        let period = period.max(Duration::from_millis(1));
        Self {
            period,
            jitter: period / 10,
            offset: None,
        }
    }

    /// At each boundary: every instant, by the wall clock in UTC, that is a whole
    /// number of periods after the UNIX epoch, plus `offset`; then a random part of
    /// the jitter, a tenth of the period up to 10 seconds by default. The first run
    /// waits for the first boundary after the loop starts, too.
    ///
    /// `aligned(Duration::from_secs(3600), Duration::ZERO)` runs at the top of each
    /// hour; `aligned(DAY, 3 * HOUR)` at 03:00 UTC. The epoch (1970-01-01) was a
    /// Thursday, so a weekly boundary on another day is that many days on:
    /// `aligned(7 * DAY, 4 * DAY)` is each Monday at 00:00 UTC, and
    /// `aligned(7 * DAY, 4 * DAY + 3 * HOUR)` each Monday at 03:00. Boundaries are in
    /// UTC: a local time that follows daylight saving time is not a fixed period.
    ///
    /// A run that lasts past one or more boundaries is followed by the next boundary
    /// after it ends: the missed ones are skipped, not caught up. The wall clock is
    /// read at least every minute while waiting, so a run waits for its boundary by
    /// the wall clock even when it is stepped. A replica runs each boundary once; a
    /// wall clock stepped back past a boundary already run runs it again, and
    /// replicas each wake at the same boundary (a [`Jobs::singleton`] keeps them from
    /// overlapping, not from running one after another), so the task does the
    /// boundary's work once by the app's own record of it, keyed by
    /// [`Every::latest_boundary`].
    ///
    /// An `offset` of a period or more is taken modulo the period. A zero period is
    /// raised to a millisecond, as in [`Every::new`].
    #[must_use]
    pub fn aligned(period: Duration, offset: Duration) -> Self {
        let period = period.max(Duration::from_millis(1));
        Self {
            period,
            jitter: (period / 10).min(ALIGNED_JITTER),
            offset: Some(from_nanos(offset.as_nanos() % period.as_nanos())),
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

    /// The offset of an aligned schedule's boundaries (less than the period); `None`
    /// for one from [`Every::new`].
    #[must_use]
    pub fn offset(&self) -> Option<Duration> {
        self.offset
    }

    /// The latest boundary at or before `now`: the one a run that starts at `now`
    /// was woken for, as the key of its work (the week it closes, say). `None` for a
    /// schedule from [`Every::new`], or before the first boundary after the epoch.
    #[must_use]
    pub fn latest_boundary(&self, now: SystemTime) -> Option<SystemTime> {
        let offset = self.offset?.as_nanos();
        let since = now.duration_since(UNIX_EPOCH).ok()?.as_nanos();
        let period = self.period.as_nanos();
        let after = since.checked_sub(offset)?;
        Some(UNIX_EPOCH + from_nanos(offset + after / period * period))
    }

    /// The first boundary strictly after `now`. `None` for a schedule from
    /// [`Every::new`].
    fn next_boundary(&self, now: SystemTime) -> Option<SystemTime> {
        let offset = self.offset?.as_nanos();
        let since = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let period = self.period.as_nanos();
        let next = match since.checked_sub(offset) {
            Some(after) => offset + (after / period + 1) * period,
            None => offset,
        };
        // Past what the platform's clock holds (a period of `Duration::MAX`): tens of
        // thousands of years on, which is never.
        Some(
            UNIX_EPOCH
                .checked_add(from_nanos(next))
                .unwrap_or(UNIX_EPOCH + Duration::from_secs(1 << 40)),
        )
    }

    fn spread(&self) -> Duration {
        if self.jitter.is_zero() {
            return Duration::ZERO;
        }
        self.jitter.mul_f64(rand::rng().random_range(0.0..1.0))
    }
}

/// A count of nanoseconds as a [`Duration`] (saturating, past any real time).
fn from_nanos(nanos: u128) -> Duration {
    const NANOS: u128 = 1_000_000_000;
    let secs = u64::try_from(nanos / NANOS).unwrap_or(u64::MAX);
    Duration::new(secs, u32::try_from(nanos % NANOS).unwrap_or_default())
}

/// The wall clock, read by aligned waits; a test's clock under tokio's paused time.
fn wall_now() -> SystemTime {
    #[cfg(test)]
    if let Some(now) = tests::virtual_now() {
        return now;
    }
    SystemTime::now()
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

    pub(crate) fn spawn<F>(&self, fut: F)
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
        let task = Arc::new(task);
        self.spawn(async move {
            let mut first = true;
            while this.wait(every, std::mem::take(&mut first)).await {
                let task = task.clone();
                let outcome = this.run(name, move || task()).await;
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
    ///
    /// The lock lives as long as its session. If that connection drops mid-run (an
    /// idle-session timeout, a failover, a network reset), Postgres releases the lock
    /// and another replica may take it at its next tick; so the connection is checked
    /// every [`LOCK_CHECK`] (the lock seen held, within the check's own deadline), and
    /// a run whose check fails is aborted (at its next `.await`) and counted as failed,
    /// rather than left running beside the new holder. The guarantee has a window: up
    /// to two checks may pass between the lock's loss and the abort, and a statement
    /// the run already sent may still commit. Make overlapping work idempotent, or
    /// guard its writes (a fencing token), where that matters. A task must tolerate
    /// being stopped part-way, as it would a crash. Session advisory locks need a
    /// direct connection: a transaction-mode pooler (`PgBouncer`) gives no such
    /// guarantee at all.
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
        let task = Arc::new(task);
        self.spawn(async move {
            let mut first = true;
            while this.wait(every, std::mem::take(&mut first)).await {
                let outcome = match try_lock(&pool, lock_id).await {
                    Ok(Some(mut conn)) => {
                        let task = task.clone();
                        let outcome = this
                            .run_until(name, move || task(), lock_lost(&mut conn, name, lock_id))
                            .await;
                        // Bounded like the checks: a hung connection is closed, which
                        // ends the session and its lock, rather than waited on.
                        let unlocked = tokio::time::timeout(
                            LOCK_CHECK,
                            sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
                                .bind(lock_id)
                                .fetch_one(&mut *conn),
                        )
                        .await;
                        if !matches!(unlocked, Ok(Ok(true))) {
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
    /// loop. The closure that builds the future runs inside that task too: a panic
    /// there (a config read, an `unwrap`) is the app's code failing like any other.
    /// Records the outcome and the time.
    async fn run<F, Fut>(&self, name: &'static str, make: F) -> Outcome
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.run_until(name, make, std::future::pending()).await
    }

    /// [`Jobs::run`], aborting the run if `stop` resolves first.
    async fn run_until<F, Fut>(
        &self,
        name: &'static str,
        make: F,
        stop: impl Future<Output = ()>,
    ) -> Outcome
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let started = Instant::now();
        let mut handle = tokio::spawn(async move { make().await });
        let joined = tokio::select! {
            joined = &mut handle => joined,
            () = stop => {
                handle.abort();
                let _ = handle.await;
                tracing::error!(job = name, "background job stopped: it lost its lock");
                self.record(name, Outcome::Failed, Some(started.elapsed()));
                return Outcome::Failed;
            }
        };
        let outcome = match joined {
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
    /// period plus one; for an aligned schedule, the next boundary and then a random
    /// part of the jitter. False once shutdown is requested.
    async fn wait(&self, every: Every, first: bool) -> bool {
        if let Some(boundary) = every.next_boundary(wall_now()) {
            // Slept in naps by tokio's monotonic clock, each checked against the wall
            // clock, so the run never starts before its boundary by the wall clock.
            while let Ok(left) = boundary.duration_since(wall_now()) {
                if left.is_zero() || !self.sleep(left.min(ALIGNED_NAP)).await {
                    break;
                }
            }
            return self.sleep(every.spread()).await;
        }
        let delay = if first {
            every.spread()
        } else {
            every.period.saturating_add(every.spread())
        };
        self.sleep(delay).await
    }

    /// Sleep for `delay`. False once shutdown is requested.
    async fn sleep(&self, delay: Duration) -> bool {
        tokio::select! {
            () = self.shutdown.cancelled() => false,
            () = tokio::time::sleep(delay) => !self.shutdown.is_cancelled(),
        }
    }
}

/// How often a singleton's run checks that its lock's connection is alive.
pub const LOCK_CHECK: Duration = Duration::from_secs(2);

/// Resolves (and marks the connection to be closed) when the lock is not seen held
/// within a check: the session ended, or its connection hangs half-open (a lost
/// node, a partition), which a check without a deadline would wait out for as long
/// as TCP takes to give up while another replica takes the lock.
async fn lock_lost(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    name: &'static str,
    lock_id: i64,
) {
    loop {
        tokio::time::sleep(LOCK_CHECK).await;
        let held = tokio::time::timeout(
            LOCK_CHECK,
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory'
                    AND pid = pg_backend_pid() AND granted
                    AND objsubid = 1
                    AND ((classid::bigint << 32) | objid::bigint) = $1)",
            )
            .bind(lock_id)
            .fetch_one(&mut **conn),
        )
        .await;
        match held {
            Ok(Ok(true)) => {}
            outcome => {
                tracing::warn!(job = name, ?outcome, "the job's lock is no longer held");
                conn.close_on_drop();
                return;
            }
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);
    const DAY: Duration = Duration::from_hours(24);

    thread_local! {
        /// The wall clock a test set: this time at this paused-clock instant.
        static CLOCK: Cell<Option<(SystemTime, tokio::time::Instant)>> = const { Cell::new(None) };
    }

    /// The test's wall clock, moving with tokio's paused one. The tests run on a
    /// current-thread runtime, so the jobs' tasks read the same thread's clock.
    pub(super) fn virtual_now() -> Option<SystemTime> {
        let (wall, at) = CLOCK.with(Cell::get)?;
        Some(wall + at.elapsed())
    }

    /// Set the wall clock to `since` the epoch, from now on the paused clock.
    fn set_clock(since: Duration) {
        let wall = UNIX_EPOCH + since;
        CLOCK.with(|c| c.set(Some((wall, tokio::time::Instant::now()))));
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn since(t: SystemTime) -> Duration {
        t.duration_since(UNIX_EPOCH).unwrap()
    }

    /// 2026-10-12 11:00:00 UTC, a Monday.
    const ELEVEN: u64 = 1_791_802_800;

    /// The `n`th hour from 11:00, since the epoch.
    fn hour(n: u32) -> Duration {
        Duration::from_secs(ELEVEN) + HOUR * n
    }

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn the_next_boundary_is_strictly_after_now() {
        let hourly = Every::aligned(HOUR, Duration::ZERO);
        assert_eq!(hourly.next_boundary(at(ELEVEN - 1)), Some(at(ELEVEN)));
        assert_eq!(hourly.next_boundary(at(ELEVEN)), Some(at(ELEVEN + 3600)));
        assert_eq!(
            hourly.next_boundary(at(ELEVEN + 1)),
            Some(at(ELEVEN + 3600))
        );
        assert_eq!(hourly.latest_boundary(at(ELEVEN)), Some(at(ELEVEN)));
        assert_eq!(hourly.latest_boundary(at(ELEVEN + 3599)), Some(at(ELEVEN)));
        assert_eq!(Every::new(HOUR).next_boundary(at(ELEVEN)), None);
        assert_eq!(Every::new(HOUR).latest_boundary(at(ELEVEN)), None);

        // Before the first boundary after the epoch.
        let late = Every::aligned(DAY, 3 * HOUR);
        assert_eq!(late.next_boundary(UNIX_EPOCH), Some(at(3 * 3600)));
        assert_eq!(late.latest_boundary(at(3 * 3600 - 1)), None);
        // 03:00 UTC.
        assert_eq!(
            late.next_boundary(at(ELEVEN)),
            Some(at(ELEVEN - 11 * 3600 + DAY.as_secs() + 3 * 3600))
        );
    }

    #[test]
    fn a_boundary_past_any_clock_is_far_off_not_a_panic() {
        let never = Every::aligned(Duration::MAX, Duration::ZERO);
        let next = never.next_boundary(at(ELEVEN)).unwrap();
        assert!(next > at(ELEVEN) + 1000 * 365 * DAY);
    }

    #[test]
    fn an_offset_of_a_period_or_more_is_reduced() {
        let a = Every::aligned(HOUR, Duration::from_mins(90));
        assert_eq!(a.offset(), Some(Duration::from_mins(30)));
        assert_eq!(a.next_boundary(at(ELEVEN)), Some(at(ELEVEN + 1800)));
        assert_eq!(Every::aligned(HOUR, HOUR).offset(), Some(Duration::ZERO));
        assert_eq!(Every::new(HOUR).offset(), None);
        let zero = Every::aligned(Duration::ZERO, Duration::from_secs(1));
        assert_eq!(zero.period(), Duration::from_millis(1));
        assert_eq!(zero.offset(), Some(Duration::ZERO));
    }

    #[test]
    fn monday_is_four_days_after_the_epoch() {
        let mondays = Every::aligned(7 * DAY, 4 * DAY);
        // Wednesday 2026-10-14 12:00 UTC to Monday 2026-10-19 00:00 UTC.
        assert_eq!(
            mondays.next_boundary(at(1_791_979_200)),
            Some(at(1_792_368_000))
        );
        assert_eq!(
            mondays.latest_boundary(at(1_791_979_200)),
            Some(at(1_792_368_000 - 7 * 86_400))
        );
        // From the boundary itself, the next Monday.
        assert_eq!(
            mondays.next_boundary(at(1_792_368_000)),
            Some(at(1_792_368_000 + 7 * 86_400))
        );
    }

    #[test]
    fn the_default_jitter_is_small_for_an_aligned_schedule() {
        assert_eq!(
            Every::aligned(7 * DAY, Duration::ZERO).jitter,
            ALIGNED_JITTER
        );
        assert_eq!(
            Every::aligned(Duration::from_secs(10), Duration::ZERO).jitter,
            Duration::from_secs(1)
        );
    }

    /// Run the paused clock forward until `done` holds (or a day of virtual time).
    async fn until(done: impl Fn() -> bool) {
        for _ in 0..1440 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        panic!("condition never held");
    }

    /// The wall times at which each run started.
    type Starts = Arc<Mutex<Vec<Duration>>>;

    /// A task that records when each run starts, and those times.
    fn recorder() -> (
        Starts,
        impl Fn() -> std::future::Ready<anyhow::Result<()>> + Send + Sync + 'static,
    ) {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let s = starts.clone();
        let task = move || {
            s.lock().unwrap().push(since(wall_now()));
            std::future::ready(Ok(()))
        };
        (starts, task)
    }

    #[tokio::test(start_paused = true)]
    async fn an_aligned_job_runs_at_each_boundary_and_not_before() {
        set_clock(hour(0).saturating_sub(500 * MS));
        let jobs = Jobs::new(CancellationToken::new());
        let (starts, task) = recorder();
        jobs.every_replica(
            "hourly",
            Every::aligned(HOUR, Duration::ZERO).jitter(Duration::ZERO),
            task,
        );
        until(|| starts.lock().unwrap().len() >= 3).await;
        jobs.shutdown().cancel();
        jobs.stopped().await;
        let starts = starts.lock().unwrap();
        for (n, &t) in (0..).zip(starts.iter().take(3)) {
            let boundary = hour(n);
            assert!(
                (boundary..boundary + 10 * MS).contains(&t),
                "run {n} at {t:?}, boundary {boundary:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn jitter_comes_after_the_boundary() {
        set_clock(hour(0).saturating_sub(10_000 * MS));
        let jobs = Jobs::new(CancellationToken::new());
        let (starts, task) = recorder();
        jobs.every_replica(
            "hourly",
            Every::aligned(HOUR, Duration::ZERO).jitter(Duration::from_secs(30)),
            task,
        );
        until(|| starts.lock().unwrap().len() >= 4).await;
        jobs.shutdown().cancel();
        jobs.stopped().await;
        for (n, &t) in (0..).zip(starts.lock().unwrap().iter().take(4)) {
            let boundary = hour(n);
            assert!(
                (boundary..boundary + 30_000 * MS).contains(&t),
                "run {n} at {t:?}, boundary {boundary:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_past_boundaries_skips_them() {
        set_clock(hour(0).saturating_sub(1000 * MS));
        let jobs = Jobs::new(CancellationToken::new());
        let starts = Arc::new(Mutex::new(Vec::new()));
        let s = starts.clone();
        let runs = Arc::new(AtomicUsize::new(0));
        let r = runs.clone();
        jobs.every_replica(
            "slow",
            Every::aligned(HOUR, Duration::ZERO).jitter(Duration::ZERO),
            move || {
                s.lock().unwrap().push(since(wall_now()));
                let first = r.fetch_add(1, SeqCst) == 0;
                async move {
                    if first {
                        // Past 12:00 and 13:00, to 13:30.
                        tokio::time::sleep(Duration::from_mins(150)).await;
                    }
                    Ok(())
                }
            },
        );
        until(|| runs.load(SeqCst) >= 3).await;
        jobs.shutdown().cancel();
        jobs.stopped().await;
        let starts: Vec<u64> = starts
            .lock()
            .unwrap()
            .iter()
            .map(Duration::as_secs)
            .collect();
        assert_eq!(
            &starts[..3],
            [hour(0), hour(3), hour(4)].map(|h| h.as_secs())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wall_clock_is_waited_for_even_when_tokios_runs_ahead() {
        // The wall clock stepped back by an hour just before 11:00: the run waits for
        // 11:00 by the wall clock, though tokio's clock passed the hour it slept for.
        set_clock(hour(0).saturating_sub(1000 * MS));
        let jobs = Jobs::new(CancellationToken::new());
        let (starts, task) = recorder();
        jobs.every_replica(
            "hourly",
            Every::aligned(HOUR, Duration::ZERO).jitter(Duration::ZERO),
            task,
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        set_clock(hour(0).saturating_sub(HOUR + 500 * MS));
        until(|| !starts.lock().unwrap().is_empty()).await;
        jobs.shutdown().cancel();
        jobs.stopped().await;
        let first = starts.lock().unwrap()[0];
        assert!(first >= hour(0), "ran at {first:?}, before its boundary");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_a_long_aligned_wait() {
        set_clock(hour(0));
        let jobs = Jobs::new(CancellationToken::new());
        let (starts, task) = recorder();
        jobs.every_replica("weekly", Every::aligned(7 * DAY, 4 * DAY), task);
        tokio::time::sleep(Duration::from_secs(5)).await;
        let asked = tokio::time::Instant::now();
        jobs.shutdown().cancel();
        jobs.stopped().await;
        assert!(asked.elapsed() < Duration::from_secs(1));
        assert!(starts.lock().unwrap().is_empty());
    }
}
