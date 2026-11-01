//! A durable job queue in Postgres.
//!
//! Each job is a row of `owt_jobs`, a table this module migrates into a ledger of its
//! own ([`migrate`]). A job goes through these states:
//!
//! ```text
//! queued ──claim──▶ running ──complete──▶ done   (purged after a while)
//!   ▲                 │
//!   └─retry (backoff)─┤
//!                     └─permanent error, or out of attempts──▶ dead   (until redriven)
//! ```
//!
//! * **Enqueue** ([`Queue::enqueue`], or [`Queue::enqueue_in`] inside the app's own
//!   transaction, so a job exists exactly when the change that wants it commits). An
//!   idempotency key ([`Job::key`]) makes a second enqueue of the same work return the
//!   first job instead of adding one; it does not make the work run once (see
//!   below). [`Job::delay`] and [`Job::run_at`] schedule it.
//! * **Claim** ([`Queue::claim`]) takes up to `n` due jobs, oldest first, with
//!   `FOR UPDATE SKIP LOCKED`: replicas claiming at once never take the same job and
//!   never wait on each other. Each claim counts an attempt and takes the next number
//!   of the job's claim counter, which only rises: that number is the claim's fencing
//!   token, and [`Queue::complete`], [`Queue::fail`], [`Queue::release`] and
//!   [`Queue::heartbeat`] act only while the job is still running under it.
//! * **Retry.** A failed attempt is queued again after an exponential backoff with
//!   jitter ([`Retry`]); after its last attempt, or on a [`JobError::permanent`] error,
//!   the job is dead: kept, payload and error, for [`Queue::dead`] and
//!   [`Queue::redrive`].
//! * **Stale claims.** A running job's heartbeat is renewed while its worker holds it.
//!   One whose heartbeat is older than the worker's `stale_after` (its replica died)
//!   is queued again, or dead when it has had its attempts
//!   ([`Queue::recover_stale`]).
//! * **The worker** ([`Queue::worker`]) does all of it: claims while it has free
//!   slots, runs the handler for each job in a task of its own, heartbeats, recovers
//!   stale claims, purges old done jobs, and stops gracefully: on shutdown it claims
//!   nothing more, lets running jobs finish for a grace period, then aborts the rest
//!   and puts them back in the queue. The aborted attempt stays counted, so a handler
//!   that never returns reaches `max_attempts` and the job goes dead. Heartbeats and
//!   housekeeping run in tasks of their own, so a slow claim or purge never delays a
//!   heartbeat.
//!
//! **Delivery is at least once.** Stale recovery, a heartbeat lost to a database
//! blip, and the put-back at shutdown all run a job again, perhaps after the first run
//! had its side effects. Fencing stops a stale worker from *recording* a result, not
//! from running: a handler must be idempotent, and an idempotency key deduplicates
//! enqueues, not executions. A claim lost before the result was recorded (the `lost`
//! outcome) means the side effect may have happened twice.
//!
//! **Payloads are opaque bytes** ([`Job::bytes`], or JSON with [`Job::json`]). The
//! table is not encrypted, and backups and replicas hold it: a payload carries
//! references (a row id) rather than personal or health data, and a payload that must
//! carry such data is encrypted by the app before it is enqueued. A done job's
//! payload is emptied; a dead job's is kept, for redriving. The last error is stored
//! too (`format!("{e:#}")`, cut to [`MAX_ERROR_CHARS`]) and logged, so handlers keep
//! personal data out of their error messages as well.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngExt;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{PgConnection, PgPool, SqlStr};
use tokio::task::{Id, JoinSet};

use crate::jobs::{CancellationToken, Jobs};

/// The table [`migrate`] records this module's migrations in, beside the app's
/// `_sqlx_migrations`.
pub const LEDGER: &str = "_owt_runtime_migrations";

/// The advisory lock [`migrate`] holds while it migrates.
pub const LOCK_ID: i64 = 0x6f77_745f_7175_6575;

/// The most rows one statement of [`Queue::purge_done`] deletes.
const PURGE_BATCH: i64 = 1000;

/// The longest error a job records; a longer one is cut at a character boundary.
pub const MAX_ERROR_CHARS: usize = 2000;

/// The migrations, in order: entry `i` is version `i + 1` in [`LEDGER`]. Append only;
/// a shipped entry is never edited.
const MIGRATIONS: &[(&str, &str)] = &[(
    "owt_runtime_queue",
    include_str!("../migrations/0001_queue.sql"),
)];

/// The migrations as a sqlx migrator on [`LEDGER`], for inspection; [`migrate`] applies
/// it.
#[must_use]
pub fn migrator() -> Migrator {
    let migrations = MIGRATIONS
        .iter()
        .zip(1..)
        .map(|((name, sql), version)| {
            Migration::new(
                version,
                std::borrow::Cow::Borrowed(*name),
                MigrationType::Simple,
                SqlStr::from_static(sql),
                false,
            )
        })
        .collect();
    let mut migrator = Migrator::with_migrations(migrations);
    migrator.dangerous_set_table_name(LEDGER);
    migrator
}

/// Create or update `owt_jobs` in the pool's schema, under [`LOCK_ID`]. Await it at
/// start, before the first enqueue; replicas starting together migrate once.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    crate::db::migrate_locked(pool, &migrator(), LOCK_ID).await
}

/// How a queue retries a failed job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry {
    /// Attempts a job gets, the first included (at least 1).
    pub max_attempts: u32,
    /// The pause after the first failure, doubled after each later one.
    pub base: Duration,
    /// The longest pause.
    pub cap: Duration,
}

impl Default for Retry {
    /// Five attempts, pausing about 10 s, 20 s, 40 s and 80 s between them, an hour at
    /// most.
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base: Duration::from_secs(10),
            cap: Duration::from_hours(1),
        }
    }
}

impl Retry {
    /// The pause before the attempt after failed attempt `attempt` (1 for the first):
    /// `base * 2^(attempt - 1)`, at most `cap`, then a random point in its upper half,
    /// so jobs that failed together do not come back together.
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(1).min(32);
        let full = self
            .base
            .saturating_mul(1_u32 << doublings.min(31))
            .min(self.cap);
        let half = full / 2;
        let spread = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
        half + Duration::from_millis(rand::rng().random_range(0..=spread))
    }
}

/// A job to enqueue.
#[derive(Clone)]
pub struct Job {
    payload: Vec<u8>,
    key: Option<String>,
    at: Option<SystemTime>,
    delay: Duration,
    max_attempts: Option<u32>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .field("key", &self.key)
            .field("at", &self.at)
            .field("delay", &self.delay)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl Job {
    /// A job carrying `payload` as it is.
    #[must_use]
    pub fn bytes(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            payload: payload.into(),
            key: None,
            at: None,
            delay: Duration::ZERO,
            max_attempts: None,
        }
    }

    /// A job carrying `value` as JSON ([`Claimed::json`] reads it back).
    pub fn json<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<Self> {
        Ok(Self::bytes(serde_json::to_vec(value)?))
    }

    /// An idempotency key (1 to 200 characters): while a job of this queue with the same
    /// key is in the table, enqueueing returns it instead of adding another. A key held
    /// by a dead job returns that dead job (`fresh: false`), and nothing new is queued,
    /// until it is discarded ([`Queue::discard_dead`]) or redriven ([`Queue::redrive`]).
    /// The key deduplicates enqueues only; execution is at least once.
    #[must_use]
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Due `delay` after it is enqueued, by the database's clock.
    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self.at = None;
        self
    }

    /// Due at `at`.
    #[must_use]
    pub fn run_at(mut self, at: SystemTime) -> Self {
        self.at = Some(at);
        self
    }

    /// Attempts for this job, instead of the queue's [`Retry::max_attempts`].
    #[must_use]
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }
}

/// What an enqueue did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enqueued {
    /// The job's id.
    pub id: i64,
    /// False when its idempotency key named a job already in the table, which this is.
    pub fresh: bool,
}

/// A job a worker holds.
#[derive(Clone)]
pub struct Claimed {
    /// The job's id.
    pub id: i64,
    /// Its idempotency key.
    pub key: Option<String>,
    /// Its payload.
    pub payload: Vec<u8>,
    /// This attempt (1 for the first).
    pub attempt: u32,
    /// The job's claim counter at this claim: the fencing token. It rises with every
    /// claim and never falls, so no two claims of a job share one.
    pub claim: i64,
    /// Its attempts in all.
    pub max_attempts: u32,
}

impl std::fmt::Debug for Claimed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claimed")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .field("attempt", &self.attempt)
            .field("claim", &self.claim)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl Claimed {
    /// The payload read as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.payload)
    }

    /// Whether this is the job's last attempt.
    #[must_use]
    pub fn is_last_attempt(&self) -> bool {
        self.attempt >= self.max_attempts
    }
}

/// A handler's failure. Any error converts into a retryable one with `?`;
/// [`JobError::permanent`] makes the job dead at once (a payload that will never
/// parse).
pub struct JobError {
    error: anyhow::Error,
    permanent: bool,
}

impl JobError {
    /// An error no retry can fix.
    pub fn permanent(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            permanent: true,
        }
    }

    /// Whether it is permanent.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        self.permanent
    }
}

impl<E: Into<anyhow::Error>> From<E> for JobError {
    fn from(error: E) -> Self {
        Self {
            error: error.into(),
            permanent: false,
        }
    }
}

impl std::fmt::Debug for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (permanent: {})", self.error, self.permanent)
    }
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

/// What [`Queue::fail`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// Queued again, due after this pause.
    Retrying(Duration),
    /// Dead: out of attempts, or a permanent error.
    Dead,
    /// The claim was no longer current (recovered as stale, and perhaps claimed again);
    /// nothing changed.
    Lost,
}

/// What [`Queue::recover_stale`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Stale claims queued again.
    pub requeued: u64,
    /// Stale claims that had had their attempts, now dead.
    pub dead: u64,
}

/// The jobs of a queue, by state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Waiting, due or not.
    pub queued: i64,
    /// Due now (part of `queued`).
    pub due: i64,
    /// Claimed.
    pub running: i64,
    /// Done and not yet purged.
    pub done: i64,
    /// Dead.
    pub dead: i64,
    /// How long the oldest due job has waited past its time.
    pub lag: Duration,
}

/// A dead job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadJob {
    /// Its id.
    pub id: i64,
    /// Its idempotency key.
    pub key: Option<String>,
    /// The attempts it had.
    pub attempts: u32,
    /// Its last error.
    pub last_error: Option<String>,
}

/// One named queue: a slice of `owt_jobs`. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Queue {
    pool: PgPool,
    name: Arc<str>,
    retry: Retry,
}

impl Queue {
    /// The queue `name`: 1 to 64 of ASCII lowercase letters, digits, `_`, `.` and `-`.
    pub fn new(pool: PgPool, name: &str) -> anyhow::Result<Self> {
        let ok = (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b));
        anyhow::ensure!(
            ok,
            "a queue name is 1 to 64 of a-z, 0-9, `_`, `.` and `-`: {name:?}"
        );
        Ok(Self {
            pool,
            name: name.into(),
            retry: Retry::default(),
        })
    }

    /// Retry failed jobs so (default [`Retry::default`]). `max_attempts` applies to
    /// jobs enqueued from now on; the backoff to every failure from now on.
    #[must_use]
    pub fn retry(mut self, retry: Retry) -> Self {
        self.retry = Retry {
            max_attempts: retry.max_attempts.max(1),
            ..retry
        };
        self
    }

    /// The queue's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enqueue `job` on its own.
    pub async fn enqueue(&self, job: Job) -> sqlx::Result<Enqueued> {
        let mut conn = self.pool.acquire().await?;
        self.enqueue_in(&mut conn, job).await
    }

    /// Enqueue `job` on `conn`: inside a transaction (`&mut *tx`), it exists exactly
    /// when the transaction commits.
    ///
    /// A keyed job needs the connection's transaction to be `READ COMMITTED`, the
    /// default: the enqueue finds a key that a concurrent transaction committed only
    /// with a snapshot per statement. Under `REPEATABLE READ` or `SERIALIZABLE` such a
    /// collision is an error, so a keyed enqueue there returns an error saying so
    /// (checked with `current_setting('transaction_isolation')`) rather than risk it.
    /// A job without a key has no collision and enqueues under any level.
    ///
    /// A key held by a dead job returns the dead job with `fresh: false`, until it is
    /// discarded or redriven.
    pub async fn enqueue_in(&self, conn: &mut PgConnection, job: Job) -> sqlx::Result<Enqueued> {
        let max = job.max_attempts.unwrap_or(self.retry.max_attempts).max(1);
        let at = job.at.map(epoch_seconds);
        if job.key.is_some() {
            let level: String =
                sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
                    .fetch_one(&mut *conn)
                    .await?;
            if level != "read committed" {
                return Err(sqlx::Error::Protocol(format!(
                    "enqueue_in with an idempotency key needs a READ COMMITTED transaction, \
                     not {}",
                    level.to_uppercase()
                )));
            }
        }
        // A key held by a transaction that commits while this statement waits on it is
        // not in this statement's snapshot: under READ COMMITTED the next statement
        // sees it.
        for _ in 0..3 {
            let row: Option<(i64, bool)> = sqlx::query_as(
                "WITH ins AS (
                     INSERT INTO owt_jobs (queue, idempotency_key, payload, max_attempts, run_at)
                     VALUES ($1, $2, $3, $4,
                             COALESCE(to_timestamp($5), now() + make_interval(secs => $6)))
                     ON CONFLICT (queue, idempotency_key) WHERE idempotency_key IS NOT NULL
                     DO NOTHING
                     RETURNING id)
                 SELECT id, true FROM ins
                 UNION ALL
                 SELECT id, false FROM owt_jobs
                 WHERE queue = $1 AND idempotency_key = $2 AND NOT EXISTS (SELECT 1 FROM ins)",
            )
            .bind(&*self.name)
            .bind(job.key.as_deref())
            .bind(&job.payload)
            .bind(to_i32(max))
            .bind(at)
            .bind(job.delay.as_secs_f64())
            .fetch_optional(&mut *conn)
            .await?;
            if let Some((id, fresh)) = row {
                return Ok(Enqueued { id, fresh });
            }
        }
        Err(sqlx::Error::Protocol(
            "the job's idempotency key conflicted with a row that stayed invisible".into(),
        ))
    }

    /// Claim up to `n` due jobs, oldest first, skipping any another claim holds.
    pub async fn claim(&self, n: u32) -> sqlx::Result<Vec<Claimed>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let rows: Vec<ClaimRow> = sqlx::query_as(
            "WITH picked AS MATERIALIZED (
                 SELECT id FROM owt_jobs
                 WHERE queue = $1 AND state = 'queued' AND run_at <= now()
                 ORDER BY run_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $2)
             UPDATE owt_jobs j SET state = 'running', attempts = j.attempts + 1,
                    claim = j.claim + 1, claimed_at = now(), heartbeat_at = now()
             FROM picked WHERE j.id = picked.id
             RETURNING j.id, j.idempotency_key, j.payload, j.attempts, j.max_attempts, j.claim",
        )
        .bind(&*self.name)
        .bind(i64::from(n))
        .fetch_all(&self.pool)
        .await?;
        let mut claimed: Vec<Claimed> = rows
            .into_iter()
            .map(|(id, key, payload, attempt, max, claim)| Claimed {
                id,
                key,
                payload,
                attempt: to_u32(attempt),
                claim,
                max_attempts: to_u32(max),
            })
            .collect();
        claimed.sort_by_key(|c| c.id);
        Ok(claimed)
    }

    /// Mark a claimed job done, emptying its payload. False when the claim was no
    /// longer current.
    pub async fn complete(&self, job: &Claimed) -> sqlx::Result<bool> {
        let done = sqlx::query(
            "UPDATE owt_jobs SET state = 'done', payload = ''::bytea, finished_at = now(),
                    claimed_at = NULL, heartbeat_at = NULL, last_error = NULL
             WHERE id = $1 AND state = 'running' AND claim = $2",
        )
        .bind(job.id)
        .bind(job.claim)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Record a claimed job's failed attempt: queued again after the backoff, or dead
    /// when it was the last attempt or `error` is permanent.
    pub async fn fail(&self, job: &Claimed, error: &JobError) -> sqlx::Result<Failed> {
        let pause = self.retry.backoff(job.attempt);
        let state: Option<String> = sqlx::query_scalar(
            "UPDATE owt_jobs SET
                 state = CASE WHEN $3 OR attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
                 finished_at = CASE WHEN $3 OR attempts >= max_attempts THEN now() END,
                 run_at = now() + make_interval(secs => $4),
                 last_error = $5, claimed_at = NULL, heartbeat_at = NULL
             WHERE id = $1 AND state = 'running' AND claim = $2
             RETURNING state",
        )
        .bind(job.id)
        .bind(job.claim)
        .bind(error.permanent)
        .bind(pause.as_secs_f64())
        .bind(cut(&error.to_string()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(match state.as_deref() {
            None => Failed::Lost,
            Some("dead") => Failed::Dead,
            Some(_) => Failed::Retrying(pause),
        })
    }

    /// Put a claimed job back in the queue, due now (a worker shutting down), or make
    /// it dead when this was its last attempt. The attempt stays counted, so a
    /// handler that never returns still runs out of attempts, and a job never runs
    /// more than its attempts. False when the claim was no longer current.
    pub async fn release(&self, job: &Claimed) -> sqlx::Result<bool> {
        Ok(release(&self.pool, job.id, job.claim).await?.is_some())
    }

    /// Renew the heartbeat of each claimed job, as `(id, claim)`, that is still running
    /// under that claim. How many were.
    pub async fn heartbeat(&self, held: &[(i64, i64)]) -> sqlx::Result<u64> {
        if held.is_empty() {
            return Ok(0);
        }
        let (ids, claims): (Vec<i64>, Vec<i64>) = held.iter().copied().unzip();
        let done = sqlx::query(
            "UPDATE owt_jobs j SET heartbeat_at = now()
             FROM unnest($1::int8[], $2::int8[]) AS h(id, claim)
             WHERE j.id = h.id AND j.claim = h.claim AND j.state = 'running'",
        )
        .bind(ids)
        .bind(claims)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Recover running jobs whose heartbeat is older than `stale_after`: queued again,
    /// due now, or dead when they have had their attempts.
    pub async fn recover_stale(&self, stale_after: Duration) -> sqlx::Result<Recovered> {
        let states: Vec<String> = sqlx::query_scalar(
            "UPDATE owt_jobs SET
                 state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
                 finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
                 run_at = now(), claimed_at = NULL, heartbeat_at = NULL,
                 last_error = 'the claim went stale: its worker stopped without finishing'
             WHERE queue = $1 AND state = 'running'
                   AND heartbeat_at < now() - make_interval(secs => $2)
             RETURNING state",
        )
        .bind(&*self.name)
        .bind(stale_after.as_secs_f64())
        .fetch_all(&self.pool)
        .await?;
        let dead = states.iter().filter(|s| *s == "dead").count() as u64;
        Ok(Recovered {
            requeued: states.len() as u64 - dead,
            dead,
        })
    }

    /// Up to `limit` dead jobs, the latest first.
    pub async fn dead(&self, limit: u32) -> sqlx::Result<Vec<DeadJob>> {
        let rows: Vec<(i64, Option<String>, i32, Option<String>)> = sqlx::query_as(
            "SELECT id, idempotency_key, attempts, last_error FROM owt_jobs
             WHERE queue = $1 AND state = 'dead'
             ORDER BY finished_at DESC, id DESC LIMIT $2",
        )
        .bind(&*self.name)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, key, attempts, last_error)| DeadJob {
                id,
                key,
                attempts: to_u32(attempts),
                last_error,
            })
            .collect())
    }

    /// Queue a dead job of this queue again, due now, with its attempts reset. False
    /// when there is no such dead job.
    pub async fn redrive(&self, id: i64) -> sqlx::Result<bool> {
        let done = sqlx::query(
            "UPDATE owt_jobs SET state = 'queued', attempts = 0, run_at = now(),
                    finished_at = NULL
             WHERE id = $1 AND queue = $2 AND state = 'dead'",
        )
        .bind(id)
        .bind(&*self.name)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Delete this queue's dead jobs, or one of them by id. How many went.
    pub async fn discard_dead(&self, id: Option<i64>) -> sqlx::Result<u64> {
        let done = sqlx::query(
            "DELETE FROM owt_jobs WHERE queue = $1 AND state = 'dead'
                                    AND ($2::int8 IS NULL OR id = $2)",
        )
        .bind(&*self.name)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Delete done jobs that finished more than `older_than` ago, freeing their
    /// idempotency keys, [`PURGE_BATCH`] rows per statement so no delete holds locks
    /// for long. How many went.
    pub async fn purge_done(&self, older_than: Duration) -> sqlx::Result<u64> {
        let mut total = 0;
        loop {
            let done = sqlx::query(
                "DELETE FROM owt_jobs WHERE id IN (
                     SELECT id FROM owt_jobs
                     WHERE queue = $1 AND state = 'done'
                           AND finished_at < now() - make_interval(secs => $2)
                     LIMIT $3)",
            )
            .bind(&*self.name)
            .bind(older_than.as_secs_f64())
            .bind(PURGE_BATCH)
            .execute(&self.pool)
            .await?
            .rows_affected();
            total += done;
            if done < PURGE_BATCH.unsigned_abs() {
                return Ok(total);
            }
        }
    }

    /// The queue's jobs by state. Each count is its own subquery whose predicate matches a
    /// partial index (`owt_jobs_due`, `owt_jobs_running`, `owt_jobs_finished`), so none
    /// reads a row of another state; `done` reads the done rows, which [`Queue::purge_done`]
    /// bounds. The housekeeping tick uses [`Queue::depth`] instead, which skips them.
    pub async fn counts(&self) -> sqlx::Result<Counts> {
        self.count_states(true).await
    }

    /// [`Queue::counts`] with `done` left at zero: the per-tick gauges never read it.
    #[cfg(feature = "metrics")]
    async fn depth(&self) -> sqlx::Result<Counts> {
        self.count_states(false).await
    }

    async fn count_states(&self, with_done: bool) -> sqlx::Result<Counts> {
        let (queued, due, running, done, dead, lag): (i64, i64, i64, i64, i64, f64) =
            sqlx::query_as(
                "SELECT (SELECT count(*) FROM owt_jobs WHERE queue = $1 AND state = 'queued'),
                        (SELECT count(*) FROM owt_jobs
                          WHERE queue = $1 AND state = 'queued' AND run_at <= now()),
                        (SELECT count(*) FROM owt_jobs WHERE queue = $1 AND state = 'running'),
                        CASE WHEN $2 THEN (SELECT count(*) FROM owt_jobs
                                            WHERE queue = $1 AND state = 'done') ELSE 0 END,
                        (SELECT count(*) FROM owt_jobs WHERE queue = $1 AND state = 'dead'),
                        COALESCE((SELECT extract(epoch FROM now() - run_at) FROM owt_jobs
                                   WHERE queue = $1 AND state = 'queued' AND run_at <= now()
                                   ORDER BY run_at, id LIMIT 1), 0)::float8",
            )
            .bind(&*self.name)
            .bind(with_done)
            .fetch_one(&self.pool)
            .await?;
        Ok(Counts {
            queued,
            due,
            running,
            done,
            dead,
            lag: Duration::try_from_secs_f64(lag).unwrap_or_default(),
        })
    }

    /// A worker that runs `handler` for each job of this queue. Start it with
    /// [`Worker::spawn`].
    pub fn worker<F, Fut>(&self, handler: F) -> Worker
    where
        F: Fn(Claimed) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), JobError>> + Send + 'static,
    {
        Worker {
            queue: self.clone(),
            handler: Arc::new(move |job| Box::pin(handler(job))),
            concurrency: 4,
            poll: Duration::from_secs(5),
            stale_after: Duration::from_mins(5),
            grace: Duration::from_secs(30),
            retain_done: Some(Duration::from_hours(24 * 7)),
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }
}

/// The state the job is left in (`queued`, or `dead` on its last attempt); `None` when
/// the claim was no longer current.
async fn release(pool: &PgPool, id: i64, claim: i64) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar(
        "UPDATE owt_jobs SET
                state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
                finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
                last_error = CASE WHEN attempts >= max_attempts
                                  THEN 'stopped at shutdown on its last attempt'
                                  ELSE last_error END,
                run_at = now(), claimed_at = NULL, heartbeat_at = NULL
         WHERE id = $1 AND state = 'running' AND claim = $2
         RETURNING state",
    )
    .bind(id)
    .bind(claim)
    .fetch_optional(pool)
    .await
}

/// A claimed row: id, key, payload, attempt, max attempts, claim.
type ClaimRow = (i64, Option<String>, Vec<u8>, i32, i32, i64);

type Handler = Arc<
    dyn Fn(Claimed) -> Pin<Box<dyn Future<Output = Result<(), JobError>> + Send>> + Send + Sync,
>;

/// Where a queue's worker records what it does.
#[cfg(feature = "metrics")]
#[derive(Clone, Debug)]
pub struct QueueMetrics {
    jobs: String,
    seconds: String,
    depth: String,
    lag: String,
}

#[cfg(feature = "metrics")]
impl QueueMetrics {
    /// `<prefix>_queue_jobs_total{queue,outcome}`, `<prefix>_queue_job_seconds{queue}`,
    /// `<prefix>_queue_depth{queue,state}` and `<prefix>_queue_lag_seconds{queue}`.
    #[must_use]
    pub fn prefixed(prefix: &str) -> Self {
        Self {
            jobs: format!("{prefix}_queue_jobs_total"),
            seconds: format!("{prefix}_queue_job_seconds"),
            depth: format!("{prefix}_queue_depth"),
            lag: format!("{prefix}_queue_lag_seconds"),
        }
    }

    /// Describe the metrics to the recorder.
    pub fn describe(&self) {
        metrics::describe_counter!(
            self.jobs.clone(),
            "Queued job attempts and recoveries, by `queue` and `outcome` (done, retried, \
             dead, lost, released, recovered)."
        );
        metrics::describe_histogram!(
            self.seconds.clone(),
            metrics::Unit::Seconds,
            "Time a queued job's attempt took, by `queue`."
        );
        metrics::describe_gauge!(
            self.depth.clone(),
            "Jobs in a queue, by `queue` and `state` (due, queued, running, dead)."
        );
        metrics::describe_gauge!(
            self.lag.clone(),
            metrics::Unit::Seconds,
            "How long a queue's oldest due job has waited past its time, by `queue`."
        );
    }
}

/// A queue's worker on this replica: see the [module docs](self).
pub struct Worker {
    queue: Queue,
    handler: Handler,
    concurrency: u32,
    poll: Duration,
    stale_after: Duration,
    grace: Duration,
    retain_done: Option<Duration>,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<QueueMetrics>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("queue", &self.queue.name)
            .field("concurrency", &self.concurrency)
            .field("poll", &self.poll)
            .field("stale_after", &self.stale_after)
            .field("grace", &self.grace)
            .field("retain_done", &self.retain_done)
            .finish_non_exhaustive()
    }
}

impl Worker {
    /// Jobs run at once on this replica (default 4, at least 1).
    #[must_use]
    pub fn concurrency(mut self, n: u32) -> Self {
        self.concurrency = n.max(1);
        self
    }

    /// How long the worker waits before claiming again after finding nothing due
    /// (default 5 s, at least 10 ms). A claim that fills every slot claims again at
    /// once. The worker polls and is not notified, so a job that becomes due may wait
    /// up to this long before it starts; a queue that needs a shorter start sets a
    /// shorter interval at the cost of one claim query per interval per replica.
    #[must_use]
    pub fn poll(mut self, every: Duration) -> Self {
        self.poll = every.max(Duration::from_millis(10));
        self
    }

    /// How old a running job's heartbeat gets before any replica's worker puts it
    /// back (default 5 minutes, at least 3 s). The heartbeat is renewed every third of
    /// it, so a long job keeps its claim; a replica that dies leaves its jobs for this
    /// long.
    #[must_use]
    pub fn stale_after(mut self, after: Duration) -> Self {
        self.stale_after = after.max(Duration::from_secs(3));
        self
    }

    /// How long running jobs get to finish at shutdown (default 30 s) before they are
    /// aborted and put back in the queue. An aborted attempt stays counted, so a handler
    /// that never returns reaches its last attempt over a few deploys and the job goes
    /// dead. Aborting stops the handler at its next await point only: work it detached
    /// keeps running, which is one more reason handlers are idempotent.
    #[must_use]
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// How long done jobs, and so their idempotency keys, are kept (default 7 days);
    /// `None` keeps them until the app deletes them.
    #[must_use]
    pub fn retain_done(mut self, retain: Option<Duration>) -> Self {
        self.retain_done = retain;
        self
    }

    /// Record under these names.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn metrics(mut self, metrics: QueueMetrics) -> Self {
        self.metrics = Some(Arc::new(metrics));
        self
    }

    /// Run the worker as one of `jobs`: it stops when their shutdown token is
    /// cancelled, and [`Jobs::stopped`] waits for it.
    pub fn spawn(self, jobs: &Jobs) {
        let shutdown = jobs.shutdown().clone();
        jobs.spawn(self.run(shutdown));
    }

    /// Run the worker in this task until `shutdown` is cancelled and its jobs have
    /// finished or been put back.
    pub async fn run(self, shutdown: CancellationToken) {
        let this = Arc::new(self);
        let held = Held::default();
        // Heartbeats and housekeeping each get a task, so a slow claim or purge never
        // delays a heartbeat. Housekeeping stops at shutdown; heartbeats go on through
        // the drain. The guard stops both tasks if this future is dropped.
        let stop = CancellationToken::new();
        let _guard = stop.clone().drop_guard();
        let heartbeats = tokio::spawn(this.clone().heartbeat_loop(held.clone(), stop.clone()));
        let housekeeping = tokio::spawn(
            this.clone()
                .housekeeping_loop(shutdown.clone(), stop.clone()),
        );
        let mut running = Running::new(held);
        let mut next_claim = tokio::time::Instant::now();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                Some(joined) = running.set.join_next_with_id(), if !running.set.is_empty() => {
                    this.joined(&mut running, joined).await;
                }
                () = tokio::time::sleep_until(next_claim) => {
                    let free = this.concurrency.saturating_sub(running.len());
                    let full = free > 0 && this.claim(&mut running, free).await == free;
                    next_claim = tokio::time::Instant::now()
                        + if full { Duration::ZERO } else { this.poll };
                }
            }
            // A slot came free after a claim that filled every slot: there is likely
            // more due, so claim now rather than at the next poll.
            if running.len() < this.concurrency && running.backlog {
                next_claim = tokio::time::Instant::now();
                running.backlog = false;
            }
        }
        this.drain(running).await;
        stop.cancel();
        let _ = tokio::join!(heartbeats, housekeeping);
    }

    /// Claim up to `free` jobs and start them; how many it claimed.
    async fn claim(&self, running: &mut Running, free: u32) -> u32 {
        let claimed = match self.queue.claim(free).await {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!(queue = %self.queue.name, %error, "claiming jobs failed");
                return 0;
            }
        };
        let n = u32::try_from(claimed.len()).unwrap_or(u32::MAX);
        running.backlog = n == free;
        for job in claimed {
            let queue = self.queue.clone();
            let handler = self.handler.clone();
            let held = (job.id, job.claim, job.attempt);
            #[cfg(feature = "metrics")]
            let metrics = self.metrics.clone();
            let handle = running.set.spawn(async move {
                let started = Instant::now();
                let result = handler(job.clone()).await;
                let outcome = finish(&queue, &job, result).await;
                #[cfg(feature = "metrics")]
                if let Some(m) = &metrics {
                    record(m, &queue.name, outcome, Some(started.elapsed()));
                }
                #[cfg(not(feature = "metrics"))]
                let _ = (outcome, started);
            });
            running.held.lock().insert(handle.id(), held);
        }
        n
    }

    /// A job's task ended: a panic is a failed attempt.
    async fn joined(
        &self,
        running: &mut Running,
        joined: Result<(Id, ()), tokio::task::JoinError>,
    ) {
        let (id, panic) = match joined {
            Ok((id, ())) => (id, None),
            Err(e) => (e.id(), e.is_panic().then_some(e)),
        };
        let Some((job_id, claim, attempt)) = running.held.lock().remove(&id) else {
            return;
        };
        if panic.is_some() {
            let job = Claimed {
                id: job_id,
                key: None,
                payload: Vec::new(),
                attempt,
                claim,
                max_attempts: attempt,
            };
            let error = JobError::from(anyhow::anyhow!("the handler panicked"));
            let outcome = match self.queue.fail(&job, &error).await {
                Ok(f) => outcome_of(f),
                Err(e) => {
                    tracing::warn!(queue = %self.queue.name, job = job_id, error = %e, "recording a panicked job failed");
                    "lost"
                }
            };
            tracing::error!(queue = %self.queue.name, job = job_id, attempt, outcome, "a job's handler panicked");
            self.record(outcome, None);
        }
    }

    /// Renew the held jobs' heartbeats every third of `stale_after` until `stop`.
    async fn heartbeat_loop(self: Arc<Self>, held: Held, stop: CancellationToken) {
        let mut tick = tokio::time::interval(self.stale_after / 3);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                _ = tick.tick() => {}
            }
            let beats: Vec<(i64, i64)> = held
                .lock()
                .values()
                .map(|&(id, claim, _)| (id, claim))
                .collect();
            if let Err(error) = self.queue.heartbeat(&beats).await {
                tracing::warn!(queue = %self.queue.name, %error, "renewing job heartbeats failed");
            }
        }
    }

    /// Housekeeping passes until `shutdown` or `stop`.
    async fn housekeeping_loop(
        self: Arc<Self>,
        shutdown: CancellationToken,
        stop: CancellationToken,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(30).min(self.stale_after / 2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = stop.cancelled() => return,
                _ = tick.tick() => {}
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = stop.cancelled() => return,
                () = self.housekeep() => {}
            }
        }
    }

    async fn housekeep(&self) {
        let name = &self.queue.name;
        match self.queue.recover_stale(self.stale_after).await {
            Ok(r) if r.requeued + r.dead > 0 => {
                tracing::warn!(queue = %name, requeued = r.requeued, dead = r.dead, "recovered stale job claims");
                for _ in 0..r.requeued {
                    self.record("recovered", None);
                }
                for _ in 0..r.dead {
                    self.record("dead", None);
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(queue = %name, %error, "recovering stale job claims failed");
            }
        }
        if let Some(retain) = self.retain_done
            && let Err(error) = self.queue.purge_done(retain).await
        {
            tracing::warn!(queue = %name, %error, "purging done jobs failed");
        }
        #[cfg(feature = "metrics")]
        if let Some(m) = &self.metrics {
            match self.queue.depth().await {
                Ok(c) => {
                    let name = name.to_string();
                    for (state, n) in [
                        ("due", c.due),
                        ("queued", c.queued),
                        ("running", c.running),
                        ("dead", c.dead),
                    ] {
                        #[expect(clippy::cast_precision_loss, reason = "a gauge")]
                        metrics::gauge!(m.depth.clone(), "queue" => name.clone(), "state" => state)
                            .set(n as f64);
                    }
                    metrics::gauge!(m.lag.clone(), "queue" => name).set(c.lag.as_secs_f64());
                }
                Err(error) => tracing::warn!(queue = %name, %error, "counting jobs failed"),
            }
        }
    }

    /// Shutdown: let running jobs finish within the grace period, then abort the rest
    /// and put back those the abort cancelled. The heartbeat task keeps the held jobs
    /// alive meanwhile.
    async fn drain(&self, mut running: Running) {
        let deadline = tokio::time::Instant::now() + self.grace;
        while !running.set.is_empty() {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => break,
                Some(joined) = running.set.join_next_with_id() => {
                    self.joined(&mut running, joined).await;
                }
            }
        }
        running.set.abort_all();
        while let Some(joined) = running.set.join_next_with_id().await {
            // A task that finished in this window recorded itself, and one that
            // panicked is recorded as failed; only a cancelled one stays held.
            if matches!(&joined, Err(e) if e.is_cancelled()) {
                continue;
            }
            self.joined(&mut running, joined).await;
        }
        let cancelled: Vec<(i64, i64, u32)> = running.held.lock().drain().map(|(_, h)| h).collect();
        for (id, claim, _) in cancelled {
            match release(&self.queue.pool, id, claim).await {
                Ok(Some(state)) => {
                    self.record(if state == "dead" { "dead" } else { "released" }, None);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(queue = %self.queue.name, job = id, %error, "putting a job back failed; it is recovered once stale");
                }
            }
        }
    }

    #[cfg_attr(
        not(feature = "metrics"),
        expect(clippy::unused_self, reason = "records only with metrics")
    )]
    fn record(&self, outcome: &'static str, took: Option<Duration>) {
        #[cfg(feature = "metrics")]
        if let Some(m) = &self.metrics {
            record(m, &self.queue.name, outcome, took);
        }
        #[cfg(not(feature = "metrics"))]
        let _ = (outcome, took);
    }
}

/// The jobs a worker's tasks hold, as `(id, claim, attempt)` by task, shared with the
/// heartbeat task.
#[derive(Clone, Default)]
struct Held(Arc<Mutex<HashMap<Id, Hold>>>);

/// One held job: `(id, claim, attempt)`.
type Hold = (i64, i64, u32);

impl Held {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Id, Hold>> {
        // The map holds plain values, so a panic while it was locked left it intact.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct Running {
    set: JoinSet<()>,
    held: Held,
    /// The last claim filled every free slot.
    backlog: bool,
}

impl Running {
    fn new(held: Held) -> Self {
        Self {
            set: JoinSet::new(),
            held,
            backlog: false,
        }
    }

    fn len(&self) -> u32 {
        u32::try_from(self.set.len()).unwrap_or(u32::MAX)
    }
}

/// Record a handler's result; the metric outcome.
async fn finish(queue: &Queue, job: &Claimed, result: Result<(), JobError>) -> &'static str {
    let name = &queue.name;
    let recorded = match &result {
        Ok(()) => queue
            .complete(job)
            .await
            .map(|held| if held { "done" } else { "lost" }),
        Err(error) => queue.fail(job, error).await.map(outcome_of),
    };
    match (recorded, result) {
        (Ok("lost"), _) => {
            tracing::warn!(queue = %name, job = job.id, attempt = job.attempt, "a job's claim was lost before it finished");
            "lost"
        }
        (Ok(outcome), Err(error)) => {
            tracing::warn!(queue = %name, job = job.id, attempt = job.attempt, outcome, error = %error, "a job failed");
            outcome
        }
        (Ok(outcome), Ok(())) => outcome,
        (Err(error), _) => {
            tracing::warn!(queue = %name, job = job.id, %error, "recording a job's result failed; it is recovered once stale");
            "lost"
        }
    }
}

fn outcome_of(failed: Failed) -> &'static str {
    match failed {
        Failed::Retrying(_) => "retried",
        Failed::Dead => "dead",
        Failed::Lost => "lost",
    }
}

#[cfg(feature = "metrics")]
fn record(m: &QueueMetrics, queue: &str, outcome: &'static str, took: Option<Duration>) {
    let queue = queue.to_string();
    metrics::counter!(m.jobs.clone(), "queue" => queue.clone(), "outcome" => outcome).increment(1);
    if let Some(t) = took {
        metrics::histogram!(m.seconds.clone(), "queue" => queue).record(t.as_secs_f64());
    }
}

fn epoch_seconds(at: SystemTime) -> f64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

fn cut(error: &str) -> &str {
    match error.char_indices().nth(MAX_ERROR_CHARS) {
        Some((i, _)) => &error[..i],
        None => error,
    }
}

fn to_i32(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

fn to_u32(n: i32) -> u32 {
    u32::try_from(n).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_within_its_upper_half_up_to_the_cap() {
        let r = Retry {
            max_attempts: 10,
            base: Duration::from_secs(10),
            cap: Duration::from_secs(60),
        };
        for _ in 0..100 {
            let first = r.backoff(1);
            assert!((Duration::from_secs(5)..=Duration::from_secs(10)).contains(&first));
            let third = r.backoff(3);
            assert!((Duration::from_secs(20)..=Duration::from_secs(40)).contains(&third));
            let late = r.backoff(40);
            assert!((Duration::from_secs(30)..=Duration::from_secs(60)).contains(&late));
        }
        assert_eq!(
            Retry {
                base: Duration::ZERO,
                ..r
            }
            .backoff(3),
            Duration::ZERO
        );
    }

    #[test]
    fn errors_are_cut_at_a_character() {
        let long = "é".repeat(MAX_ERROR_CHARS + 5);
        assert_eq!(cut(&long).chars().count(), MAX_ERROR_CHARS);
        assert_eq!(cut("short"), "short");
    }

    #[tokio::test]
    async fn names_are_checked() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/x").unwrap();
        for ok in ["emails", "a", "media.transcode-2_x"] {
            assert!(Queue::new(pool.clone(), ok).is_ok(), "{ok}");
        }
        for bad in ["", "Emails", "a b", "a:b", &"x".repeat(65)] {
            assert!(Queue::new(pool.clone(), bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_hides_payloads() {
        let job = Job::bytes(b"secret".to_vec()).key("k");
        assert!(!format!("{job:?}").contains("secret"));
        let c = Claimed {
            id: 1,
            key: None,
            payload: b"secret".to_vec(),
            attempt: 1,
            claim: 1,
            max_attempts: 1,
        };
        assert!(!format!("{c:?}").contains("secret"));
    }
}
