//! `owt_runtime::queue` against a real Postgres (`DATABASE_URL`); skipped when it is
//! unset. Each test takes a schema of its own and drops it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use owt_runtime::jobs::{CancellationToken, Jobs};
use owt_runtime::queue::{self, Failed, Job, JobError, Queue, Retry};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

struct Db {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl Db {
    async fn new() -> Option<Self> {
        let url = owt_runtime::env::var("DATABASE_URL")?;
        let schema = format!("owt_queue_{}_{}", std::process::id(), rand::random::<u32>());
        let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let opts: PgConnectOptions = url.parse().unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(opts.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        queue::migrate(&pool).await.unwrap();
        // Twice is a no-op.
        queue::migrate(&pool).await.unwrap();
        Some(Self {
            pool,
            admin,
            schema,
        })
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }

    async fn state(&self, id: i64) -> (String, i32, Vec<u8>, Option<String>) {
        sqlx::query_as("SELECT state, attempts, payload, last_error FROM owt_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn quick() -> Retry {
    Retry {
        max_attempts: 3,
        base: Duration::ZERO,
        cap: Duration::ZERO,
    }
}

#[tokio::test]
async fn a_job_is_claimed_once_and_done_empties_its_payload() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    let other = Queue::new(db.pool.clone(), "other").unwrap();
    let e = q
        .enqueue(Job::json(&serde_json::json!({"to": 7})).unwrap())
        .await
        .unwrap();
    assert!(e.fresh);
    assert!(
        other.claim(10).await.unwrap().is_empty(),
        "queues are apart"
    );
    let claimed = q.claim(10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, e.id);
    assert_eq!(claimed[0].attempt, 1);
    assert_eq!(claimed[0].json::<serde_json::Value>().unwrap()["to"], 7);
    assert!(
        q.claim(10).await.unwrap().is_empty(),
        "a running job is not claimed"
    );
    assert!(q.complete(&claimed[0]).await.unwrap());
    assert!(!q.complete(&claimed[0]).await.unwrap(), "done once");
    let (state, attempts, payload, _) = db.state(e.id).await;
    assert_eq!((state.as_str(), attempts, payload.len()), ("done", 1, 0));
    db.drop().await;
}

#[tokio::test]
async fn an_idempotency_key_enqueues_once() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    let a = q
        .enqueue(Job::bytes(b"a".to_vec()).key("k1"))
        .await
        .unwrap();
    let b = q
        .enqueue(Job::bytes(b"b".to_vec()).key("k1"))
        .await
        .unwrap();
    assert!(a.fresh && !b.fresh);
    assert_eq!(a.id, b.id);
    // Another queue's key is its own.
    let other = Queue::new(db.pool.clone(), "other").unwrap();
    assert!(
        other
            .enqueue(Job::bytes(b"c".to_vec()).key("k1"))
            .await
            .unwrap()
            .fresh
    );
    // Concurrent enqueues of one key agree on one job.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let q = q.clone();
        set.spawn(async move {
            q.enqueue(Job::bytes(b"x".to_vec()).key("k2"))
                .await
                .unwrap()
        });
    }
    let all = set.join_all().await;
    assert_eq!(all.iter().filter(|e| e.fresh).count(), 1);
    assert!(all.iter().all(|e| e.id == all[0].id));
    // Done and purged, the key is free again.
    let c = q.claim(10).await.unwrap();
    for job in &c {
        q.complete(job).await.unwrap();
    }
    assert_eq!(q.purge_done(Duration::ZERO).await.unwrap(), 2);
    assert!(
        q.enqueue(Job::bytes(b"a".to_vec()).key("k1"))
            .await
            .unwrap()
            .fresh
    );
    db.drop().await;
}

#[tokio::test]
async fn a_job_enqueued_in_a_rolled_back_transaction_does_not_exist() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    let mut tx = db.pool.begin().await.unwrap();
    q.enqueue_in(&mut tx, Job::bytes(vec![1])).await.unwrap();
    tx.rollback().await.unwrap();
    let mut tx = db.pool.begin().await.unwrap();
    let kept = q.enqueue_in(&mut tx, Job::bytes(vec![2])).await.unwrap();
    tx.commit().await.unwrap();
    let claimed = q.claim(10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, kept.id);
    db.drop().await;
}

#[tokio::test]
async fn claims_skip_each_other_and_wait_for_their_time() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    for i in 0..20_u8 {
        q.enqueue(Job::bytes(vec![i])).await.unwrap();
    }
    q.enqueue(Job::bytes(vec![99]).delay(Duration::from_hours(1)))
        .await
        .unwrap();
    q.enqueue(Job::bytes(vec![98]).run_at(std::time::SystemTime::now() + Duration::from_hours(1)))
        .await
        .unwrap();
    let (a, b) = tokio::join!(q.claim(15), q.claim(15));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.len() + b.len(), 20, "the delayed jobs wait");
    let mut ids: Vec<i64> = a.iter().chain(&b).map(|c| c.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 20, "no job claimed twice");
    let c = q.counts().await.unwrap();
    assert_eq!((c.queued, c.due, c.running), (2, 0, 20));
    db.drop().await;
}

#[tokio::test]
async fn failures_retry_then_die_and_can_be_redriven() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap().retry(quick());
    let e = q.enqueue(Job::bytes(b"p".to_vec())).await.unwrap();
    for attempt in 1..=3 {
        let c = q.claim(1).await.unwrap().pop().expect("due again");
        assert_eq!(c.attempt, attempt);
        assert_eq!(c.is_last_attempt(), attempt == 3);
        let f = q
            .fail(&c, &JobError::from(anyhow::anyhow!("boom {attempt}")))
            .await
            .unwrap();
        assert_eq!(
            f,
            if attempt < 3 {
                Failed::Retrying(Duration::ZERO)
            } else {
                Failed::Dead
            }
        );
    }
    let (state, _, payload, error) = db.state(e.id).await;
    assert_eq!(state, "dead");
    assert_eq!(payload, b"p", "a dead job keeps its payload");
    assert_eq!(error.as_deref(), Some("boom 3"));
    let dead = q.dead(10).await.unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!((dead[0].id, dead[0].attempts), (e.id, 3));
    assert!(q.redrive(e.id).await.unwrap());
    assert!(!q.redrive(e.id).await.unwrap());
    let c = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!(c.attempt, 1);

    // A permanent error dies at once; a job's own attempts beat the queue's.
    assert_eq!(
        q.fail(&c, &JobError::permanent(anyhow::anyhow!("bad payload")))
            .await
            .unwrap(),
        Failed::Dead
    );
    let one = q.enqueue(Job::bytes(vec![]).max_attempts(1)).await.unwrap();
    let c = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!(c.id, one.id);
    assert_eq!(
        q.fail(&c, &anyhow::anyhow!("x").into()).await.unwrap(),
        Failed::Dead
    );
    assert_eq!(q.discard_dead(Some(one.id)).await.unwrap(), 1);
    assert_eq!(q.discard_dead(None).await.unwrap(), 1);
    db.drop().await;
}

#[tokio::test]
async fn a_retry_waits_out_its_backoff() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap().retry(Retry {
        max_attempts: 3,
        base: Duration::from_hours(1),
        cap: Duration::from_hours(1),
    });
    q.enqueue(Job::bytes(vec![])).await.unwrap();
    let c = q.claim(1).await.unwrap().pop().unwrap();
    let Failed::Retrying(pause) = q.fail(&c, &anyhow::anyhow!("x").into()).await.unwrap() else {
        panic!("retries");
    };
    assert!(pause >= Duration::from_mins(30));
    assert!(q.claim(1).await.unwrap().is_empty());
    db.drop().await;
}

#[tokio::test]
async fn a_stale_claim_is_recovered_and_its_old_attempt_is_fenced() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap().retry(Retry {
        max_attempts: 2,
        ..quick()
    });
    let e = q.enqueue(Job::bytes(vec![])).await.unwrap();
    let first = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!(q.heartbeat(&[(first.id, first.claim)]).await.unwrap(), 1);
    assert_eq!(
        q.recover_stale(Duration::from_hours(1))
            .await
            .unwrap()
            .requeued,
        0
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    let r = q.recover_stale(Duration::from_millis(1)).await.unwrap();
    assert_eq!((r.requeued, r.dead), (1, 0));
    let second = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!(second.attempt, 2);
    // The first claim's worker comes back: it holds nothing.
    assert!(!q.complete(&first).await.unwrap());
    assert_eq!(
        q.fail(&first, &anyhow::anyhow!("x").into()).await.unwrap(),
        Failed::Lost
    );
    assert!(!q.release(&first).await.unwrap());
    assert_eq!(q.heartbeat(&[(first.id, first.claim)]).await.unwrap(), 0);
    // Out of attempts, a stale claim is dead.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let r = q.recover_stale(Duration::from_millis(1)).await.unwrap();
    assert_eq!((r.requeued, r.dead), (0, 1));
    assert_eq!(db.state(e.id).await.0, "dead");
    db.drop().await;
}

#[tokio::test]
async fn the_worker_retries_survives_panics_and_stops() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "work").unwrap().retry(quick());
    let ok = q.enqueue(Job::bytes(b"ok".to_vec())).await.unwrap();
    let flaky = q.enqueue(Job::bytes(b"flaky".to_vec())).await.unwrap();
    let panics = q.enqueue(Job::bytes(b"panic".to_vec())).await.unwrap();
    let bad = q.enqueue(Job::bytes(b"bad".to_vec())).await.unwrap();
    let flaky_runs = Arc::new(AtomicU32::new(0));
    let runs = flaky_runs.clone();
    let shutdown = CancellationToken::new();
    let jobs = Jobs::new(shutdown.clone());
    q.worker(move |job| {
        let runs = runs.clone();
        async move {
            match job.payload.as_slice() {
                b"flaky" if runs.fetch_add(1, Ordering::SeqCst) == 0 => {
                    Err(anyhow::anyhow!("not yet"))?;
                }
                b"panic" => panic!("handler bug"),
                b"bad" => return Err(JobError::permanent(anyhow::anyhow!("unreadable"))),
                _ => {}
            }
            Ok(())
        }
    })
    .poll(Duration::from_millis(20))
    .concurrency(2)
    .spawn(&jobs);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let c = q.counts().await.unwrap();
        if c.done == 2 && c.dead == 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker stalled: {c:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(db.state(ok.id).await.0, "done");
    assert_eq!(db.state(flaky.id).await.0, "done");
    assert_eq!(flaky_runs.load(Ordering::SeqCst), 2);
    let (state, attempts, _, error) = db.state(panics.id).await;
    assert_eq!((state.as_str(), attempts), ("dead", 3));
    assert_eq!(error.as_deref(), Some("the handler panicked"));
    let (state, attempts, _, _) = db.state(bad.id).await;
    assert_eq!((state.as_str(), attempts), ("dead", 1));
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), jobs.stopped())
        .await
        .expect("the worker stops");
    db.drop().await;
}

#[tokio::test]
async fn shutdown_puts_back_a_job_that_outlasts_the_grace() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "work").unwrap();
    let slow = q.enqueue(Job::bytes(b"slow".to_vec())).await.unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let s = started.clone();
    let shutdown = CancellationToken::new();
    let jobs = Jobs::new(shutdown.clone());
    q.worker(move |_| {
        let s = s.clone();
        async move {
            s.notify_one();
            tokio::time::sleep(Duration::from_hours(1)).await;
            Ok(())
        }
    })
    .poll(Duration::from_millis(20))
    .shutdown_grace(Duration::from_millis(100))
    .spawn(&jobs);
    tokio::time::timeout(Duration::from_secs(10), started.notified())
        .await
        .expect("the job starts");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), jobs.stopped())
        .await
        .expect("the worker stops within its grace");
    let (state, attempts, payload, _) = db.state(slow.id).await;
    assert_eq!(
        (state.as_str(), attempts),
        ("queued", 1),
        "put back, its aborted attempt still counted"
    );
    assert_eq!(payload, b"slow");
    db.drop().await;
}

async fn wait_for(q: &Queue, secs: u64, ok: impl Fn(&queue::Counts) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let c = q.counts().await.unwrap();
        if ok(&c) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the queue stalled: {c:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn heartbeats_keep_a_long_job_from_being_recovered() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "work").unwrap();
    let job = q.enqueue(Job::bytes(b"long".to_vec())).await.unwrap();
    let runs = Arc::new(AtomicU32::new(0));
    let shutdown = CancellationToken::new();
    let jobs = Jobs::new(shutdown.clone());
    // Two replicas, each recovering stale claims every 1.5 s; the job outlasts
    // `stale_after` by two thirds.
    for _ in 0..2 {
        let runs = runs.clone();
        q.worker(move |_| {
            let runs = runs.clone();
            async move {
                runs.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }
        })
        .poll(Duration::from_millis(20))
        .stale_after(Duration::from_secs(3))
        .spawn(&jobs);
    }
    wait_for(&q, 90, |c| c.done == 1).await;
    let (state, attempts, _, _) = db.state(job.id).await;
    assert_eq!((state.as_str(), attempts), ("done", 1));
    assert_eq!(runs.load(Ordering::SeqCst), 1, "no other replica stole it");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), jobs.stopped())
        .await
        .expect("the workers stop");
    db.drop().await;
}

#[tokio::test]
async fn a_heartbeat_that_finds_the_claim_lost_aborts_the_handler() {
    struct Dropped(Arc<AtomicU32>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "work").unwrap();
    let job = q.enqueue(Job::bytes(b"long".to_vec())).await.unwrap();
    let (started, dropped) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
    let (s, d) = (started.clone(), dropped.clone());
    let shutdown = CancellationToken::new();
    let jobs = Jobs::new(shutdown.clone());
    q.worker(move |_| {
        let (s, guard) = (s.clone(), Dropped(d.clone()));
        async move {
            let _guard = guard;
            s.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        }
    })
    .poll(Duration::from_millis(20))
    .stale_after(Duration::from_secs(3))
    .spawn(&jobs);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while started.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the job never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Another worker took the job over: its claim moved on.
    sqlx::query("UPDATE owt_jobs SET claim = claim + 1 WHERE id = $1")
        .bind(job.id)
        .execute(&db.pool)
        .await
        .unwrap();
    // The next heartbeat (every second) finds the claim lost and aborts the handler.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while dropped.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the handler ran on after its claim was lost"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (state, attempts, _, _) = db.state(job.id).await;
    assert_eq!(
        (state.as_str(), attempts),
        ("running", 1),
        "the new claim's row is untouched"
    );
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), jobs.stopped())
        .await
        .expect("the worker stops");
    db.drop().await;
}

#[tokio::test]
async fn a_worker_never_runs_more_jobs_than_its_concurrency() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "work").unwrap();
    for i in 0..6_u8 {
        q.enqueue(Job::bytes(vec![i])).await.unwrap();
    }
    let (now, peak) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
    let (n, p) = (now.clone(), peak.clone());
    let shutdown = CancellationToken::new();
    let jobs = Jobs::new(shutdown.clone());
    q.worker(move |_| {
        let (n, p) = (n.clone(), p.clone());
        async move {
            let inflight = n.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(inflight, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(150)).await;
            n.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    })
    .concurrency(2)
    .poll(Duration::from_millis(20))
    .spawn(&jobs);
    wait_for(&q, 60, |c| c.done == 6).await;
    let peak = peak.load(Ordering::SeqCst);
    assert!((1..=2).contains(&peak), "peak in flight was {peak}");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), jobs.stopped())
        .await
        .expect("the worker stops");
    db.drop().await;
}

#[tokio::test]
async fn an_old_claim_cannot_touch_a_later_one_of_the_same_job() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap().retry(quick());
    let e = q.enqueue(Job::bytes(b"p".to_vec())).await.unwrap();
    let boom = || JobError::from(anyhow::anyhow!("zombie"));

    // Released, then claimed again: the retry counter steps back, the claim does not.
    let first = q.claim(1).await.unwrap().pop().unwrap();
    assert!(q.release(&first).await.unwrap());
    let second = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!((first.attempt, second.attempt), (1, 2));
    assert!(second.claim > first.claim);
    assert!(!q.complete(&first).await.unwrap());
    assert_eq!(q.fail(&first, &boom()).await.unwrap(), Failed::Lost);
    assert!(!q.release(&first).await.unwrap());
    assert_eq!(q.heartbeat(&[(e.id, first.claim)]).await.unwrap(), 0);
    assert_eq!(q.heartbeat(&[(e.id, second.claim)]).await.unwrap(), 1);
    assert_eq!(db.state(e.id).await.0, "running");

    // Dead, redriven (attempts reset), claimed again.
    assert_eq!(
        q.fail(&second, &JobError::permanent(anyhow::anyhow!("x")))
            .await
            .unwrap(),
        Failed::Dead
    );
    assert!(q.redrive(e.id).await.unwrap());
    let third = q.claim(1).await.unwrap().pop().unwrap();
    assert_eq!(third.attempt, 1);
    assert!(third.claim > second.claim);
    for old in [&first, &second] {
        assert!(!q.complete(old).await.unwrap());
        assert_eq!(q.fail(old, &boom()).await.unwrap(), Failed::Lost);
        assert!(!q.release(old).await.unwrap());
        assert_eq!(q.heartbeat(&[(e.id, old.claim)]).await.unwrap(), 0);
    }
    assert_eq!(db.state(e.id).await.0, "running");
    assert!(q.complete(&third).await.unwrap());
    db.drop().await;
}

#[tokio::test]
async fn a_keyed_enqueue_refuses_a_snapshot_isolation_level() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {level}"
        )))
        .execute(&mut *tx)
        .await
        .unwrap();
        let err = q
            .enqueue_in(&mut tx, Job::bytes(vec![1]).key("k"))
            .await
            .expect_err("refused");
        let message = err.to_string();
        assert!(message.contains("READ COMMITTED"), "{message}");
        assert!(message.contains(level), "{message}");
        tx.rollback().await.unwrap();

        // Without a key nothing can collide.
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {level}"
        )))
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            q.enqueue_in(&mut tx, Job::bytes(vec![2]))
                .await
                .unwrap()
                .fresh
        );
        tx.commit().await.unwrap();
    }
    let mut tx = db.pool.begin().await.unwrap();
    assert!(
        q.enqueue_in(&mut tx, Job::bytes(vec![3]).key("k"))
            .await
            .unwrap()
            .fresh,
        "READ COMMITTED is the default"
    );
    tx.commit().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn a_job_released_on_its_last_attempt_is_dead() {
    let Some(db) = Db::new().await else { return };
    let q = Queue::new(db.pool.clone(), "mail").unwrap();
    let e = q.enqueue(Job::bytes(vec![]).max_attempts(1)).await.unwrap();
    let c = q.claim(1).await.unwrap().pop().unwrap();
    assert!(q.release(&c).await.unwrap());
    assert!(
        q.claim(1).await.unwrap().is_empty(),
        "it does not run a second time"
    );
    let (state, attempts, _, error) = db.state(e.id).await;
    assert_eq!((state.as_str(), attempts), ("dead", 1));
    assert!(error.unwrap().contains("last attempt"));
    db.drop().await;
}
