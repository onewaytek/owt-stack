//! `owt_runtime::jobs`: the shared loop on tokio's paused clock, the singleton against
//! a real Postgres (`DATABASE_URL`), leases against a real Redis (`REDIS_URL`). The
//! database and Redis tests are skipped when their variable is unset.

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use owt_runtime::jobs::{CancellationToken, Every, Jobs};
use tokio::time::Instant;

/// Run the paused clock forward until `done` holds (or a minute of virtual time).
async fn until(done: impl Fn() -> bool) {
    for _ in 0..6000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition never held");
}

#[tokio::test(start_paused = true)]
async fn a_failed_or_panicking_run_does_not_stop_the_loop() {
    let runs = Arc::new(AtomicUsize::new(0));
    let jobs = Jobs::new(CancellationToken::new());
    let r = runs.clone();
    jobs.every_replica(
        "flaky",
        Every::new(Duration::from_secs(1)).jitter(Duration::ZERO),
        move || {
            let n = r.fetch_add(1, SeqCst);
            async move {
                match n {
                    0 => panic!("first run panics"),
                    1 => anyhow::bail!("second run fails"),
                    _ => Ok(()),
                }
            }
        },
    );
    until(|| runs.load(SeqCst) >= 4).await;
    jobs.shutdown().cancel();
    jobs.stopped().await;
}

#[tokio::test(start_paused = true)]
async fn the_period_holds_and_jitter_only_adds() {
    let at = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let start = Instant::now();
    let jobs = Jobs::new(CancellationToken::new());
    let a = at.clone();
    jobs.every_replica(
        "timed",
        Every::new(Duration::from_secs(10)).jitter(Duration::from_secs(2)),
        move || {
            a.lock().unwrap().push(Instant::now());
            async { Ok(()) }
        },
    );
    until(|| at.lock().unwrap().len() >= 6).await;
    jobs.shutdown().cancel();
    jobs.stopped().await;
    let at = at.lock().unwrap();
    assert!(
        at[0] - start < Duration::from_secs(2),
        "the first run waits only the jitter"
    );
    for pair in at.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= Duration::from_secs(10) && gap < Duration::from_secs(12),
            "gap {gap:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_lets_the_run_in_progress_finish_and_starts_no_more() {
    let (started, finished) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let jobs = Jobs::new(CancellationToken::new());
    let (s, f) = (started.clone(), finished.clone());
    jobs.every_replica(
        "slow",
        Every::new(Duration::from_secs(1)).jitter(Duration::ZERO),
        move || {
            s.fetch_add(1, SeqCst);
            let f = f.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                f.fetch_add(1, SeqCst);
                Ok(())
            }
        },
    );
    until(|| started.load(SeqCst) == 1).await;
    jobs.shutdown().cancel();
    jobs.stopped().await;
    assert_eq!((started.load(SeqCst), finished.load(SeqCst)), (1, 1));
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(started.load(SeqCst), 1, "nothing starts after shutdown");
}

// ------------------------------------------------------------------ singleton

async fn pool() -> Option<sqlx::PgPool> {
    // Blank is unset: CI clears it when it starts no Postgres.
    let url = owt_runtime::env::var("DATABASE_URL")?;
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("DATABASE_URL connects"),
    )
}

fn lock_id() -> i64 {
    // Distinct per test and per run, so concurrent test binaries never share a lock.
    i64::from(std::process::id()) << 20 | i64::from(rand_u16())
}

fn rand_u16() -> u16 {
    use std::hash::{BuildHasher, RandomState};
    u16::try_from(RandomState::new().hash_one(0u8) & 0xffff).unwrap()
}

/// Two replicas tick together on one lock; runs never overlap, and both replicas'
/// ticks happen (the loser skips rather than waits).
#[tokio::test]
async fn a_singleton_runs_on_one_replica_at_a_time() {
    let Some(pool) = pool().await else { return };
    let id = lock_id();
    let active = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let runs = Arc::new(AtomicUsize::new(0));
    let shutdown = CancellationToken::new();
    let replicas: Vec<Jobs> = (0..2).map(|_| Jobs::new(shutdown.clone())).collect();
    for jobs in &replicas {
        let (a, m, r) = (active.clone(), most.clone(), runs.clone());
        jobs.singleton(
            "exclusive",
            Every::new(Duration::from_millis(40)).jitter(Duration::ZERO),
            pool.clone(),
            id,
            move || {
                let (a, m, r) = (a.clone(), m.clone(), r.clone());
                async move {
                    let now = a.fetch_add(1, SeqCst) + 1;
                    m.fetch_max(now, SeqCst);
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    a.fetch_sub(1, SeqCst);
                    r.fetch_add(1, SeqCst);
                    Ok(())
                }
            },
        );
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;
    shutdown.cancel();
    for jobs in &replicas {
        jobs.stopped().await;
    }
    assert!(
        runs.load(SeqCst) >= 3,
        "the work ran ({})",
        runs.load(SeqCst)
    );
    assert_eq!(most.load(SeqCst), 1, "two replicas ran it at once");
}

/// A run that panics still gives the lock up: the other replica gets its turn, and
/// nothing is left holding it afterwards.
#[tokio::test]
async fn a_panicking_singleton_releases_its_lock() {
    let Some(pool) = pool().await else { return };
    let id = lock_id();
    let shutdown = CancellationToken::new();
    let (bad, good) = (Jobs::new(shutdown.clone()), Jobs::new(shutdown.clone()));
    let every = Every::new(Duration::from_millis(30)).jitter(Duration::ZERO);
    bad.singleton("panics", every, pool.clone(), id, || async {
        panic!("boom")
    });
    let good_runs = Arc::new(AtomicUsize::new(0));
    let g = good_runs.clone();
    good.singleton("steady", every, pool.clone(), id, move || {
        g.fetch_add(1, SeqCst);
        async { Ok(()) }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    shutdown.cancel();
    bad.stopped().await;
    good.stopped().await;
    assert!(
        good_runs.load(SeqCst) > 0,
        "the healthy replica never got the lock"
    );
    let mut conn = pool.acquire().await.unwrap();
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(free, "the lock outlived the jobs");
    let _: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------- leases

#[cfg(feature = "redis")]
mod leases {
    use super::*;
    use owt_runtime::jobs::lease::Leases;

    async fn redis() -> Option<redis::aio::ConnectionManager> {
        let url = owt_runtime::env::var("REDIS_URL")?;
        Some(
            redis::aio::ConnectionManager::new(redis::Client::open(url).unwrap())
                .await
                .unwrap(),
        )
    }

    fn prefix() -> String {
        format!("owt-jobs-test-{}-{}", std::process::id(), rand_u16())
    }

    #[tokio::test]
    async fn only_the_holder_renews_or_releases_and_expiry_frees_it() {
        let Some(conn) = redis().await else { return };
        let p = prefix();
        let (a, b) = (
            Leases::new(conn.clone(), "a", &p),
            Leases::new(conn.clone(), "b", &p),
        );
        let ttl = Duration::from_millis(300);
        assert!(a.acquire("clock", ttl).await);
        assert!(
            a.acquire("clock", ttl).await,
            "the holder confirms its own lease"
        );
        assert!(!b.acquire("clock", ttl).await);
        assert!(!b.renew("clock", ttl).await, "renewal is compare-and-set");
        b.release("clock").await;
        assert!(!b.acquire("clock", ttl).await, "release is compare-and-set");
        assert!(a.renew("clock", ttl).await);
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert!(b.acquire("clock", ttl).await, "an expired lease is free");
        assert!(
            !a.renew("clock", ttl).await,
            "the old holder can't take it back"
        );
        b.release("clock").await;
        assert!(
            a.acquire("clock", ttl).await,
            "a released lease is free at once"
        );
        assert!(a.first_within("sweep", ttl).await.unwrap());
        assert!(!b.first_within("sweep", ttl).await.unwrap());
    }

    /// The work stays on one replica while it lives; when it shuts down it releases
    /// the lease, and the other replica takes over well before the TTL would have.
    #[tokio::test]
    async fn a_leased_job_sticks_to_its_holder_and_hands_over_on_shutdown() {
        let Some(conn) = redis().await else { return };
        let p = prefix();
        let ttl = Duration::from_secs(2);
        let every = Every::new(Duration::from_millis(50)).jitter(Duration::from_millis(10));
        let ran: Arc<Mutex<Vec<&'static str>>> = Arc::default();
        let tokens = [CancellationToken::new(), CancellationToken::new()];
        let replicas: Vec<Jobs> = tokens.iter().map(|t| Jobs::new(t.clone())).collect();
        for (jobs, who) in replicas.iter().zip(["a", "b"]) {
            let r = ran.clone();
            jobs.leased(
                "clock",
                every,
                Leases::new(conn.clone(), who, &p),
                "clock",
                ttl,
                move |_held| {
                    r.lock().unwrap().push(who);
                    async { Ok(()) }
                },
            );
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        let owner = {
            let ran = ran.lock().unwrap();
            assert!(ran.len() >= 5, "it ran ({})", ran.len());
            assert!(
                ran.iter().all(|w| *w == ran[0]),
                "ownership flapped: {ran:?}"
            );
            ran[0]
        };
        let (gone, other) = if owner == "a" { (0, "b") } else { (1, "a") };
        tokens[gone].cancel();
        replicas[gone].stopped().await;
        let handed = Instant::now();
        loop {
            if ran.lock().unwrap().last() == Some(&other) {
                break;
            }
            assert!(
                handed.elapsed() < ttl / 2,
                "no handover before the TTL: the lease was not released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokens[1 - gone].cancel();
        replicas[1 - gone].stopped().await;
    }

    /// A TTL that outlasts the period plus jitter keeps the lease between ticks, even
    /// when a run ends with only part of the TTL left: the renewal at the end of each
    /// run, not the renewer's last beat, is what spans the wait for the next tick.
    #[tokio::test]
    async fn a_ttl_longer_than_the_period_keeps_the_lease_between_ticks() {
        let Some(conn) = redis().await else { return };
        let p = prefix();
        let thief = Leases::new(conn.clone(), "thief", &p);
        let jobs = Jobs::new(CancellationToken::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let r = runs.clone();
        jobs.leased(
            "tick",
            Every::new(Duration::from_millis(400)).jitter(Duration::ZERO),
            Leases::new(conn.clone(), "owner", &p),
            "tick",
            Duration::from_millis(500),
            move |_held| {
                r.fetch_add(1, SeqCst);
                async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    Ok(())
                }
            },
        );
        // Let the owner take the lease, then try to steal it for a few periods.
        until(|| runs.load(SeqCst) > 0).await;
        let started = Instant::now();
        let mut stolen = 0;
        while started.elapsed() < Duration::from_millis(2500) {
            if thief.acquire("tick", Duration::from_millis(500)).await {
                stolen += 1;
                thief.release("tick").await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        jobs.shutdown().cancel();
        jobs.stopped().await;
        assert_eq!(stolen, 0, "the lease lapsed between ticks {stolen} times");
        assert!(runs.load(SeqCst) >= 5, "it ran ({})", runs.load(SeqCst));
    }

    /// A run learns when another replica has taken its lease out from under it.
    #[tokio::test]
    async fn a_run_learns_its_lease_was_lost() {
        let Some(conn) = redis().await else { return };
        let p = prefix();
        let ttl = Duration::from_millis(600);
        let thief = Leases::new(conn.clone(), "thief", &p);
        let jobs = Jobs::new(CancellationToken::new());
        let lost = Arc::new(AtomicUsize::new(0));
        let l = lost.clone();
        let (c, p2) = (conn.clone(), p.clone());
        jobs.leased(
            "long",
            Every::new(Duration::from_secs(60)).jitter(Duration::ZERO),
            Leases::new(conn.clone(), "owner", &p),
            "long",
            ttl,
            move |held| {
                let (l, mut c, p2) = (l.clone(), c.clone(), p2.clone());
                async move {
                    // Someone else takes the key, as after an expiry during a stall.
                    let _: () = redis::cmd("SET")
                        .arg(format!("{p2}:lease:long"))
                        .arg("thief")
                        .query_async(&mut c)
                        .await?;
                    tokio::time::timeout(Duration::from_secs(3), held.lost()).await?;
                    assert!(held.is_lost());
                    l.fetch_add(1, SeqCst);
                    Ok(())
                }
            },
        );
        let started = Instant::now();
        while lost.load(SeqCst) == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the run never learnt it lost the lease"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        jobs.shutdown().cancel();
        jobs.stopped().await;
        thief.release("long").await;
    }
}
