//! Password hashing: Argon2id, run on the blocking pool.
//!
//! Argon2 is slow on purpose (tens of milliseconds of CPU per check). On a runtime
//! worker it would hold up every socket and request that worker serves, so both
//! functions hand the work to `spawn_blocking`.
//!
//! It is also memory-hard (19 MiB per hash), so the checks running at once are
//! bounded: a burst of sign-ins queues for a permit instead of multiplying that by
//! the blocking pool's 512 threads, which no pod's memory limit survives. The bound
//! is the CPU count, at most [`MAX_DEFAULT_CONCURRENCY`]; [`set_concurrency`] changes
//! it. The permit moves into the blocking task, so a caller that gives up (a request
//! timeout, a closed connection) does not free it while the hash is still running.
//!
//! When [`hash`]'s parameters are raised, [`needs_rehash`] says which stored hashes are
//! weaker: the app stores a fresh [`hash`] after the next successful check.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use std::sync::OnceLock;

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::task::spawn_blocking;

/// The most hashes run at once unless [`set_concurrency`] says otherwise: 150 MiB of
/// Argon2 memory at the worst.
pub const MAX_DEFAULT_CONCURRENCY: usize = 8;

static PERMITS: OnceLock<Semaphore> = OnceLock::new();

/// Run at most `n` hashes at once (at least one). Call at startup: it returns `false`,
/// changing nothing, once a hash has run or a bound has been set.
pub fn set_concurrency(n: usize) -> bool {
    PERMITS.set(Semaphore::new(n.max(1))).is_ok()
}

async fn permit() -> SemaphorePermit<'static> {
    PERMITS
        .get_or_init(|| {
            let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
            Semaphore::new(cpus.min(MAX_DEFAULT_CONCURRENCY))
        })
        .acquire()
        .await
        .expect("the semaphore is never closed")
}

/// An Argon2id PHC string for `password`.
pub async fn hash(password: &str) -> anyhow::Result<String> {
    let password = password.to_owned();
    let permit = permit().await;
    spawn_blocking(move || {
        let _permit = permit;
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing a password: {e}"))
    })
    .await?
}

/// Whether `password` matches `stored`, an Argon2 PHC string.
/// Anything unparseable matches nothing.
pub async fn verify(password: &str, stored: &str) -> bool {
    let (password, stored) = (password.to_owned(), stored.to_owned());
    let permit = permit().await;
    spawn_blocking(move || {
        let _permit = permit;
        verify_blocking(&password, &stored)
    })
    .await
    .unwrap_or(false)
}

fn verify_blocking(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Check `password` for an account that may not exist: `stored` is its hash, or `None`
/// if no account matched. `None` still costs a full Argon2 check (against a hash
/// nothing matches), so the time a sign-in takes does not say whether the account
/// exists.
pub async fn verify_or_decoy(password: &str, stored: Option<&str>) -> bool {
    static DECOY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    if let Some(stored) = stored {
        return verify(password, stored).await;
    }
    // Hashed with today's parameters, so it costs what a real check costs.
    let decoy = DECOY
        .get_or_try_init(|| async { hash(&crate::random_token(32)).await })
        .await;
    if let Ok(decoy) = decoy {
        verify(password, decoy).await;
    }
    false
}

/// `stored` is not an Argon2id hash at least as strong as [`hash`] makes today: rehash
/// after the next successful check. This is what raises old hashes when the
/// parameters are raised.
#[must_use]
pub fn needs_rehash(stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return true;
    };
    let Ok(params) = argon2::Params::try_from(&parsed) else {
        return true;
    };
    let now = argon2::Params::default();
    !stored.starts_with("$argon2id$")
        || params.m_cost() < now.m_cost()
        || params.t_cost() < now.t_cost()
        || params.p_cost() < now.p_cost()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn argon2_round_trip() {
        let h = hash("correct horse").await.unwrap();
        assert!(verify("correct horse", &h).await);
        assert!(!verify("wrong", &h).await);
        assert!(!verify("x", "not-a-hash").await);
        assert!(!needs_rehash(&h));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn checking_a_password_leaves_the_runtime_free() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        let stored = hash("correct horse").await.unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                t.fetch_add(1, Relaxed);
                tokio::task::yield_now().await;
            }
        });
        assert!(verify("correct horse", &stored).await);
        ticker.abort();
        assert!(
            ticks.load(Relaxed) > 0,
            "the runtime ran nothing else during the check"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_burst_of_checks_queues_for_permits_and_all_finish() {
        let stored = hash("correct horse").await.unwrap();
        // More than there are permits (other tests share them, so only completion is
        // asserted, not how many are free).
        let checks: Vec<_> = (0..MAX_DEFAULT_CONCURRENCY * 3)
            .map(|_| {
                let stored = stored.clone();
                tokio::spawn(async move { verify("correct horse", &stored).await })
            })
            .collect();
        for c in checks {
            assert!(c.await.unwrap());
        }
    }

    #[tokio::test]
    async fn weaker_argon2_hashes_ask_to_be_replaced() {
        assert!(!needs_rehash(&hash("x").await.unwrap()));
        // Argon2id at a tenth of today's memory, and Argon2i at today's parameters.
        let salt_and_hash = "c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(needs_rehash(&format!(
            "$argon2id$v=19$m=1024,t=2,p=1${salt_and_hash}"
        )));
        assert!(needs_rehash(&format!(
            "$argon2i$v=19$m=19456,t=2,p=1${salt_and_hash}"
        )));
        assert!(needs_rehash("garbage"));
    }

    #[tokio::test]
    async fn a_missing_account_costs_a_check_and_never_matches() {
        let stored = hash("correct horse").await.unwrap();
        assert!(verify_or_decoy("correct horse", Some(&stored)).await);
        assert!(!verify_or_decoy("wrong", Some(&stored)).await);
        let started = std::time::Instant::now();
        assert!(verify("correct horse", &stored).await);
        let real = started.elapsed();
        // The first decoy also hashes it; time the second.
        assert!(!verify_or_decoy("correct horse", None).await);
        let started = std::time::Instant::now();
        assert!(!verify_or_decoy("correct horse", None).await);
        assert!(
            started.elapsed() > real / 4,
            "the decoy took {:?}, a real check {real:?}",
            started.elapsed()
        );
    }
}
