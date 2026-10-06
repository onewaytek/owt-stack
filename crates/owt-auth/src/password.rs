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
//! [`verify`] also accepts Django's `pbkdf2_sha256$<iterations>$<salt>$<hash>`, the
//! format a Django app's accounts carry over in. After a successful check against such
//! a hash, [`needs_rehash`] says so and the app stores [`hash`] of the password it now
//! holds in the clear: accounts migrate one sign-in at a time.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use std::sync::OnceLock;

use subtle::ConstantTimeEq;
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

/// Whether `password` matches `stored` (Argon2 PHC, or Django `pbkdf2_sha256`).
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
    if stored.starts_with("pbkdf2_sha256$") {
        return django_pbkdf2(password, stored).unwrap_or(false);
    }
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// `stored` is not a current Argon2id hash: rehash after the next successful check.
#[must_use]
pub fn needs_rehash(stored: &str) -> bool {
    !stored.starts_with("$argon2id$")
}

fn django_pbkdf2(password: &str, stored: &str) -> Option<bool> {
    let mut parts = stored.splitn(4, '$');
    let (_, iterations, salt, expected) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let iterations: u32 = iterations.parse().ok()?;
    let expected = base64::engine::general_purpose::STANDARD
        .decode(expected)
        .ok()?;
    let mut derived = vec![0u8; expected.len()];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut derived,
    );
    Some(bool::from(derived.ct_eq(&expected)))
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

    /// Made by Django's algorithm: `hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)`.
    #[tokio::test]
    async fn django_hashes_verify_and_ask_to_be_replaced() {
        let stored = "pbkdf2_sha256$1000$saltsaltsalt$F7o7+5VTVzFAO998X6s3AHrDsJVdMiIlgndIMe19NvY=";
        assert!(verify("correct horse", stored).await);
        assert!(!verify("correct horsf", stored).await);
        assert!(needs_rehash(stored));
        assert!(!verify("correct horse", "pbkdf2_sha256$x$salt$AAAA").await);
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
}
