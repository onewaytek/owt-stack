//! Password hashing: Argon2id, run on the blocking pool.
//!
//! Argon2 is slow on purpose (tens of milliseconds of CPU per check). On a runtime
//! worker it would hold up every socket and request that worker serves, so both
//! functions hand the work to `spawn_blocking`.
//!
//! [`verify`] also accepts Django's `pbkdf2_sha256$<iterations>$<salt>$<hash>`, the
//! format a Django app's accounts carry over in. After a successful check against such
//! a hash, [`needs_rehash`] says so and the app stores [`hash`] of the password it now
//! holds in the clear: accounts migrate one sign-in at a time.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::task::spawn_blocking;

/// An Argon2id PHC string for `password`.
pub async fn hash(password: &str) -> anyhow::Result<String> {
    let password = password.to_owned();
    spawn_blocking(move || {
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
    spawn_blocking(move || verify_blocking(&password, &stored))
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
}
