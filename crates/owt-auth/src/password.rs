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
//! A check waits for a permit at most [`DEFAULT_PERMIT_TIMEOUT`] (five seconds;
//! [`set_permit_timeout`] changes it), then fails with [`Busy`] rather than queueing
//! for as long as the burst lasts. `owt_accounts` answers it with a 503 and
//! `Retry-After` (`owt_web::Error::Unavailable`); an app calling these functions
//! itself maps it the same way.
//!
//! What a new password must satisfy is [`Policy`]: NIST SP 800-63B's rules, with a
//! breached-password check against a corpus the app supplies ([`SortedHashes`],
//! [`Bloom`]).
//!
//! When [`hash`]'s parameters are raised, [`needs_rehash`] says which stored hashes are
//! weaker: the app stores a fresh [`hash`] after the next successful check.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use std::sync::OnceLock;
use std::time::Duration;

use unicode_normalization::UnicodeNormalization;

mod policy;
pub use policy::{Bloom, Breached, Context, Policy, Refusal, SortedHashes};

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::task::spawn_blocking;

/// The most hashes run at once unless [`set_concurrency`] says otherwise: 150 MiB of
/// Argon2 memory at the worst.
pub const MAX_DEFAULT_CONCURRENCY: usize = 8;

/// How long a check waits for a permit unless [`set_permit_timeout`] says otherwise.
/// Long enough to ride out an ordinary burst of sign-ins (a permit is held for tens of
/// milliseconds, a recovery code's for a few hundred), short enough that a saturated
/// pod answers 503 well inside a request's deadline instead of letting the queue grow.
pub const DEFAULT_PERMIT_TIMEOUT: Duration = Duration::from_secs(5);

static PERMITS: OnceLock<Semaphore> = OnceLock::new();
static PERMIT_TIMEOUT: OnceLock<Duration> = OnceLock::new();

/// Every permit stayed taken for the whole [`DEFAULT_PERMIT_TIMEOUT`] (or what
/// [`set_permit_timeout`] set): the pod is saturated with password checks, and this
/// one was not run. Not a mismatch: answer 503 with `Retry-After`
/// (`owt_web::Error::unavailable`), and do not charge it as a failed sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("too many passwords are being checked at once: try again shortly")]
pub struct Busy;

/// Run at most `n` hashes at once (at least one). Call at startup: it returns `false`,
/// changing nothing, once a hash has run or a bound has been set.
pub fn set_concurrency(n: usize) -> bool {
    PERMITS.set(Semaphore::new(n.max(1))).is_ok()
}

/// Wait at most `wait` for a permit (at least a millisecond), then fail with [`Busy`].
/// Call at startup: it returns `false`, changing nothing, once a check has waited for a
/// permit or a timeout has been set.
pub fn set_permit_timeout(wait: Duration) -> bool {
    PERMIT_TIMEOUT
        .set(wait.max(Duration::from_millis(1)))
        .is_ok()
}

async fn permit() -> Result<SemaphorePermit<'static>, Busy> {
    let semaphore = PERMITS.get_or_init(|| {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Semaphore::new(cpus.min(MAX_DEFAULT_CONCURRENCY))
    });
    acquire(
        semaphore,
        *PERMIT_TIMEOUT.get_or_init(|| DEFAULT_PERMIT_TIMEOUT),
    )
    .await
}

async fn acquire(semaphore: &Semaphore, wait: Duration) -> Result<SemaphorePermit<'_>, Busy> {
    tokio::time::timeout(wait, semaphore.acquire())
        .await
        .map(|permit| permit.expect("the semaphore is never closed"))
        .map_err(|_| Busy)
}

/// `password` as it is hashed and checked: NFKC-normalized, so a password typed from a
/// composed keyboard (`é`, U+00E9) and from a decomposed one (`e` and U+0301) are one
/// password, and the length [`Policy`] counts is the length that was hashed
/// (SP 800-63B-4 §3.1.1.2: verifiers SHOULD apply Unicode normalization).
fn normalized(password: &str) -> String {
    password.nfkc().collect()
}

/// An Argon2id PHC string for `password`, hashed in its NFKC-normalized form.
///
/// # Errors
///
/// [`Busy`] (downcast the `anyhow::Error` to find it) when no permit came free in
/// time; otherwise a failure of the hasher itself, which does not happen short of
/// exhaustion.
pub async fn hash(password: &str) -> anyhow::Result<String> {
    let password = normalized(password);
    let permit = permit().await?;
    spawn_blocking(move || {
        let _permit = permit;
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing a password: {e}"))
    })
    .await?
}

/// What checking a password against a stored hash found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Check {
    /// It does not match.
    Mismatch,
    /// It matches, and the hash is of the normalized form.
    Match,
    /// It matches only as typed, not normalized: the hash was made before passwords were
    /// normalized (a password with a composed or compatibility character). Store a fresh
    /// [`hash`] now, as for [`needs_rehash`].
    MatchRaw,
}

impl Check {
    /// Whether the password matched, either way.
    #[must_use]
    pub fn matched(self) -> bool {
        self != Self::Mismatch
    }
}

/// Whether `password` matches `stored`, an Argon2 PHC string. Anything unparseable
/// matches nothing. The normalized form is tried, then (only if it differs) the
/// password as typed, which is how hashes made before normalization still open. It answers
/// only yes or no: a caller that stores hashes and rehashes after a match uses [`check`],
/// which says when the match was only of the password as typed ([`Check::MatchRaw`]),
/// so that hash is replaced by one of the normalized form.
///
/// # Errors
///
/// [`Busy`]: no permit came free in time, and nothing was checked.
pub async fn verify(password: &str, stored: &str) -> Result<bool, Busy> {
    Ok(check(password, stored).await?.matched())
}

/// [`verify`], saying whether a match needs the hash replaced ([`Check::MatchRaw`]).
///
/// # Errors
///
/// [`Busy`]: no permit came free in time, and nothing was checked.
pub async fn check(password: &str, stored: &str) -> Result<Check, Busy> {
    let (password, stored) = (password.to_owned(), stored.to_owned());
    let permit = permit().await?;
    Ok(spawn_blocking(move || {
        let _permit = permit;
        check_blocking(&password, &stored)
    })
    .await
    .unwrap_or(Check::Mismatch))
}

fn check_blocking(password: &str, stored: &str) -> Check {
    let normalized = normalized(password);
    if verify_blocking(&normalized, stored) {
        Check::Match
    } else if normalized != password && verify_blocking(password, stored) {
        Check::MatchRaw
    } else {
        Check::Mismatch
    }
}

fn verify_blocking(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// A hash nothing matches, made once with today's parameters, so a check against it
/// costs what a real one costs. `None` if the hasher failed; [`Busy`] if making it
/// found no permit.
async fn decoy() -> Result<Option<&'static str>, Busy> {
    static DECOY: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    match DECOY
        .get_or_try_init(|| async { hash(&crate::random_token(32)).await })
        .await
    {
        Ok(decoy) => Ok(Some(decoy.as_str())),
        Err(e) if e.is::<Busy>() => Err(Busy),
        Err(_) => Ok(None),
    }
}

/// Check `password` for an account that may not exist: `stored` is its hash, or `None`
/// if no account matched. `None`, or a hash that is not one [`verify`] reads (a
/// legacy format, an empty or damaged value), still costs a full Argon2 check
/// against a hash nothing matches, so the time a sign-in takes says neither whether
/// the account exists nor what its hash looks like. A yes or no: a caller that rehashes uses
/// [`check_or_decoy`], to learn of a [`Check::MatchRaw`].
///
/// # Errors
///
/// [`Busy`]: no permit came free in time, and nothing was checked.
pub async fn verify_or_decoy(password: &str, stored: Option<&str>) -> Result<bool, Busy> {
    Ok(check_or_decoy(password, stored).await?.matched())
}

/// [`verify_or_decoy`], saying whether a match needs the hash replaced.
///
/// # Errors
///
/// [`Busy`]: no permit came free in time, and nothing was checked.
pub async fn check_or_decoy(password: &str, stored: Option<&str>) -> Result<Check, Busy> {
    if let Some(stored) = stored.filter(|s| usable(s)) {
        return check(password, stored).await;
    }
    if let Some(decoy) = decoy().await? {
        check(password, decoy).await?;
    }
    Ok(Check::Mismatch)
}

/// The index of the hash in `hashes` that `secret` (ASCII, used as it is) matches, or
/// `None`. Always checks `max(hashes.len(), pad)` hashes, one after another on one
/// permit, the missing ones against a decoy, so the time taken does not say how many
/// hashes there were or which matched. For secrets that are not passwords
/// (recovery codes). [`Busy`] when no permit came free in time.
pub(crate) async fn find_matching(
    secret: &str,
    hashes: &[&str],
    pad: usize,
) -> Result<Option<usize>, Busy> {
    let Some(decoy) = decoy().await? else {
        return Ok(None);
    };
    let decoy = decoy.to_owned();
    let hashes: Vec<String> = hashes.iter().map(|h| (*h).to_owned()).collect();
    let secret = secret.to_owned();
    let permit = permit().await?;
    Ok(spawn_blocking(move || {
        let _permit = permit;
        let mut found = None;
        for i in 0..hashes.len().max(pad) {
            let stored = hashes.get(i).unwrap_or(&decoy);
            if verify_blocking(&secret, stored) && found.is_none() && i < hashes.len() {
                found = Some(i);
            }
        }
        found
    })
    .await
    .ok()
    .flatten())
}

/// Whether `stored` is a hash [`verify`] can check: an Argon2 PHC string with an
/// output and parameters Argon2 takes. Anything else (empty, a legacy format, a salt
/// with no hash) opens nothing.
#[must_use]
pub fn usable(stored: &str) -> bool {
    stored.starts_with("$argon2")
        && PasswordHash::new(stored)
            .is_ok_and(|h| h.hash.is_some() && argon2::Params::try_from(&h).is_ok())
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
        || parsed.version != Some(argon2::Version::V0x13.into())
        || params.m_cost() < now.m_cost()
        || params.t_cost() < now.t_cost()
        || params.p_cost() < now.p_cost()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password set from a composed `é` opens from a decomposed one and the reverse, and
    /// a hash made from the raw bytes (before normalization) still opens, flagged.
    #[tokio::test]
    async fn composed_and_decomposed_forms_are_one_password() {
        let composed = "caf\u{e9} au lait";
        let decomposed = "cafe\u{301} au lait";
        let h = hash(composed).await.unwrap();
        assert!(verify(decomposed, &h).await.unwrap() && verify(composed, &h).await.unwrap());
        assert_eq!(check(decomposed, &h).await.unwrap(), Check::Match);
        let h = hash(decomposed).await.unwrap();
        assert!(verify(composed, &h).await.unwrap());
        // `ﬁ` is `fi` under NFKC.
        let h = hash("\u{fb01}sh and chips").await.unwrap();
        assert!(verify("fish and chips", &h).await.unwrap());
        assert!(!verify("fish and chip", &h).await.unwrap());

        // A hash of the raw decomposed bytes, as an older build wrote it.
        let legacy = Argon2::default()
            .hash_password(decomposed.as_bytes())
            .unwrap()
            .to_string();
        assert_eq!(check(decomposed, &legacy).await.unwrap(), Check::MatchRaw);
        assert_eq!(check("other", &legacy).await.unwrap(), Check::Mismatch);
        assert_eq!(
            check_or_decoy(decomposed, Some(&legacy)).await.unwrap(),
            Check::MatchRaw
        );
        assert_eq!(
            check_or_decoy(decomposed, None).await.unwrap(),
            Check::Mismatch
        );
    }

    #[tokio::test]
    async fn find_matching_finds_the_one_and_pads() {
        let hashes = [
            hash("AAAAAAAAAA").await.unwrap(),
            hash("BBBBBBBBBB").await.unwrap(),
        ];
        let refs: Vec<&str> = hashes.iter().map(String::as_str).collect();
        assert_eq!(
            find_matching("BBBBBBBBBB", &refs, 4).await.unwrap(),
            Some(1)
        );
        assert_eq!(find_matching("CCCCCCCCCC", &refs, 4).await.unwrap(), None);
        assert_eq!(find_matching("AAAAAAAAAA", &[], 3).await.unwrap(), None);
    }

    #[tokio::test]
    async fn argon2_round_trip() {
        let h = hash("correct horse").await.unwrap();
        assert!(verify("correct horse", &h).await.unwrap());
        assert!(!verify("wrong", &h).await.unwrap());
        assert!(!verify("x", "not-a-hash").await.unwrap());
        assert!(!needs_rehash(&h));
        // Argon2 version 0x10 (an old library's) is rehashed even at today's costs.
        let v10 = h.replacen("$v=19$", "$v=16$", 1);
        assert!(needs_rehash(&v10));
    }

    /// A legacy or damaged hash costs what a real check costs, so its timing does not
    /// mark the account as one that has never signed in since an import.
    #[tokio::test]
    async fn an_unreadable_hash_costs_a_full_check() {
        let real = hash("correct horse").await.unwrap();
        let time = |stored: Option<String>| async move {
            let began = std::time::Instant::now();
            assert!(!verify_or_decoy("guess", stored.as_deref()).await.unwrap());
            began.elapsed()
        };
        time(None).await; // the decoy is made once
        let legacy = time(Some("pbkdf2_sha256$600000$salt$hash".into())).await;
        let genuine = time(Some(real)).await;
        assert!(
            legacy * 3 > genuine,
            "legacy {legacy:?} against a real check's {genuine:?}"
        );
        assert!(!usable("pbkdf2_sha256$600000$salt$hash") && !usable(""));
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
        assert!(verify("correct horse", &stored).await.unwrap());
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
                tokio::spawn(async move { verify("correct horse", &stored).await.unwrap() })
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
        assert!(
            verify_or_decoy("correct horse", Some(&stored))
                .await
                .unwrap()
        );
        assert!(!verify_or_decoy("wrong", Some(&stored)).await.unwrap());
        let started = std::time::Instant::now();
        assert!(verify("correct horse", &stored).await.unwrap());
        let real = started.elapsed();
        // The first decoy also hashes it; time the second.
        assert!(!verify_or_decoy("correct horse", None).await.unwrap());
        let started = std::time::Instant::now();
        assert!(!verify_or_decoy("correct horse", None).await.unwrap());
        assert!(
            started.elapsed() > real / 4,
            "the decoy took {:?}, a real check {real:?}",
            started.elapsed()
        );
    }

    /// Django hashes are not verified. A row that holds one must match nothing, the
    /// empty password included, and must not be honoured as a PBKDF2 request: an
    /// iteration count of `4294967295` would otherwise hold a permit, and a core, for
    /// most of an hour.
    #[tokio::test]
    async fn django_hashes_match_nothing_and_cost_nothing() {
        let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for stored in [
            "pbkdf2_sha256$1$salt$".to_owned(),
            "pbkdf2_sha256$1000$saltsaltsalt$".to_owned(),
            "pbkdf2_sha256$1$$".to_owned(),
            "pbkdf2_sha256$1$salt$AA==".to_owned(),
            format!("pbkdf2_sha256$4294967295$salt${digest}"),
            format!("pbkdf2_sha256$10000001$salt${digest}"),
            format!("pbkdf2_sha256$1000000$salt${digest}"),
            "md5$salt$900150983cd24fb0d6963f7d28e17f72".to_owned(),
            "sha1$salt$a9993e364706816aba3e25717850c26c9cd0d89d".to_owned(),
        ] {
            // Refused at the parse, so no key derivation runs for it: a wall-clock
            // bound here would say the same thing, and fail under a loaded machine.
            assert!(
                PasswordHash::new(&stored).is_err(),
                "{stored:?} parsed as a PHC string"
            );
            assert!(
                !verify("anything", &stored).await.unwrap(),
                "{stored:?} matched"
            );
            assert!(
                !verify("", &stored).await.unwrap(),
                "{stored:?} matched the empty password"
            );
            assert!(
                needs_rehash(&stored),
                "{stored:?} was not flagged for rehash"
            );
        }
    }

    /// A caller that gives up (a request timeout, a closed connection) must not free
    /// its permit while its hash still runs: that is the memory bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_check_keeps_its_permit_until_the_hash_ends() {
        let stored = hash("correct horse").await.unwrap();
        let semaphore = PERMITS.get().unwrap();
        let task = tokio::spawn(async move { verify("correct horse", &stored).await.unwrap() });
        // Wait until some check holds a permit (other tests share the semaphore, and
        // any of them holding one only makes the bound below easier to see).
        let total = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(MAX_DEFAULT_CONCURRENCY);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while semaphore.available_permits() == total {
            assert!(
                std::time::Instant::now() < deadline,
                "no check ever started"
            );
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        // The blocking hash cannot be cancelled; right after the abort it is still
        // running, so its permit must still be out.
        assert!(
            semaphore.available_permits() < total,
            "the permit was freed while the hash ran on"
        );
    }

    /// With every permit taken, a check waits its timeout and fails with `Busy` rather
    /// than queueing; once a permit is free it is granted at once.
    #[tokio::test]
    async fn a_saturated_pool_answers_busy_after_the_timeout() {
        let semaphore = Semaphore::new(1);
        let held = acquire(&semaphore, Duration::from_secs(1)).await.unwrap();
        let began = std::time::Instant::now();
        assert_eq!(
            acquire(&semaphore, Duration::from_millis(50)).await.err(),
            Some(Busy)
        );
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(50),
            "gave up after {waited:?}"
        );
        drop(held);
        assert!(acquire(&semaphore, Duration::from_millis(50)).await.is_ok());
    }

    #[test]
    fn only_weaker_parameters_ask_for_a_rehash() {
        let tail = "c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let with = |m: u32, t: u32, p: u32| format!("$argon2id$v=19$m={m},t={t},p={p}${tail}");
        assert!(!needs_rehash(&with(19456, 2, 1)), "today's parameters");
        // Stronger in any dimension is left alone.
        assert!(!needs_rehash(&with(65536, 2, 1)));
        assert!(!needs_rehash(&with(19456, 3, 1)));
        assert!(!needs_rehash(&with(19456, 2, 4)));
        assert!(!needs_rehash(&with(65536, 3, 4)));
        // Weaker in any one is replaced, however strong the others.
        assert!(needs_rehash(&with(19455, 2, 1)));
        assert!(needs_rehash(&with(19456, 1, 1)));
        assert!(needs_rehash(&with(65536, 1, 4)));
        assert!(needs_rehash(&with(1024, 9, 4)));
    }
}
