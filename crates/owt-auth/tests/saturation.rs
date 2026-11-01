//! The permit timeout in a process of its own: `set_concurrency` and
//! `set_permit_timeout` only take effect before the first check, and the other tests
//! share one semaphore.

use owt_auth::password;
use std::time::{Duration, Instant};

/// One permit, a short timeout: while a long check holds the permit, another fails
/// with `Busy` after the timeout instead of queueing behind it, and once the permit
/// is free checks run as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saturated_hasher_fails_fast_with_busy() {
    assert!(password::set_concurrency(1));
    assert!(password::set_permit_timeout(Duration::from_millis(100)));
    assert!(
        !password::set_permit_timeout(Duration::from_secs(5)),
        "a second setting changes nothing"
    );
    let stored = password::hash("correct horse").await.unwrap();

    // A hash with two hundred passes: checking anything against it holds the only
    // permit for seconds (it matches nothing; the output is not its own).
    let slow = "$argon2id$v=19$m=19456,t=200,p=1$c29tZXNhbHRzb21lc2FsdA$\
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let holder = tokio::spawn(async move { password::verify("guess", slow).await });
    // Let it take the permit.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let began = Instant::now();
    assert_eq!(
        password::verify("correct horse", &stored).await,
        Err(password::Busy)
    );
    let waited = began.elapsed();
    assert!(
        !holder.is_finished(),
        "the long check ended before the busy answer, so nothing was saturated"
    );
    assert!(
        waited >= Duration::from_millis(100),
        "gave up after {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(2),
        "waited {waited:?}, not 100 ms"
    );
    assert!(
        password::hash("x")
            .await
            .unwrap_err()
            .is::<password::Busy>()
    );

    assert_eq!(holder.await.unwrap(), Ok(false));
    // Free again: an ordinary check is unchanged.
    assert_eq!(password::verify("correct horse", &stored).await, Ok(true));
    assert_eq!(password::verify("wrong", &stored).await, Ok(false));
}
