//! `set_concurrency` in a process of its own: it only takes effect before the first
//! hash, and the other tests share one semaphore.

use owt_auth::password;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bound_is_set_once_and_then_holds() {
    assert!(password::set_concurrency(1), "the first setting takes");
    assert!(!password::set_concurrency(8), "a second changes nothing");
    let stored = password::hash("correct horse").await.unwrap();
    assert!(!password::set_concurrency(8));
    // One at a time, six checks still all finish.
    let checks: Vec<_> = (0..6)
        .map(|i| {
            let stored = stored.clone();
            let given = if i % 2 == 0 { "correct horse" } else { "wrong" };
            tokio::spawn(async move { password::verify(given, &stored).await })
        })
        .collect();
    let mut matched = 0;
    for c in checks {
        matched += usize::from(c.await.unwrap());
    }
    assert_eq!(matched, 3);
}
