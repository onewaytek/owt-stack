//! Process plumbing apps on owt-stack share.
//!
//! * [`env`]: configuration from the environment. A variable that is present but does
//!   not parse is an error at startup, never a silent fall back to the default.
//! * [`logging`]: `tracing` to stderr (JSON in production), optionally exported over
//!   OTLP (feature `otel`).
//! * [`metrics`] (feature `metrics`): a Prometheus recorder, per-route HTTP timings,
//!   runtime and pool gauges, `/metrics` on its own listener.
//! * [`cache`] (feature `redis`): a Redis read-through cache that can never fail a
//!   request: misses and errors are both a miss, writes are detached.
//! * [`db`]: the Postgres pool, and migrations under an advisory lock.
//! * [`jobs`]: background work on every replica, on one at a time (an advisory lock),
//!   or on the replica holding a Redis lease (feature `redis`).
//! * [`serve`]: bind, serve with client addresses, stop on SIGTERM or Ctrl-C.

#[cfg(feature = "redis")]
pub mod cache;
pub mod db;
pub mod env;
pub mod jobs;
pub mod logging;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod serve;

/// A Redis key prefix that names one deployment and nothing nested under it: ASCII
/// letters, digits, `_`, `.` and `-`, the rule `owt_bus::Bus::redis` applies too. A
/// `:` would let `myapp:c` hold a cache key that is also a lease under `myapp`, and
/// a space or glob character reads differently in a pattern than in a key.
#[cfg(feature = "redis")]
pub(crate) fn checked_prefix(prefix: &str) -> anyhow::Result<()> {
    let literal = !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    anyhow::ensure!(
        literal,
        "a Redis prefix is ASCII letters, digits, `_`, `.` and `-`: {prefix:?}"
    );
    Ok(())
}

#[cfg(all(test, feature = "redis"))]
mod tests {
    use super::checked_prefix;

    #[test]
    fn a_prefix_names_one_deployment() {
        for ok in ["myapp", "my-app_2.staging"] {
            assert!(checked_prefix(ok).is_ok(), "{ok}");
        }
        for bad in ["", "*", "my?app", "[ab]", "myapp:c", "my app", "é"] {
            assert!(checked_prefix(bad).is_err(), "{bad}");
        }
    }
}
