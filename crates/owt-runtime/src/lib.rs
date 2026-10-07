//! Process plumbing the onewaytek apps share.
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
