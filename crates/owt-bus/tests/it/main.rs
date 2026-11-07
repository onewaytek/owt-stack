//! owt-bus's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-bus --test it <area>::`.

mod model;
mod redis_hostile;
mod redis_tls;
