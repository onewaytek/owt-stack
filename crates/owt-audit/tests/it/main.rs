//! owt-audit's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-audit --test it <area>::`.

mod audit;
#[cfg(feature = "s3")]
mod s3_object_lock;
