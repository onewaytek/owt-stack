//! owt-runtime's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-runtime --test it <area>::`.

mod db;
mod jobs;
mod properties;
mod queue;
