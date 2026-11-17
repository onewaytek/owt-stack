//! owt-web's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-web --test it <area>::`.

mod hardened_app;
mod middleware;
mod properties;
mod stack;
