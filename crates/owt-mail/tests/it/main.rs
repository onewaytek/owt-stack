//! owt-mail's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-mail --test it <area>::`.

mod http;
mod smtp;
