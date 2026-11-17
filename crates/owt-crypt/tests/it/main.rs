//! owt-crypt's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-crypt --test it <area>::`.

mod crypt;
#[cfg(feature = "yubihsm")]
mod yubihsm;
