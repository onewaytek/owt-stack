//! owt-accounts's integration tests as one binary, a `mod` per area; one area runs with
//! `cargo test -p owt-accounts --test it <area>::`.

mod accounts;
mod ledger;
mod mfa;
mod mfa_pages;
mod policies;
