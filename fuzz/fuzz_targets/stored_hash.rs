//! `password::needs_rehash` over arbitrary stored values: never panics, and anything
//! that is not an Argon2id hash at today's parameters asks to be replaced.
#![no_main]

use libfuzzer_sys::fuzz_target;
use owt_auth::password::needs_rehash;

fuzz_target!(|stored: &str| {
    let rehash = needs_rehash(stored);
    if !stored.starts_with("$argon2id$") {
        assert!(rehash, "{stored:?} was accepted as current");
    }
});
