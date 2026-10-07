//! `Sessions::unseal` over arbitrary cookie values: never panics, never opens.
#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use owt_web::session::{Sessions, key_from_base64};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Data {
    user: Option<i64>,
}

fuzz_target!(|value: &str| {
    // A fixed key: the fuzzer may learn the format, never the key.
    let key = key_from_base64("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==").unwrap();
    let s: Sessions<Data> = Sessions::new(key, "sid", Duration::from_secs(3600), true);
    assert!(s.unseal(value).is_none(), "an arbitrary value opened: {value:?}");
});
