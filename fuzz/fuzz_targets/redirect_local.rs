//! `redirect::local` over arbitrary `?next=` values: whatever it accepts is a path on
//! this site as a browser reads it, parsed against the site's own URL.
#![no_main]

use libfuzzer_sys::fuzz_target;
use owt_web::redirect::local;

fuzz_target!(|next: &str| {
    let Some(ok) = local(next) else { return };
    let base = url::Url::parse("https://this.example/sign-in").unwrap();
    let resolved = base.join(ok).expect("an accepted path resolves");
    assert_eq!(resolved.host_str(), Some("this.example"), "{next:?} -> {resolved}");
    assert_eq!(resolved.scheme(), "https", "{next:?} -> {resolved}");
});
