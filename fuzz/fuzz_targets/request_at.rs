//! `RequestInfo::at` and its query helpers over arbitrary URIs: never panic, and a
//! path never begins with `//` (a browser would read it as another host).
#![no_main]

use libfuzzer_sys::fuzz_target;
use owt_web::request::RequestInfo;

fuzz_target!(|input: (&str, &str, Option<&str>)| {
    let (uri, key, value) = input;
    let info = RequestInfo::at(uri);
    assert!(!info.path.starts_with("//"), "{uri:?} -> {:?}", info.path);
    assert!(!info.full_path.starts_with("//"), "{uri:?} -> {:?}", info.full_path);
    let _ = info.query_value(key);
    let with = info.query_with(key, value);
    assert!(with.starts_with('?'), "{uri:?} -> {with:?}");
    let link = info.url_with(key, value);
    assert!(!link.starts_with("//"), "{uri:?} -> {link:?}");
    let page = info.for_page(key);
    assert!(!page.path.starts_with("//"), "{key:?} -> {:?}", page.path);
    assert_eq!(page.query, info.query);
    let _ = info.is_under(key);
});
