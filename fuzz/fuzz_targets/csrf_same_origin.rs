//! `CrossOrigin::same_origin` over arbitrary header bytes and trusted origins.
//! Invariants: it never panics; a request labelled `cross-site` by the browser never
//! passes unless its Origin is trusted; an Origin with no Host to match passes only
//! when trusted; an unreadable Origin or Sec-Fetch-Site never passes.
#![no_main]

use arbitrary::Arbitrary;
use axum::http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use owt_web::csrf::CrossOrigin;

#[derive(Arbitrary, Debug)]
struct Input {
    origin: Option<Vec<u8>>,
    site: Option<Vec<u8>>,
    host: Option<Vec<u8>>,
    trusted: Vec<String>,
}

fn header(map: &mut HeaderMap, name: &'static str, v: &Option<Vec<u8>>) -> bool {
    let Some(v) = v else { return false };
    match HeaderValue::from_bytes(v) {
        Ok(h) => {
            map.insert(name, h);
            true
        }
        Err(_) => false,
    }
}

fuzz_target!(|input: Input| {
    let mut headers = HeaderMap::new();
    header(&mut headers, "origin", &input.origin);
    header(&mut headers, "sec-fetch-site", &input.site);
    header(&mut headers, "host", &input.host);
    let trusted: Vec<&str> = input.trusted.iter().map(String::as_str).take(4).collect();
    let check = CrossOrigin::new().trust(trusted.iter().copied());
    let result = check.same_origin(&headers);

    let origin_trusted = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| {
            let o = o.trim_end_matches('/');
            trusted.iter().any(|t| {
                let t = t.trim().trim_end_matches('/');
                !t.is_empty() && t == o
            })
        });
    if headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") {
        assert!(result.is_err() || origin_trusted, "cross-site passed: {input:?}");
    }
    // A readable Origin with no Host to compare against passes only when trusted.
    if headers.get("sec-fetch-site").is_none()
        && headers.get("origin").is_some_and(|v| v.to_str().is_ok())
        && headers.get("host").is_none()
    {
        assert!(result.is_err() || origin_trusted, "origin without host passed: {input:?}");
    }
    // An unreadable Origin or Sec-Fetch-Site never passes (it is not an absent one).
    if headers.get("origin").is_some_and(|v| v.to_str().is_err())
        || headers.get("sec-fetch-site").is_some_and(|v| v.to_str().is_err())
    {
        assert!(result.is_err(), "unreadable header passed: {input:?}");
    }
});
