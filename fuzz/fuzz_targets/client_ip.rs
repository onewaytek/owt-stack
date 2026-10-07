//! `Source::client_ip` over arbitrary `X-Forwarded-For` lines. Invariants: never
//! panics; with one trusted proxy the answer is the last entry if it is an address,
//! else the peer; the client's own entries never move the answer.
#![no_main]

use std::net::IpAddr;

use arbitrary::Arbitrary;
use axum::http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use owt_web::client_ip::Source;

#[derive(Arbitrary, Debug)]
struct Input {
    client_line: Vec<u8>,
    proxy_entry: Vec<u8>,
    second_header: bool,
    proxies: u8,
    peer: [u8; 4],
}

fuzz_target!(|input: Input| {
    let peer = IpAddr::from(input.peer);
    let mut headers = HeaderMap::new();
    // A proxy appends ", <entry>" to the client's line, or adds a second header.
    let appended = if input.second_header {
        input.client_line.clone()
    } else {
        let mut l = input.client_line.clone();
        l.extend_from_slice(b", ");
        l.extend_from_slice(&input.proxy_entry);
        l
    };
    let Ok(first) = HeaderValue::from_bytes(&appended) else { return };
    headers.append("x-forwarded-for", first);
    if input.second_header {
        let Ok(second) = HeaderValue::from_bytes(&input.proxy_entry) else { return };
        headers.append("x-forwarded-for", second);
    }
    let one = Source::ForwardedFor { proxies: 1 };
    let got = one.client_ip(&headers, peer);
    let expected = std::str::from_utf8(&input.proxy_entry)
        .ok()
        .and_then(|e| e.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer);
    if !input.proxy_entry.contains(&b',') {
        assert_eq!(got, expected, "{input:?}");
    }
    // More proxies than entries: the peer.
    let many = Source::ForwardedFor { proxies: usize::from(input.proxies).max(1) + 64 };
    assert_eq!(many.client_ip(&headers, peer), peer);
    let _ = Source::Peer.client_ip(&headers, peer);
    let _ = Source::Header("cf-connecting-ip".into()).client_ip(&headers, peer);
});
