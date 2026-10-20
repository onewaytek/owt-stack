//! The debug line `ClientIp::of` writes. This test is the only one in its binary:
//! tracing caches, per callsite, whether any subscriber is interested, and a
//! concurrent test calling `ClientIp::of` with no subscriber installed could cache
//! "not interested" before this test's thread-scoped subscriber is seen. Alone in
//! its process, nothing else reaches the callsite.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request};
use owt_web::client_ip::{ClientIp, Source};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 128, 0, 2));

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_choice_is_logged_at_debug() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut req = Request::new(());
        for v in ["1.1.1.1, \"x\", 203.0.113.9", "198.51.100.7"] {
            req.headers_mut()
                .append("x-forwarded-for", HeaderValue::from_static(v));
        }
        req.headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.20"));
        req.extensions_mut()
            .insert(Source::ForwardedFor { proxies: 1 });
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(PEER, 40_000)));
        let p = req.into_parts().0;
        assert_eq!(ClientIp::of(&p), Some("198.51.100.7".parse().unwrap()));
    });
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("DEBUG"), "{out}");
    assert!(out.contains("source=forwarded-for:1"), "{out}");
    // Quoted, with the client's own quote escaped: a value cannot pass for a field.
    assert!(
        out.contains(r#"["1.1.1.1, \"x\", 203.0.113.9", "198.51.100.7"]"#),
        "{out}"
    );
    assert!(out.contains(&format!("peer={PEER}")), "{out}");
    assert!(out.contains("chosen=198.51.100.7"), "{out}");
}
