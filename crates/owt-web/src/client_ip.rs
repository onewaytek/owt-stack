//! The client's address, behind proxies.
//!
//! The socket's peer is the last proxy, not the client, and the headers that name
//! the client are the client's to forge unless a proxy this app trusts wrote them. So
//! which one to believe is configuration, never a guess: [`Source`] says how the app
//! is deployed, and anything that does not parse falls back to the peer.
//!
//! Rate limits keyed on the wrong address either lump everyone together (the proxy's)
//! or let an attacker pick a fresh key per request (a forged header).
//!
//! An app reads its [`Source`] once ([`Source::from_env`]), adds it to every request
//! as an `Extension`, serves with `into_make_service_with_connect_info::<SocketAddr>()`,
//! and takes [`ClientIp`] in a handler:
//!
//! ```
//! use axum::{Extension, Router, routing::get};
//! use owt_web::client_ip::{ClientIp, Source};
//!
//! async fn hello(ClientIp(ip): ClientIp) -> String { ip.to_string() }
//!
//! let source: Source = "forwarded-for:1".parse().unwrap();
//! let app: Router = Router::new().route("/", get(hello)).layer(Extension(source));
//! ```

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};

/// Where the client's address is. A source may be added without a breaking release (the
/// `Forwarded` header, say), so a `match` on it ends with a `_` arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// The socket's peer: nothing is in front of the app.
    Peer,
    /// A header one trusted proxy sets to exactly the client's address, replacing
    /// whatever the client sent (`CF-Connecting-IP` behind Cloudflare). Only when
    /// nothing can reach the app except through that proxy.
    Header(String),
    /// `X-Forwarded-For`, counting from the right: with `proxies` trusted proxies in
    /// front of the app, each appending the address it saw, the client is the entry
    /// that many from the end. Entries further left are the client's own claims.
    /// (One for the `OpenShift` router alone.)
    ForwardedFor {
        /// How many trusted proxies append to the header; at least 1.
        proxies: usize,
    },
}

/// A [`Source`] that does not parse, naming the grammar.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "a client address source is forwarded-for:N (N at least 1), header:NAME or peer, not {0:?}"
)]
pub struct BadSource(pub String);

impl FromStr for Source {
    type Err = BadSource;

    /// `peer`, `forwarded-for:N` (N trusted proxies append to `X-Forwarded-For`, at
    /// least 1) or `header:NAME` (one trusted proxy's header), as `CLIENT_IP` holds it.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || BadSource(s.to_owned());
        let v = s.trim();
        if v == "peer" {
            return Ok(Self::Peer);
        }
        if let Some(n) = v.strip_prefix("forwarded-for:") {
            let proxies: usize = n.trim().parse().map_err(|_| bad())?;
            return if proxies >= 1 {
                Ok(Self::ForwardedFor { proxies })
            } else {
                Err(bad())
            };
        }
        match v.strip_prefix("header:").map(str::trim) {
            Some(name) if axum::http::HeaderName::from_bytes(name.as_bytes()).is_ok() => {
                Ok(Self::Header(name.to_ascii_lowercase()))
            }
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for Source {
    /// As [`FromStr`] reads it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer => f.write_str("peer"),
            Self::Header(name) => write!(f, "header:{name}"),
            Self::ForwardedFor { proxies } => write!(f, "forwarded-for:{proxies}"),
        }
    }
}

impl Source {
    /// How the app is deployed, from the environment: `CLIENT_IP` (`forwarded-for:N`,
    /// `header:NAME` or `peer`), else `TRUSTED_PROXIES` (a count: `0` is `peer`, `N`
    /// is `forwarded-for:N`), else `peer`. Behind the `OpenShift` router alone it is
    /// `forwarded-for:1`; the peer is never forged, but behind a proxy it is the
    /// proxy, and every client shares one rate limit. A blank variable is unset.
    ///
    /// # Errors
    ///
    /// A variable that is set and does not parse, named.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// [`from_env`](Self::from_env), reading variables through `var`.
    ///
    /// # Errors
    ///
    /// As [`from_env`](Self::from_env).
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let set = |name: &str| var(name).filter(|v| !v.trim().is_empty());
        if let Some(v) = set("CLIENT_IP") {
            return v.parse().map_err(|e| anyhow::anyhow!("CLIENT_IP: {e}"));
        }
        if let Some(v) = set("TRUSTED_PROXIES") {
            let proxies: usize = v.trim().parse().map_err(|_| {
                anyhow::anyhow!("TRUSTED_PROXIES is a count of proxies: 0 for none")
            })?;
            return Ok(match proxies {
                0 => Self::Peer,
                proxies => Self::ForwardedFor { proxies },
            });
        }
        Ok(Self::Peer)
    }

    /// The header values this source reads, in order: none for the peer.
    fn weighed<'h>(&self, headers: &'h HeaderMap) -> Vec<&'h HeaderValue> {
        match self {
            Self::Peer => Vec::new(),
            Self::Header(name) => headers.get_all(name.as_str()).iter().collect(),
            Self::ForwardedFor { .. } => headers.get_all("x-forwarded-for").iter().collect(),
        }
    }

    /// The client's address for a request with these headers from this peer.
    #[must_use]
    pub fn client_ip(&self, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
        let found = match self {
            Self::Peer => None,
            Self::Header(name) => headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok()),
            Self::ForwardedFor { proxies } => {
                // Several headers are one list, in order. Split as bytes: a proxy
                // may append to the line the client sent, and bytes there that are
                // not text must not hide the entry the proxy added.
                let entries: Vec<&[u8]> = headers
                    .get_all("x-forwarded-for")
                    .iter()
                    .flat_map(|v| v.as_bytes().split(|b| *b == b','))
                    .collect();
                entries
                    .len()
                    .checked_sub((*proxies).max(1))
                    .and_then(|i| std::str::from_utf8(entries[i]).ok())
                    .and_then(|entry| entry.trim().parse().ok())
            }
        };
        found.unwrap_or(peer)
    }
}

/// The client's address, as the request's [`Source`] says to read it: the extractor.
///
/// The `Source` is the request's `Extension` (the [`Peer`](Source::Peer) when none
/// was added) and the peer is axum's `ConnectInfo<SocketAddr>`, or the address of a
/// `MockConnectInfo<SocketAddr>` layer in a test. Without either (an app served
/// without `into_make_service_with_connect_info`, or a bare `oneshot`), a header
/// the source names still answers, and otherwise the request fails with a 500 and a
/// logged error: guessing would key every client's rate limit alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    /// The client's address for `parts`, as the extractor reads it; `None` when it
    /// cannot say (no peer, and no header the source believes).
    ///
    /// Each call logs a `debug` event (target `owt_web::client_ip`) naming the source,
    /// the header values it weighed, the peer and the address chosen: what an app
    /// confirms its `CLIENT_IP` setting against real proxies with. The values are the
    /// client's to forge, so they appear quoted, and only at `debug`.
    #[must_use]
    pub fn of(parts: &Parts) -> Option<IpAddr> {
        // axum's own `ConnectInfo` extractor falls back to `MockConnectInfo` the same
        // way, so a router tested with that layer has a peer here too.
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .or_else(|| {
                parts
                    .extensions
                    .get::<MockConnectInfo<SocketAddr>>()
                    .map(|m| m.0.ip())
            });
        let source = parts.extensions.get::<Source>().unwrap_or(&Source::Peer);
        // A stand-in peer no header parses to tells "the header answered" apart.
        let unspecified = IpAddr::from([0, 0, 0, 0]);
        let found = source.client_ip(&parts.headers, peer.unwrap_or(unspecified));
        let chosen = if found == unspecified {
            peer
        } else {
            Some(found)
        };
        tracing::debug!(
            source = %source,
            weighed = ?source.weighed(&parts.headers),
            peer = peer.map(tracing::field::display),
            chosen = chosen.map(tracing::field::display),
            "client address"
        );
        chosen
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = crate::Error;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::of(parts).map(Self).ok_or_else(|| {
            crate::Error::Internal(anyhow::anyhow!(
                "no client address: serve with into_make_service_with_connect_info::<SocketAddr>()"
            ))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 128, 0, 2));

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forged_entries_to_the_left_are_not_believed() {
        let one = Source::ForwardedFor { proxies: 1 };
        // The client sent "1.1.1.1"; the router appended what it saw.
        let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.9")]);
        assert_eq!(one.client_ip(&h, PEER), ip("203.0.113.9"));
        let two = Source::ForwardedFor { proxies: 2 };
        let h = headers(&[
            ("x-forwarded-for", "1.1.1.1, 203.0.113.9"),
            ("x-forwarded-for", "198.51.100.7"),
        ]);
        assert_eq!(two.client_ip(&h, PEER), ip("203.0.113.9"));
        // Fewer entries than proxies, or garbage: the peer.
        assert_eq!(
            two.client_ip(&headers(&[("x-forwarded-for", "1.1.1.1")]), PEER),
            PEER
        );
        assert_eq!(
            one.client_ip(&headers(&[("x-forwarded-for", "unknown")]), PEER),
            PEER
        );
        assert_eq!(one.client_ip(&headers(&[]), PEER), PEER);
    }

    #[test]
    fn a_named_header_or_the_peer() {
        let h = headers(&[
            ("cf-connecting-ip", " 2001:db8::1 "),
            ("x-forwarded-for", "1.1.1.1"),
        ]);
        let cf = Source::Header("cf-connecting-ip".into());
        assert_eq!(cf.client_ip(&h, PEER), ip("2001:db8::1"));
        assert_eq!(cf.client_ip(&headers(&[]), PEER), PEER);
        assert_eq!(Source::Peer.client_ip(&h, PEER), PEER);
    }

    #[test]
    fn the_environment_names_the_source() {
        let from = |pairs: &[(&str, &str)]| {
            let map: std::collections::HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            Source::from_vars(move |n| map.get(n).cloned())
        };
        assert_eq!(from(&[]).unwrap(), Source::Peer);
        assert_eq!(
            from(&[("CLIENT_IP", "forwarded-for:2")]).unwrap(),
            Source::ForwardedFor { proxies: 2 }
        );
        assert_eq!(
            from(&[("CLIENT_IP", " header:CF-Connecting-IP ")]).unwrap(),
            Source::Header("cf-connecting-ip".into())
        );
        assert_eq!(from(&[("CLIENT_IP", "peer")]).unwrap(), Source::Peer);
        assert_eq!(from(&[("TRUSTED_PROXIES", "0")]).unwrap(), Source::Peer);
        assert_eq!(
            from(&[("TRUSTED_PROXIES", "1")]).unwrap(),
            Source::ForwardedFor { proxies: 1 }
        );
        assert_eq!(
            from(&[("CLIENT_IP", "peer"), ("TRUSTED_PROXIES", "3")]).unwrap(),
            Source::Peer,
            "CLIENT_IP wins"
        );
        assert_eq!(
            from(&[("CLIENT_IP", " "), ("TRUSTED_PROXIES", "1")]).unwrap(),
            Source::ForwardedFor { proxies: 1 },
            "blank is unset"
        );
        for bad in [
            "forwarded-for:0",
            "forwarded-for:x",
            "header:",
            "header:a b",
            "xff",
        ] {
            let e = from(&[("CLIENT_IP", bad)]).unwrap_err().to_string();
            assert!(e.starts_with("CLIENT_IP:"), "{bad}: {e}");
        }
        assert!(from(&[("TRUSTED_PROXIES", "-1")]).is_err());
        for s in [
            Source::Peer,
            Source::Header("x-real-ip".into()),
            Source::ForwardedFor { proxies: 2 },
        ] {
            assert_eq!(s.to_string().parse::<Source>().unwrap(), s);
        }
    }

    fn parts(source: Option<Source>, peer: Option<IpAddr>, xff: &[&'static str]) -> Parts {
        let mut req = axum::http::Request::new(());
        for v in xff {
            req.headers_mut()
                .append("x-forwarded-for", HeaderValue::from_static(v));
        }
        req.headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.20"));
        if let Some(s) = source {
            req.extensions_mut().insert(s);
        }
        if let Some(p) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(p, 40_000)));
        }
        req.into_parts().0
    }

    #[tokio::test]
    async fn the_extractor_reads_the_requests_source() {
        let three = ["1.1.1.1, 203.0.113.9, 198.51.100.7"];
        let get = |p: Parts| async move {
            let mut p = p;
            ClientIp::from_request_parts(&mut p, &()).await.map(|c| c.0)
        };
        let one = Source::ForwardedFor { proxies: 1 };
        let two = Source::ForwardedFor { proxies: 2 };
        assert_eq!(
            get(parts(Some(one), Some(PEER), &three)).await.unwrap(),
            ip("198.51.100.7")
        );
        assert_eq!(
            get(parts(Some(two), Some(PEER), &three)).await.unwrap(),
            ip("203.0.113.9")
        );
        let header = Source::Header("x-real-ip".into());
        assert_eq!(
            get(parts(Some(header.clone()), Some(PEER), &three))
                .await
                .unwrap(),
            ip("198.51.100.20")
        );
        // A header answers without a peer.
        assert_eq!(
            get(parts(Some(header), None, &[])).await.unwrap(),
            ip("198.51.100.20")
        );
        // The peer ignores every header; no source is the peer.
        assert_eq!(
            get(parts(Some(Source::Peer), Some(PEER), &three))
                .await
                .unwrap(),
            PEER
        );
        assert_eq!(get(parts(None, Some(PEER), &three)).await.unwrap(), PEER);
        // Nothing to go on: a 500, never a guess.
        let e = get(parts(None, None, &three)).await.unwrap_err();
        assert!(matches!(e, crate::Error::Internal(_)), "{e:?}");
        let e = get(parts(
            Some(Source::ForwardedFor { proxies: 1 }),
            None,
            &["garbage"],
        ))
        .await
        .unwrap_err();
        assert!(matches!(e, crate::Error::Internal(_)), "{e:?}");
    }

    #[tokio::test]
    async fn a_mock_connect_info_layer_is_the_peer() {
        use axum::{Router, routing::get};
        use tower::ServiceExt;
        let app = Router::new()
            .route(
                "/",
                get(|ClientIp(ip): ClientIp| async move { ip.to_string() }),
            )
            .layer(MockConnectInfo(SocketAddr::new(PEER, 40_000)));
        let res = app
            .oneshot(axum::http::Request::new(axum::body::Body::empty()))
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap();
        assert_eq!(body.to_bytes(), PEER.to_string());
    }

    #[test]
    fn the_choice_is_logged_at_debug() {
        use std::sync::{Arc, Mutex};
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
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let p = parts(
                Some(Source::ForwardedFor { proxies: 1 }),
                Some(PEER),
                &["1.1.1.1, \"x\", 203.0.113.9", "198.51.100.7"],
            );
            assert_eq!(ClientIp::of(&p), Some(ip("198.51.100.7")));
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
}
