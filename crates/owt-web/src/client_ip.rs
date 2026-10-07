//! The client's address, behind proxies.
//!
//! The socket's peer is the last proxy, not the client, and the headers that name
//! the client are the client's to forge unless a proxy this app trusts wrote them. So
//! which one to believe is configuration, never a guess: [`Source`] says how the app
//! is deployed, and anything that does not parse falls back to the peer.
//!
//! Rate limits keyed on the wrong address either lump everyone together (the proxy's)
//! or let an attacker pick a fresh key per request (a forged header).

use std::net::IpAddr;

use axum::http::HeaderMap;

/// Where the client's address is.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl Source {
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

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

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
}
