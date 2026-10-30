//! The canonical encoding an event's hash covers.
//!
//! `hash = SHA-256(DOMAIN || encoding)`, where the encoding is every field of the
//! recorded event but its hash, in this order:
//!
//! | field | encoding |
//! |---|---|
//! | tenant (`""` for none) | text |
//! | seq | 8 bytes, big-endian, signed |
//! | at | microseconds since the UNIX epoch, 8 bytes, big-endian, signed |
//! | actor, actor kind, subject, action, resource type, resource id, purpose, outcome | text, or absent |
//! | ip (as Rust's `IpAddr` displays it) | text, or absent |
//! | user agent, request id | text, or absent |
//! | prev | 32 bytes |
//!
//! Text is its UTF-8 bytes after a 4-byte big-endian length; absent is the length
//! `0xFFFF_FFFF` alone, so `None` and `Some("")` differ and no field can run into
//! the next. Kinds and outcomes are their stored forms (`account`, `success`). Any
//! change to this encoding is a new domain string, and the verifier keeps the old.

use sha2::{Digest, Sha256};

use crate::{Hash, Recorded, micros};

/// The prefix of every hashed encoding.
pub const DOMAIN: &[u8] = b"owt-audit/event/v1\0";

/// The encoding of `r`, without [`DOMAIN`].
#[must_use]
pub fn encode(r: &Recorded) -> Vec<u8> {
    let e = &r.event;
    let mut out = Vec::with_capacity(256);
    text(&mut out, Some(e.tenant.as_deref().unwrap_or("")));
    out.extend_from_slice(&r.seq.to_be_bytes());
    out.extend_from_slice(&micros(r.at).to_be_bytes());
    text(&mut out, Some(&e.actor));
    text(&mut out, Some(e.actor_kind.as_str()));
    text(&mut out, e.subject.as_deref());
    text(&mut out, Some(&e.action));
    text(&mut out, Some(&e.resource_type));
    text(&mut out, e.resource_id.as_deref());
    text(&mut out, e.purpose.as_deref());
    text(&mut out, Some(e.outcome.as_str()));
    text(&mut out, e.ip.map(|ip| ip.to_string()).as_deref());
    text(&mut out, e.user_agent.as_deref());
    text(&mut out, e.request_id.as_deref());
    out.extend_from_slice(&r.prev);
    out
}

/// The hash of `r`.
#[must_use]
pub fn hash(r: &Recorded) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(encode(r));
    h.finalize().into()
}

fn text(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            // Fields are at most 512 characters, so the length always fits.
            let n = u32::try_from(s.len()).unwrap_or(u32::MAX - 1);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        None => out.extend_from_slice(&u32::MAX.to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::{ActorKind, Event, GENESIS};

    fn sample() -> Recorded {
        Recorded {
            event: Event::new(ActorKind::Account, "17", "record.view", "chart")
                .tenant("t1")
                .subject("patient:42")
                .client(
                    Some("192.0.2.7".parse().unwrap()),
                    Some("ua"),
                    Some("req-1"),
                ),
            seq: 1,
            at: UNIX_EPOCH + Duration::from_micros(1_761_000_000_000_001),
            prev: GENESIS,
            hash: GENESIS,
        }
    }

    /// The encoding is a stored format: this pins it (the value was checked against
    /// an independent implementation of the table above).
    #[test]
    fn the_encoding_is_pinned() {
        assert_eq!(
            crate::hex(&hash(&sample())),
            "be9ffc802d81d14a2196dba2824333fab0ea50f9d15131fe0fbb651203f9eb74"
        );
    }

    #[test]
    fn none_and_empty_differ_and_fields_do_not_run_together() {
        let a = sample();
        let mut b = sample();
        b.event.resource_id = Some(String::new());
        assert_ne!(hash(&a), hash(&b));
        let mut c = sample();
        c.event.actor = "1".into();
        c.event.tenant = Some("t17".into());
        let mut d = sample();
        d.event.actor = "71".into();
        d.event.tenant = Some("t1".into());
        assert_ne!(hash(&c), hash(&d));
    }

    type Edit = Box<dyn Fn(&mut Recorded)>;

    #[test]
    fn every_field_counts() {
        let base = hash(&sample());
        let edits: Vec<Edit> = vec![
            Box::new(|r| r.seq = 2),
            Box::new(|r| r.at += Duration::from_micros(1)),
            Box::new(|r| r.prev[31] = 1),
            Box::new(|r| r.event.tenant = None),
            Box::new(|r| r.event.actor_kind = ActorKind::Service),
            Box::new(|r| r.event.subject = None),
            Box::new(|r| r.event.purpose = Some("treatment".into())),
            Box::new(|r| r.event.outcome = crate::Outcome::Denied),
            Box::new(|r| r.event.ip = Some("192.0.2.8".parse().unwrap())),
            Box::new(|r| r.event.user_agent = None),
            Box::new(|r| r.event.request_id = Some("req-2".into())),
            Box::new(|r| r.event.action = "record.edit".into()),
            Box::new(|r| r.event.resource_type = "note".into()),
        ];
        for edit in edits {
            let mut r = sample();
            edit(&mut r);
            assert_ne!(hash(&r), base);
        }
    }
}
