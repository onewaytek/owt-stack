//! Walking chains, and checking them against anchored heads.

use futures::TryStreamExt;
use sqlx::PgPool;

use crate::anchor::Manifest;
use crate::{ActorKind, Event, GENESIS, Outcome, Recorded, from_micros, to_hash};

/// The last event of a chain.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Head {
    /// The tenant (`""` for events with none).
    pub tenant: String,
    /// The event's position.
    pub seq: i64,
    /// Its hash, as lowercase hex.
    pub hash: String,
}

/// A chain that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Events checked.
    pub events: u64,
    /// The chain's head; `None` for a chain with no events.
    pub head: Option<Head>,
}

/// Where and why verification failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Broken {
    /// An event is missing: the chain jumps from `expected - 1` to `found`.
    #[error("chain {tenant:?}: event {expected} is missing (found {found})")]
    Gap {
        /// The chain.
        tenant: String,
        /// The position expected.
        expected: i64,
        /// The position found.
        found: i64,
    },
    /// An event's `prev` is not its predecessor's hash: one of them was replaced.
    #[error("chain {tenant:?}: event {seq} does not link to the event before it")]
    Link {
        /// The chain.
        tenant: String,
        /// The event.
        seq: i64,
    },
    /// An event's fields do not give its hash: it was edited.
    #[error("chain {tenant:?}: event {seq} does not match its hash")]
    Hash {
        /// The chain.
        tenant: String,
        /// The event.
        seq: i64,
    },
    /// An event holds a value no recorded event can.
    #[error("chain {tenant:?}: event {seq} has an unreadable `{field}`")]
    Unreadable {
        /// The chain.
        tenant: String,
        /// The event.
        seq: i64,
        /// The field.
        field: &'static str,
    },
    /// An anchored head is not in the chain, or the chain's event there differs.
    #[error("chain {tenant:?}: event {seq} is not the event anchored")]
    Anchor {
        /// The chain.
        tenant: String,
        /// The anchored position.
        seq: i64,
    },
}

/// Why [`verify`] or [`verify_anchor`] failed.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The chain is broken.
    #[error(transparent)]
    Broken(#[from] Broken),
    /// The database.
    #[error("reading the audit chain: {0}")]
    Db(#[from] sqlx::Error),
}

type Row = (
    String,
    i64,
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<u8>,
    Vec<u8>,
);

/// Walk `tenant`'s chain (`""` for events with no tenant) from its first event,
/// recomputing each hash and link.
pub async fn verify(pool: &PgPool, tenant: &str) -> Result<Verified, VerifyError> {
    let mut rows = sqlx::query_as::<_, Row>(
        "SELECT tenant, seq, (extract(epoch FROM at) * 1000000)::int8, actor, actor_kind,
                subject, action, resource_type, resource_id, purpose, outcome, ip, user_agent,
                request_id, prev, hash
         FROM owt_audit_events WHERE tenant = $1 ORDER BY seq",
    )
    .bind(tenant)
    .fetch(pool);
    let mut expected = 1_i64;
    let mut prev = GENESIS;
    let mut head = None;
    while let Some(row) = rows.try_next().await? {
        let r = decode(row)?;
        let seq = r.seq;
        if seq != expected {
            return Err(Broken::Gap {
                tenant: tenant.into(),
                expected,
                found: seq,
            }
            .into());
        }
        if r.prev != prev {
            return Err(Broken::Link {
                tenant: tenant.into(),
                seq,
            }
            .into());
        }
        if r.computed_hash() != r.hash {
            return Err(Broken::Hash {
                tenant: tenant.into(),
                seq,
            }
            .into());
        }
        prev = r.hash;
        expected += 1;
        head = Some(Head {
            tenant: tenant.into(),
            seq,
            hash: crate::hex(&r.hash),
        });
    }
    Ok(Verified {
        events: u64::try_from(expected - 1).unwrap_or(0),
        head,
    })
}

/// Every chain's head, by tenant.
pub async fn heads(pool: &PgPool) -> sqlx::Result<Vec<Head>> {
    // A loose index scan over the primary key: one probe per tenant, not a pass over
    // every event.
    let rows: Vec<(String, i64, Vec<u8>)> = sqlx::query_as(
        "WITH RECURSIVE t(tenant) AS (
             (SELECT tenant FROM owt_audit_events ORDER BY tenant LIMIT 1)
             UNION ALL
             SELECT (SELECT e.tenant FROM owt_audit_events e WHERE e.tenant > t.tenant
                     ORDER BY e.tenant LIMIT 1)
             FROM t WHERE t.tenant IS NOT NULL)
         SELECT t.tenant, h.seq, h.hash FROM t
         CROSS JOIN LATERAL (SELECT seq, hash FROM owt_audit_events e
                             WHERE e.tenant = t.tenant ORDER BY seq DESC LIMIT 1) h
         WHERE t.tenant IS NOT NULL
         ORDER BY t.tenant",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(tenant, seq, hash)| Head {
            tenant,
            seq,
            hash: crate::hex(&hash),
        })
        .collect())
}

/// Check that every head `manifest` anchored is still in its chain, unchanged. With
/// [`verify`] of each chain, this shows the chains were only appended to since.
pub async fn verify_anchor(pool: &PgPool, manifest: &Manifest) -> Result<(), VerifyError> {
    for head in &manifest.heads {
        let hash: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM owt_audit_events WHERE tenant = $1 AND seq = $2")
                .bind(&head.tenant)
                .bind(head.seq)
                .fetch_optional(pool)
                .await?;
        if hash.map(|h| crate::hex(&h)).as_deref() != Some(head.hash.as_str()) {
            return Err(Broken::Anchor {
                tenant: head.tenant.clone(),
                seq: head.seq,
            }
            .into());
        }
    }
    Ok(())
}

fn decode(row: Row) -> Result<Recorded, Broken> {
    let (tenant, seq, at, actor, kind, subject, action, resource_type, resource_id, purpose) = (
        row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9,
    );
    let (outcome, ip, user_agent, request_id, prev, hash) =
        (row.10, row.11, row.12, row.13, row.14, row.15);
    let bad = |field| Broken::Unreadable {
        tenant: tenant.clone(),
        seq,
        field,
    };
    let actor_kind = ActorKind::parse(&kind).ok_or_else(|| bad("actor_kind"))?;
    let outcome = Outcome::parse(&outcome).ok_or_else(|| bad("outcome"))?;
    let ip = match ip {
        Some(ip) => {
            let parsed: std::net::IpAddr = ip.parse().map_err(|_| bad("ip"))?;
            // Stored as Rust displays it, or the hash would not cover what is shown.
            if parsed.to_string() != ip {
                return Err(bad("ip"));
            }
            Some(parsed)
        }
        None => None,
    };
    let prev = to_hash(&prev).ok_or_else(|| bad("prev"))?;
    let hash = to_hash(&hash).ok_or_else(|| bad("hash"))?;
    Ok(Recorded {
        event: Event {
            actor,
            actor_kind,
            tenant: (!tenant.is_empty()).then(|| tenant.clone()),
            subject,
            action,
            resource_type,
            resource_id,
            purpose,
            outcome,
            ip,
            user_agent,
            request_id,
        },
        seq,
        at: from_micros(at),
        prev,
        hash,
    })
}
