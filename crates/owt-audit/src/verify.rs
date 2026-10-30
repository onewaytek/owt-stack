//! Walking chains, and checking them against anchored heads.

use futures::TryStreamExt;
use sqlx::PgPool;

use crate::anchor::Manifest;
use crate::{GENESIS, Hash};

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
    /// A manifest that is not one, or whose recorded digest does not match it.
    #[error("audit manifest: {0}")]
    Manifest(String),
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
    walk(pool, tenant, 0, GENESIS).await
}

/// Walk `tenant`'s chain from the event after `seq`, whose hash must be `hash` (an
/// anchored head): the events since an anchor, without re-reading those before it.
pub async fn verify_since(
    pool: &PgPool,
    tenant: &str,
    seq: i64,
    hash: &Hash,
) -> Result<Verified, VerifyError> {
    if seq > 0 {
        let at: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM owt_audit_events WHERE tenant = $1 AND seq = $2")
                .bind(tenant)
                .bind(seq)
                .fetch_optional(pool)
                .await?;
        if at.as_deref() != Some(&hash[..]) {
            return Err(Broken::Anchor {
                tenant: tenant.into(),
                seq,
            }
            .into());
        }
    }
    walk(pool, tenant, seq, *hash).await
}

async fn walk(
    pool: &PgPool,
    tenant: &str,
    after: i64,
    start: Hash,
) -> Result<Verified, VerifyError> {
    let mut rows = sqlx::query_as::<_, Row>(
        "SELECT tenant, seq, (extract(epoch FROM at) * 1000000)::int8, actor, actor_kind,
                subject, action, resource_type, resource_id, purpose, outcome, ip, user_agent,
                request_id, prev, hash
         FROM owt_audit_events WHERE tenant = $1 AND seq > $2 ORDER BY seq",
    )
    .bind(tenant)
    .bind(after)
    .fetch(pool);
    let mut expected = after + 1;
    let mut prev = start;
    let mut head = None;
    while let Some(row) = rows.try_next().await? {
        let seq = row.1;
        let broken =
            |kind: fn(String, i64) -> Broken| -> VerifyError { kind(tenant.into(), seq).into() };
        if seq != expected {
            return Err(Broken::Gap {
                tenant: tenant.into(),
                expected,
                found: seq,
            }
            .into());
        }
        if row.14 != prev {
            return Err(broken(|tenant, seq| Broken::Link { tenant, seq }));
        }
        let computed = crate::canonical::hash_raw(&crate::canonical::Raw {
            tenant: &row.0,
            seq,
            at_us: row.2,
            actor: &row.3,
            actor_kind: &row.4,
            subject: row.5.as_deref(),
            action: &row.6,
            resource_type: &row.7,
            resource_id: row.8.as_deref(),
            purpose: row.9.as_deref(),
            outcome: &row.10,
            ip: row.11.as_deref(),
            user_agent: row.12.as_deref(),
            request_id: row.13.as_deref(),
            prev: &row.14,
        });
        if row.15 != computed {
            return Err(broken(|tenant, seq| Broken::Hash { tenant, seq }));
        }
        prev = computed;
        expected += 1;
        head = Some(Head {
            tenant: tenant.into(),
            seq,
            hash: crate::hex(&computed),
        });
    }
    Ok(Verified {
        events: u64::try_from(expected - 1 - after).unwrap_or(0),
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
/// [`verify`] of each chain, this shows the chains were only appended to since. A
/// manifest of another format is refused.
pub async fn verify_anchor(pool: &PgPool, manifest: &Manifest) -> Result<(), VerifyError> {
    if manifest.format != crate::anchor::FORMAT {
        return Err(VerifyError::Manifest("not an owt-audit manifest".into()));
    }
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
