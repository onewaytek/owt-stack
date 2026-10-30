//! Anchoring the chains' heads to external write-once storage.
//!
//! The database's owner can drop the append-only triggers and rewrite a chain from
//! some event on, recomputing every hash after it: the chain still verifies on its
//! own. What it cannot rewrite is a copy of the heads held where it has no write
//! access. [`anchor`] builds a [`Manifest`] of every chain's head, hands it to an
//! [`Anchor`] (an object store bucket under a compliance-mode retention lock, say),
//! and records it, with the store's receipt, in `owt_audit_anchors`. Each manifest
//! names the previous one's digest, so the anchors form a chain of their own.
//!
//! Run it on a schedule (a `singleton` job, hourly or daily): an edit to an event
//! older than the latest anchor is then always detectable with [`crate::verify_anchor`]
//! against a manifest fetched from the store, not from the database.

use std::future::Future;
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{Hash, Head, micros};

/// The manifest's format.
pub const FORMAT: &str = "owt-audit/manifest/v1";

/// Every chain's head at one moment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// [`FORMAT`].
    pub format: String,
    /// When it was made, in microseconds since the UNIX epoch.
    pub at_us: i64,
    /// The previous anchor's digest, as lowercase hex; `None` for the first.
    pub prev: Option<String>,
    /// The heads, by tenant.
    pub heads: Vec<Head>,
}

impl Manifest {
    /// The bytes stored and hashed: JSON, fields in declaration order.
    ///
    /// # Panics
    ///
    /// Never: a manifest is strings and integers, which always serialize.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a manifest of strings and integers serializes")
    }

    /// Read a manifest from its bytes.
    pub fn from_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }

    /// SHA-256 of [`Manifest::to_bytes`].
    #[must_use]
    pub fn digest(&self) -> Hash {
        Sha256::digest(self.to_bytes()).into()
    }

    /// The object key it is stored under: `owt-audit/<at_us>-<digest>.json`.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "owt-audit/{:020}-{}.json",
            self.at_us,
            crate::hex(&self.digest())
        )
    }
}

/// Where manifests are kept, out of the database owner's reach. An implementation
/// stores `bytes` under `key` so it cannot be overwritten or deleted before its
/// retention ends, and returns a receipt (a version id, an `ETag`) to record.
pub trait Anchor: Send + Sync {
    /// The provider's name, recorded with each anchor.
    fn name(&self) -> &str;

    /// Store a manifest.
    fn put(&self, key: &str, bytes: &[u8]) -> impl Future<Output = anyhow::Result<String>> + Send;
}

/// Anchors nowhere: manifests are recorded in the database only. For development and
/// tests; in production it leaves rewrites by the database's owner undetectable.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAnchor;

impl Anchor for NoAnchor {
    fn name(&self) -> &'static str {
        "none"
    }

    fn put(
        &self,
        _key: &str,
        _bytes: &[u8],
    ) -> impl Future<Output = anyhow::Result<String>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

/// A manifest as anchored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchored {
    /// Its row in `owt_audit_anchors`.
    pub id: i64,
    /// The manifest.
    pub manifest: Manifest,
    /// The store's receipt.
    pub receipt: String,
}

/// The advisory lock [`anchor`] holds, so concurrent runs do not fork the anchors.
pub const ANCHOR_LOCK: i64 = 0x6f77_745f_616e_6368;

/// Anchor every chain's head now. Each chain is verified first, from the head the
/// previous manifest anchored (from its first event when there is none), so a
/// broken chain is never anchored; then the manifest is stored with `to`, and
/// recorded. Runs are serialized by [`ANCHOR_LOCK`]. A failed verification or store
/// records nothing.
///
/// Run it as a role that may insert into `owt_audit_anchors` (see the README); the
/// app's role needs only `SELECT` on it.
pub async fn anchor<A: Anchor>(pool: &PgPool, to: &A) -> anyhow::Result<Anchored> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ANCHOR_LOCK)
        .execute(&mut *tx)
        .await?;
    let previous = latest_in(&mut tx).await?;
    let prev_heads: std::collections::HashMap<String, (i64, Hash)> = previous
        .as_ref()
        .map(|(m, _)| {
            m.heads
                .iter()
                .filter_map(|h| Some((h.tenant.clone(), (h.seq, unhex(&h.hash)?))))
                .collect()
        })
        .unwrap_or_default();
    let mut heads = Vec::new();
    for head in crate::heads(pool).await? {
        let (seq, hash) = prev_heads
            .get(&head.tenant)
            .copied()
            .unwrap_or((0, crate::GENESIS));
        let verified = crate::verify::verify_since(pool, &head.tenant, seq, &hash).await?;
        // Events recorded since `heads` read; the walk's own end is the head.
        heads.push(verified.head.unwrap_or(crate::Head {
            tenant: head.tenant.clone(),
            seq,
            hash: crate::hex(&hash),
        }));
    }
    // A chain the previous manifest anchored must still be there.
    for (tenant, (seq, _)) in &prev_heads {
        if !heads.iter().any(|h| &h.tenant == tenant) && *seq > 0 {
            anyhow::bail!("the audit chain {tenant:?} anchored at event {seq} is gone");
        }
    }
    let manifest = Manifest {
        format: FORMAT.into(),
        at_us: micros(SystemTime::now()),
        prev: previous.map(|(_, digest)| crate::hex(&digest)),
        heads,
    };
    let bytes = manifest.to_bytes();
    let digest = manifest.digest();
    let receipt = to.put(&manifest.key(), &bytes).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO owt_audit_anchors (manifest, digest, provider, receipt)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&bytes)
    .bind(&digest[..])
    .bind(to.name())
    .bind(&receipt)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(
        id,
        chains = manifest.heads.len(),
        provider = to.name(),
        "anchored the audit chains' heads"
    );
    Ok(Anchored {
        id,
        manifest,
        receipt,
    })
}

/// The latest manifest recorded in the database whose recorded digest and format
/// match it (a row that does not is skipped, with a warning). The database's copy is only as trustworthy as the roles that
/// may insert into `owt_audit_anchors`: for a check the database's owner cannot
/// defeat, verify against the copy in the anchor store.
pub async fn latest(pool: &PgPool) -> anyhow::Result<Option<Manifest>> {
    let mut conn = pool.acquire().await?;
    Ok(latest_in(&mut conn).await?.map(|(m, _)| m))
}

async fn latest_in(conn: &mut sqlx::PgConnection) -> anyhow::Result<Option<(Manifest, Hash)>> {
    // The newest row whose manifest matches its digest. A row that does not is
    // skipped with a warning rather than trusted, and, since anchors are never
    // deleted, rather than blocking every later anchoring.
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT id, manifest, digest FROM owt_audit_anchors ORDER BY id DESC")
            .fetch_all(&mut *conn)
            .await?;
    for (id, bytes, digest) in rows {
        let valid = Manifest::from_bytes(&bytes).ok().and_then(|m| {
            let stored: Hash = digest.as_slice().try_into().ok()?;
            (m.format == FORMAT && m.digest() == stored).then_some((m, stored))
        });
        match valid {
            Some(found) => return Ok(Some(found)),
            None => tracing::warn!(
                id,
                "an audit anchor's manifest does not match its digest; skipped"
            ),
        }
    }
    Ok(None)
}

fn unhex(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}
