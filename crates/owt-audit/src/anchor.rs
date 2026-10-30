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

use crate::{Hash, Head, heads, micros};

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
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
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

/// Anchor every chain's head now: build the manifest, store it with `to`, then record
/// it. A failed store records nothing; the next run anchors the heads as they are
/// then.
pub async fn anchor<A: Anchor>(pool: &PgPool, to: &A) -> anyhow::Result<Anchored> {
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT digest FROM owt_audit_anchors ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    let manifest = Manifest {
        format: FORMAT.into(),
        at_us: micros(SystemTime::now()),
        prev: prev.map(|d| crate::hex(&d)),
        heads: heads(pool).await?,
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
    .fetch_one(pool)
    .await?;
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

/// The latest manifest recorded in the database. Verify against the copy in the
/// store for a check the database's owner cannot defeat.
pub async fn latest(pool: &PgPool) -> anyhow::Result<Option<Manifest>> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT manifest FROM owt_audit_anchors ORDER BY id DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(bytes.map(|b| Manifest::from_bytes(&b)).transpose()?)
}
