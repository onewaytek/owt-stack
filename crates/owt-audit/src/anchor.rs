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
//! older than the latest anchor is then always detectable with [`verify_store`],
//! which checks the database's anchors against the store's copies.

use std::future::Future;
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{Hash, Head, micros};

#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "s3")]
pub use s3::{S3Config, S3ObjectLock};

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
/// retention ends, returns a receipt (a version id, an `ETag`) to record, and reads
/// stored manifests back for [`verify_store`].
pub trait Anchor: Send + Sync {
    /// The provider's name, recorded with each anchor.
    fn name(&self) -> &str;

    /// Store a manifest.
    fn put(&self, key: &str, bytes: &[u8]) -> impl Future<Output = anyhow::Result<String>> + Send;

    /// Read a stored manifest back. [`Stored::Version`] is the one stored under a key
    /// with a receipt `put` returned, and is an error when the store does not hold it.
    /// [`Stored::Latest`] is the newest manifest stored (keys order by time), or
    /// `None` when the store holds none.
    fn get(
        &self,
        which: Stored<'_>,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send;
}

/// Which stored manifest [`Anchor::get`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored<'a> {
    /// The manifest under `key`, as stored with `receipt`.
    Version {
        /// [`Manifest::key`].
        key: &'a str,
        /// The receipt `put` returned for it.
        receipt: &'a str,
    },
    /// The newest manifest stored.
    Latest,
}

/// Anchors nowhere: manifests are recorded in the database only. For development and
/// tests; in production it leaves rewrites by the database's owner undetectable.
/// It holds nothing to read back: [`Stored::Latest`] is `None` and a
/// [`Stored::Version`] is an error.
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

    fn get(
        &self,
        which: Stored<'_>,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send {
        std::future::ready(match which {
            Stored::Latest => Ok(None),
            Stored::Version { key, .. } => Err(anyhow::anyhow!(
                "NoAnchor stores nothing, so it does not hold {key:?}"
            )),
        })
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

/// Every manifest recorded in the database, oldest first, checked as a chain: each
/// row's manifest matches its recorded digest and format, the first names no
/// previous manifest, and each later one names the digest of the one before it.
/// Unlike [`latest`], a row that fails is an error, not skipped: verification
/// reports a damaged or inserted anchor instead of falling back past it.
///
/// This checks the database's copies against each other only; a role that may
/// rewrite `owt_audit_anchors` can rewrite them consistently. The independent check
/// is the store's copy: [`verify_store`], or `audit verify`.
pub async fn history(pool: &PgPool) -> Result<Vec<Manifest>, crate::VerifyError> {
    Ok(recorded(pool)
        .await?
        .into_iter()
        .map(|r| r.manifest)
        .collect())
}

/// A manifest the database records, with the provider and receipt recorded with it.
struct Recorded {
    manifest: Manifest,
    provider: String,
    receipt: String,
}

/// [`history`], with each row's provider and receipt.
async fn recorded(pool: &PgPool) -> Result<Vec<Recorded>, crate::VerifyError> {
    use crate::VerifyError;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT id, manifest, digest, provider, receipt FROM owt_audit_anchors ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut out: Vec<Recorded> = Vec::with_capacity(rows.len());
    let mut prev: Option<String> = None;
    for (id, bytes, digest, provider, receipt) in rows {
        let m = Manifest::from_bytes(&bytes)
            .map_err(|e| VerifyError::Manifest(format!("anchor {id} does not parse: {e}")))?;
        let stored: Option<Hash> = digest.as_slice().try_into().ok();
        if m.format != FORMAT || Some(m.digest()) != stored {
            return Err(VerifyError::Manifest(format!(
                "anchor {id}'s manifest does not match its recorded digest"
            )));
        }
        if m.prev != prev {
            return Err(VerifyError::Manifest(format!(
                "anchor {id} names {:?} as the previous manifest, not {prev:?}",
                m.prev
            )));
        }
        prev = Some(crate::hex(&m.digest()));
        out.push(Recorded {
            manifest: m,
            provider,
            receipt,
        });
    }
    Ok(out)
}

/// Check the database's anchors against the store's copies, so a rewrite of both the
/// chains and `owt_audit_anchors` by the database's owner is caught: the database's
/// anchors must form an unbroken chain ([`history`]); the latest must have been
/// stored by `store` (its recorded provider is `store`'s name), the store's copy of
/// it, read by its receipt, must be the database's, and it must be the newest
/// manifest the store holds; and its heads must still be in their chains
/// ([`crate::verify_anchor`]). Since each manifest names the digest of the one before
/// it, the store's copy of the latest vouches for every earlier row as well. Walk
/// each chain with [`crate::verify`] as well, to show the events before the heads
/// are intact.
///
/// Returns the latest manifest, or `None` when neither the database nor the store
/// holds one. A store that cannot be read, or that holds a manifest the database
/// does not record as its latest, is a failure, not a warning. A run of [`anchor`]
/// whose store write succeeded but whose database insert failed leaves the store a
/// manifest ahead, which fails this check until the next run anchors again.
pub async fn verify_store<A: Anchor>(
    pool: &PgPool,
    store: &A,
) -> Result<Option<Manifest>, crate::VerifyError> {
    use crate::VerifyError;
    let unreadable = |e: anyhow::Error| VerifyError::Store(format!("{e:#}"));
    let recorded = recorded(pool).await?;
    let newest = store
        .get(Stored::Latest)
        .await
        .map_err(unreadable)?
        .map(|b| Manifest::from_bytes(&b))
        .transpose()
        .map_err(|e| {
            VerifyError::Store(format!("the store's latest manifest does not parse: {e}"))
        })?;
    let Some(latest) = recorded.last() else {
        return match newest {
            Some(n) => Err(VerifyError::Store(format!(
                "the store holds {} but the database records no anchor: the anchors were removed",
                n.key()
            ))),
            None => Ok(None),
        };
    };
    let m = &latest.manifest;
    let key = m.key();
    if latest.provider != store.name() {
        return Err(VerifyError::Store(format!(
            "the latest anchor ({key}) was recorded by {:?}, not by the configured store {:?}",
            latest.provider,
            store.name()
        )));
    }
    let copy = store
        .get(Stored::Version {
            key: &key,
            receipt: &latest.receipt,
        })
        .await
        .map_err(unreadable)?
        .ok_or_else(|| VerifyError::Store(format!("the store does not hold {key}")))?;
    let same = Manifest::from_bytes(&copy).is_ok_and(|c| c.digest() == m.digest());
    if !same {
        return Err(VerifyError::Store(format!(
            "the store's copy of {key} is not the manifest the database records"
        )));
    }
    match newest {
        Some(n) if n.digest() == m.digest() => {}
        Some(n) => {
            return Err(VerifyError::Store(format!(
                "the store's newest manifest is {}, not the database's latest {key}: anchors were removed or rewritten",
                n.key()
            )));
        }
        None => {
            return Err(VerifyError::Store(format!(
                "the store lists no manifest, but the database's latest is {key}"
            )));
        }
    }
    crate::verify_anchor(pool, m).await?;
    Ok(Some(m.clone()))
}

/// How long ago the latest valid manifest in the database was made; `None` when
/// nothing is anchored. Events recorded since are not yet anchored, so an app
/// alerts when this exceeds its anchoring interval by a margin (a store credential
/// that stopped working, a job that stopped running).
pub async fn age(pool: &PgPool) -> anyhow::Result<Option<std::time::Duration>> {
    Ok(latest(pool).await?.map(|m| {
        let now = micros(SystemTime::now());
        std::time::Duration::from_micros(u64::try_from(now - m.at_us).unwrap_or(0))
    }))
}

/// The latest manifest recorded in the database whose recorded digest and format
/// match it (a row that does not is skipped, with a warning). The database's copy is only as trustworthy as the roles that
/// may insert into `owt_audit_anchors`: for a check the database's owner cannot
/// defeat, use [`verify_store`].
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
        if let Some(found) = valid {
            return Ok(Some(found));
        }
        tracing::warn!(
            id,
            "an audit anchor's manifest does not match its digest; skipped"
        );
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
