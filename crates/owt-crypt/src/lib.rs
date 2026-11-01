//! Envelope encryption of fields, with blind indexes for equality search.
//!
//! * **Data keys.** Each scope (a tenant) has its own AES-256 data keys, versioned,
//!   stored in `owt_crypt_keys` only wrapped by a KEK ([`kek::KekProvider`]). The
//!   newest version encrypts; every version decrypts. [`Crypt::rotate`] adds a
//!   version, and [`Crypt::reencrypt_column`] moves a column's values onto it.
//! * **Fields.** [`Crypt::encrypt`] seals a value with XChaCha20-Poly1305 under its
//!   scope's current data key. The associated data binds the ciphertext to its [`Field`]
//!   (scope, table, column and row), so a value copied to another row, column or
//!   tenant does not decrypt there. The ciphertext is self-describing: format byte,
//!   key version, nonce, sealed bytes ([`format`]). Values sealed with AES-256-GCM
//!   (format byte `0x01`) still open, and [`Crypt::reencrypt`] moves them to the
//!   current format.
//! * **Padding.** [`Crypt::encrypt_padded`] and [`Sealer::seal_padded`] pad a value to
//!   a [`Padding`] bucket (64 bytes by default) inside the AEAD before sealing, for a
//!   field whose length is itself sensitive; opening removes it. Unpadded seals are
//!   unchanged.
//! * **Blind indexes.** [`Crypt::blind_index`] is HMAC-SHA256 of a value under the
//!   scope's index key (separate from its data keys), for `WHERE email_idx = $1`
//!   without decrypting. It reveals which rows hold equal values, so index only what
//!   must be searched, and normalize first (case, whitespace) as the search will.
//! * **KEKs.** [`kek::LocalKek`] for development, CI and staging; `YubiHsmKek`
//!   (feature `yubihsm`) for a wrap key in a `YubiHSM 2`. [`Crypt::require_hardware_kek`]
//!   refuses a software KEK where the app requires hardware. [`Crypt::rewrap`] moves
//!   every data key to the current KEK after a KEK rotation, without touching data.
//! * **Memory.** Keys, unwrapped keys and decrypted values are zeroized when dropped
//!   ([`zeroize::Zeroizing`]); unwrapped data keys are cached for [`Crypt::cache_ttl`]
//!   (five minutes by default, or until [`Crypt::forget_keys`]), so the KEK is asked
//!   once per key per interval. Long-lived key material comes from the operating
//!   system's random generator; nonces from the thread generator.
//! * **Sealers.** [`Crypt::sealer`] loads a scope's keys once, and the [`Sealer`] seals,
//!   opens and computes blind indexes synchronously, for code that cannot `.await`. It is
//!   a snapshot: a rotation or shred makes it refuse to seal, and so does its age.
//! * **Shredding.** [`Crypt::shred`] deletes a scope's keys and records a tombstone, so
//!   the scope can never get keys again. Another replica's cache can still decrypt for
//!   up to the cache TTL after a shred; that TTL is the shred's latency.
//!
//! # Limits
//!
//! * A data key seals with random 192-bit nonces, so the number of seals per key sets
//!   no practical limit (a repeat is expected after about 2^96). Rotate data keys for
//!   other reasons (a suspected leak, a policy), not to stay under a nonce budget.
//! * One data key serves both formats: it opens its old AES-256-GCM values and seals
//!   new XChaCha20-Poly1305 ones. The format byte is in the associated data and picks
//!   the cipher, so a value cannot be opened as the other format.
//! * Concurrent [`Crypt::rotate`] calls may each add a version. That is harmless: the
//!   newest encrypts and all decrypt.
//! * Neither AES-GCM nor XChaCha20-Poly1305 is key-committing. Keys are chosen by
//!   (scope, version) from the database and the associated data carries both, so this
//!   has no practical attack here.
//! * The `hmac` and `sha2` states derived from an index key are not zeroized.
//! * A `LocalKek` read from an environment variable leaves the secret in the process
//!   environment for the process's life; prefer `from_file`.

pub mod format;
pub mod kek;
mod migrations;
mod sealer;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use format::Padding;
pub use migrations::{LEDGER, LOCK_ID, migrate, migrator};
pub use sealer::Sealer;
pub use zeroize;

use crate::format::{Format, Sealed, lp};
use crate::kek::{KekError, KekProvider};

/// Where a value lives: what its ciphertext is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    /// The scope whose keys encrypt it: the tenant.
    pub scope: &'a str,
    /// The table.
    pub table: &'a str,
    /// The column.
    pub column: &'a str,
    /// The row's stable id, as text: known before the row is inserted (a UUID the app
    /// makes), and never changed. [`Crypt::reencrypt_column`] reads it as the id
    /// column's text form.
    pub row: &'a str,
}

impl<'a> Field<'a> {
    /// The field `table.column` of row `row` in `scope`.
    #[must_use]
    pub fn new(scope: &'a str, table: &'a str, column: &'a str, row: &'a str) -> Self {
        Self {
            scope,
            table,
            column,
            row,
        }
    }
}

/// What a key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Encrypting fields.
    Data,
    /// Computing blind indexes.
    Index,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Index => "index",
        }
    }
}

/// Why an operation failed. None carries a key or a plaintext. New variants are not a
/// breaking change: match with a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptError {
    /// The KEK provider.
    #[error(transparent)]
    Kek(#[from] KekError),
    /// The database.
    #[error("owt-crypt: {0}")]
    Db(#[from] sqlx::Error),
    /// The bytes are not an owt-crypt ciphertext.
    #[error("not an owt-crypt ciphertext")]
    Malformed,
    /// The scope was shredded: it has no keys and can never get any.
    #[error("scope {0:?} was shredded")]
    Shredded(String),
    /// A [`Sealer`] is past its maximum age, or its scope was rotated since it loaded:
    /// [`Sealer::refresh`] it.
    #[error("the sealer for scope {0:?} is stale: refresh it")]
    Stale(String),
    /// A [`Sealer`] did not load that data key version, which was made after it
    /// loaded: [`Sealer::refresh`] it.
    #[error("the sealer for scope {scope:?} has not loaded data key version {version}: refresh it")]
    NotLoaded {
        /// The scope.
        scope: String,
        /// The version.
        version: u32,
    },
    /// The scope has no key of that purpose and version (never made, or shredded).
    #[error("scope {scope:?} has no {purpose:?} key version {version}")]
    NoKey {
        /// The scope.
        scope: String,
        /// The purpose.
        purpose: Purpose,
        /// The version.
        version: u32,
    },
    /// The ciphertext did not authenticate: altered, or read as another field than
    /// the one it was sealed for.
    #[error("a ciphertext did not decrypt for {table}.{column}")]
    Refused {
        /// The table.
        table: String,
        /// The column.
        column: String,
    },
    /// The current KEK is software and the app requires hardware.
    #[error("a hardware KEK is required, and {0:?} is software")]
    SoftwareKek(String),
    /// A scope or identifier is not acceptable.
    #[error("owt-crypt: {0}")]
    Invalid(String),
}

/// A key, zeroized on drop.
struct Key(Zeroizing<[u8; 32]>);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key([redacted])")
    }
}

/// What [`Sealer`]s of one scope check, shared with the [`Crypt`] that made them.
#[derive(Debug, Default)]
struct ScopeState {
    /// Bumped by every `rotate` and `shred` of the scope.
    generation: AtomicU64,
    /// Set by `shred`; a shredded scope never returns.
    shredded: AtomicBool,
}

/// A cached key and when it was cached.
type Cache = HashMap<(String, Purpose, u32), (Arc<Key>, Instant)>;

/// The most unwrapped keys cached; past it expired entries go, then the oldest half.
const CACHE_MAX: usize = 10_000;

/// How long an unwrapped key is cached unless [`Crypt::cache_ttl`] says otherwise.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// The most failed rows [`Crypt::reencrypt_column`] remembers before it stops.
const FAILED_MAX: usize = 10_000;

/// Field encryption for one database. Cheap to clone; clones share the key cache.
#[derive(Clone)]
pub struct Crypt {
    pool: PgPool,
    kek: Arc<dyn KekProvider>,
    cache: Arc<Mutex<Cache>>,
    /// Bumped by every `shred`; a key unwrapped across a bump is not cached.
    shreds: Arc<AtomicU64>,
    /// What each scope's live sealers check. An entry lasts as long as a sealer holds
    /// it; a scope without one is read afresh from the database at load.
    scopes: Arc<Mutex<HashMap<String, Weak<ScopeState>>>>,
    cache_ttl: Duration,
    sealer_max_age: Option<Duration>,
}

impl fmt::Debug for Crypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Crypt")
            .field("kek", &self.kek.kek_id())
            .finish_non_exhaustive()
    }
}

impl Crypt {
    /// Keys in `pool`'s `owt_crypt_keys` ([`migrate`] first), wrapped by `kek`.
    #[must_use]
    pub fn new(pool: PgPool, kek: Arc<dyn KekProvider>) -> Self {
        Self {
            pool,
            kek,
            cache: Arc::default(),
            shreds: Arc::default(),
            scopes: Arc::default(),
            cache_ttl: DEFAULT_CACHE_TTL,
            sealer_max_age: None,
        }
    }

    /// Cache unwrapped keys for `ttl` (five minutes by default). It bounds how long a
    /// replica keeps decrypting after [`Crypt::shred`] or [`Crypt::rewrap`] ran on
    /// another: the shred latency. A shorter TTL asks the KEK (the HSM) more often.
    /// Writes are not delayed: the current version is read from the database each
    /// time, and a shredded scope refuses new keys at once.
    #[must_use]
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// With `required` (production), refuse a KEK that is not in hardware. Call it
    /// at startup, from the app's configuration, so a production replica given a
    /// software KEK does not start. It checks the current KEK only: a [`kek::KekChain`]
    /// whose previous provider is software passes while rows are still software-wrapped.
    /// Production also treats a non-empty [`Crypt::software_wrapped_keys`] after
    /// [`Crypt::rewrap`] as an alarm; [`Crypt::check_keys_hardware`] makes that a
    /// start-up failure.
    pub fn require_hardware_kek(self, required: bool) -> Result<Self, CryptError> {
        if required && !self.kek.is_hardware() {
            return Err(CryptError::SoftwareKek(self.kek.kek_id().into()));
        }
        Ok(self)
    }

    /// Fail with [`CryptError::SoftwareKek`] when any stored key is wrapped by a KEK
    /// that is not hardware (or that no provider knows). Call it at start-up after
    /// [`Crypt::require_hardware_kek`], so a chain that still holds software-wrapped
    /// rows does not pass for hardware.
    pub async fn check_keys_hardware(&self) -> Result<(), CryptError> {
        let ids = self.software_wrapped_keys().await?;
        if ids.is_empty() {
            Ok(())
        } else {
            Err(CryptError::SoftwareKek(ids.join(", ")))
        }
    }

    /// The distinct KEK ids in `owt_crypt_keys` that are not hardware ones. After a
    /// move to an HSM and [`Crypt::rewrap`] this is empty; anything left is a key a
    /// software KEK still protects.
    pub async fn software_wrapped_keys(&self) -> Result<Vec<String>, CryptError> {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT kek_id FROM owt_crypt_keys ORDER BY kek_id")
                .fetch_all(&self.pool)
                .await?;
        Ok(ids
            .into_iter()
            .filter(|id| !self.kek.is_hardware_kek(id))
            .collect())
    }

    /// The KEK provider.
    #[must_use]
    pub fn kek(&self) -> &Arc<dyn KekProvider> {
        &self.kek
    }

    /// Seal `plaintext` for `field` under its scope's current data key (made on first
    /// use).
    pub async fn encrypt(
        &self,
        field: &Field<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        check_field(field)?;
        let (version, key) = self.current(field.scope, Purpose::Data).await?;
        Ok(seal(&key, version, field, plaintext))
    }

    /// [`Crypt::encrypt`] of a string.
    pub async fn encrypt_str(
        &self,
        field: &Field<'_>,
        plaintext: &str,
    ) -> Result<Vec<u8>, CryptError> {
        self.encrypt(field, plaintext.as_bytes()).await
    }

    /// [`Crypt::encrypt`], with `plaintext` padded to `padding`'s bucket first (format
    /// `0x03`, [`format`]), so every value whose length falls in one bucket has a
    /// ciphertext of one length. [`Crypt::decrypt`] removes the padding;
    /// [`Crypt::reencrypt`] keeps it.
    pub async fn encrypt_padded(
        &self,
        field: &Field<'_>,
        plaintext: &[u8],
        padding: Padding,
    ) -> Result<Vec<u8>, CryptError> {
        check_field(field)?;
        let (version, key) = self.current(field.scope, Purpose::Data).await?;
        Ok(seal_padded(&key, version, field, plaintext, padding))
    }

    /// [`Crypt::encrypt_padded`] of a string.
    pub async fn encrypt_str_padded(
        &self,
        field: &Field<'_>,
        plaintext: &str,
        padding: Padding,
    ) -> Result<Vec<u8>, CryptError> {
        self.encrypt_padded(field, plaintext.as_bytes(), padding)
            .await
    }

    /// Open a ciphertext sealed for `field`.
    pub async fn decrypt(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        check_field(field)?;
        let sealed = Sealed::parse(ciphertext).ok_or(CryptError::Malformed)?;
        let key = self.key(field.scope, Purpose::Data, sealed.version).await?;
        open(&key, &sealed, field)
    }

    /// [`Crypt::decrypt`] of a string.
    pub async fn decrypt_string(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<String>, CryptError> {
        let mut bytes = self.decrypt(field, ciphertext).await?;
        if std::str::from_utf8(&bytes).is_err() {
            return Err(CryptError::Malformed);
        }
        let taken = std::mem::take(&mut *bytes);
        Ok(Zeroizing::new(String::from_utf8(taken).unwrap_or_default()))
    }

    /// The blind index of `value` in `scope`'s `table.column`, under the scope's
    /// current index key: store it beside the ciphertext, and look rows up by it.
    pub async fn blind_index(
        &self,
        scope: &str,
        table: &str,
        column: &str,
        value: &[u8],
    ) -> Result<[u8; 32], CryptError> {
        check_scope(scope)?;
        let (_, key) = self.current(scope, Purpose::Index).await?;
        Ok(mac(&key, table, column, value))
    }

    /// The blind index of `value` under every index key version of `scope`, newest
    /// first: search with `= ANY($1)` while a rotation of the index key is under way.
    pub async fn blind_index_candidates(
        &self,
        scope: &str,
        table: &str,
        column: &str,
        value: &[u8],
    ) -> Result<Vec<[u8; 32]>, CryptError> {
        check_scope(scope)?;
        let mut out = Vec::new();
        for version in self.versions(scope, Purpose::Index).await? {
            let key = self.key(scope, Purpose::Index, version).await?;
            out.push(mac(&key, table, column, value));
        }
        if out.is_empty() {
            out.push(self.blind_index(scope, table, column, value).await?);
        }
        Ok(out)
    }

    /// Add a new version of `scope`'s `purpose` key; new values use it from now on,
    /// and older ones still decrypt. Its version. Concurrent calls may each add a
    /// version, which is harmless.
    pub async fn rotate(&self, scope: &str, purpose: Purpose) -> Result<u32, CryptError> {
        check_scope(scope)?;
        loop {
            let latest = self
                .versions(scope, purpose)
                .await?
                .first()
                .copied()
                .unwrap_or(0);
            if let Some(v) = self.create(scope, purpose, latest + 1).await? {
                self.invalidate(scope, false);
                return Ok(v);
            }
        }
    }

    /// The current version of `scope`'s data key, made if there is none.
    pub async fn current_version(&self, scope: &str) -> Result<u32, CryptError> {
        check_scope(scope)?;
        Ok(self.current(scope, Purpose::Data).await?.0)
    }

    /// `ciphertext` sealed again under its scope's current data key in the current
    /// [`format`], or `None` when it already is (so an AES-256-GCM value under the
    /// current key is sealed again too). A padded value stays padded, to the same
    /// length.
    pub async fn reencrypt(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptError> {
        check_field(field)?;
        let sealed = Sealed::parse(ciphertext).ok_or(CryptError::Malformed)?;
        let (version, key) = self.current(field.scope, Purpose::Data).await?;
        if sealed.version == version && sealed.format.is_current() {
            return Ok(None);
        }
        let old = self.key(field.scope, Purpose::Data, sealed.version).await?;
        reseal(&old, &sealed, &key, version, field).map(Some)
    }

    /// Re-encrypt every value of a column that is not under its scope's current data
    /// key, `batch` rows at a time: the job after [`Crypt::rotate`]. Each row is
    /// updated only if its value is still the one read, so it runs beside live
    /// writes.
    ///
    /// A row that cannot be decrypted (malformed, its key shredded, or refused) is
    /// recorded in [`Reencrypted::failed`] and left out of later passes; the job goes on
    /// and stops after 10,000 failures. It also stops when a pass moves no row and
    /// finds no new failure (a trigger, a policy or a view that swallows the update,
    /// or live writers winning every race), so it cannot loop forever; that stop and
    /// the failure cap return [`Reencrypted::complete`] false. Rows whose scope has no
    /// data key are not visited; they are counted in [`Reencrypted::no_key`], which
    /// also makes `complete` false. A database or KEK
    /// outage, and a KEK id no provider knows, are errors.
    ///
    /// Retire an old key version only after a run that is `complete` with no `failed`
    /// rows (and has been checked against the column): `moved: 0` alone is not "done".
    pub async fn reencrypt_column(
        &self,
        column: &Column<'_>,
        batch: u32,
    ) -> Result<Reencrypted, CryptError> {
        let table = ident(column.table)?;
        let id = ident(column.id)?;
        let value = ident(column.column)?;
        let (scope_expr, scope_arg, skip_param) = match column.scope {
            Scope::Fixed(s) => {
                check_scope(s)?;
                ("$2::text".to_owned(), Some(s), "$3")
            }
            Scope::Column(c) => (format!("t.{}::text", ident(c)?), None, "$2"),
        };
        let select = format!(
            "SELECT t.ctid::text, t.{id}::text, {scope_expr}, t.{value}
             FROM {table} t
             JOIN (SELECT scope, max(version) AS v FROM owt_crypt_keys
                   WHERE purpose = 'data' GROUP BY scope) k ON k.scope = {scope_expr}
             WHERE t.{value} IS NOT NULL
               AND substring(t.{value} FROM 2 FOR 4) <> int4send(k.v)
               AND t.ctid::text <> ALL({skip_param}::text[])
             LIMIT $1"
        );
        let update =
            format!("UPDATE {table} SET {value} = $1 WHERE ctid = $2::tid AND {value} = $3");
        let mut moved = 0;
        let mut failed = Vec::new();
        let mut skip: Vec<String> = Vec::new();
        let complete = loop {
            let mut query = sqlx::query_as::<_, (String, String, String, Vec<u8>)>(
                sqlx::AssertSqlSafe(select.clone()),
            )
            .bind(i64::from(batch.max(1)));
            if let Some(scope) = scope_arg {
                query = query.bind(scope);
            }
            let rows = query.bind(&skip).fetch_all(&self.pool).await?;
            if rows.is_empty() {
                break true;
            }
            // The current version of each scope, asked once per pass.
            let mut currents: HashMap<String, (u32, Arc<Key>)> = HashMap::new();
            let (moved_before, failed_before) = (moved, failed.len());
            for (ctid, row, scope, old) in rows {
                let field = Field::new(&scope, column.table, column.column, &row);
                let new = match self.reencrypt_with(&mut currents, &field, &old).await {
                    Ok(Some(new)) => new,
                    Ok(None) => continue,
                    Err(
                        CryptError::Malformed
                        | CryptError::NoKey { .. }
                        | CryptError::Refused { .. }
                        | CryptError::Shredded(_)
                        | CryptError::Kek(KekError::Refused(_)),
                    ) => {
                        failed.push(row);
                        skip.push(ctid);
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                // A row changed meanwhile keeps its new value; if that is under an old
                // key, the next pass reads it again.
                moved += sqlx::query(sqlx::AssertSqlSafe(update.clone()))
                    .bind(&new)
                    .bind(&ctid)
                    .bind(&old)
                    .execute(&self.pool)
                    .await?
                    .rows_affected();
            }
            if failed.len() >= FAILED_MAX
                || (moved == moved_before && failed.len() == failed_before)
            {
                break false;
            }
        };
        // Rows the JOIN above cannot see: their scope has no data key at all.
        let no_key_scope = match column.scope {
            Scope::Fixed(_) => "$1::text".to_owned(),
            Scope::Column(c) => format!("t.{}::text", ident(c)?),
        };
        let count = format!(
            "SELECT count(*) FROM {table} t
             WHERE t.{value} IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM owt_crypt_keys k
                               WHERE k.purpose = 'data' AND k.scope = {no_key_scope})"
        );
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count));
        if let Some(scope) = scope_arg {
            query = query.bind(scope);
        }
        let no_key = u64::try_from(query.fetch_one(&self.pool).await?).unwrap_or(0);
        Ok(Reencrypted {
            moved,
            failed,
            no_key,
            complete: complete && no_key == 0,
        })
    }

    /// [`Crypt::reencrypt`] with the scope's current key remembered in `currents`.
    async fn reencrypt_with(
        &self,
        currents: &mut HashMap<String, (u32, Arc<Key>)>,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptError> {
        check_field(field)?;
        let sealed = Sealed::parse(ciphertext).ok_or(CryptError::Malformed)?;
        if !currents.contains_key(field.scope) {
            let current = self.current(field.scope, Purpose::Data).await?;
            currents.insert(field.scope.to_owned(), current);
        }
        let (version, key) = &currents[field.scope];
        if sealed.version == *version && sealed.format.is_current() {
            return Ok(None);
        }
        let old = self.key(field.scope, Purpose::Data, sealed.version).await?;
        reseal(&old, &sealed, key, *version, field).map(Some)
    }

    /// Wrap every key not under the current KEK under it: the job after a KEK
    /// rotation. Data is untouched. Each key is replaced only if it is still wrapped
    /// as read. How many keys it rewrapped.
    pub async fn rewrap(&self) -> Result<u64, CryptError> {
        let current = self.kek.kek_id().to_owned();
        let rows: Vec<(String, String, i32, String, Vec<u8>)> = sqlx::query_as(
            "SELECT scope, purpose, version, kek_id, wrapped FROM owt_crypt_keys
             WHERE kek_id <> $1 ORDER BY scope, purpose, version",
        )
        .bind(&current)
        .fetch_all(&self.pool)
        .await?;
        let mut done = 0;
        for (scope, purpose, version, kek_id, wrapped) in rows {
            let version = u32::try_from(version).map_err(|_| CryptError::Malformed)?;
            let context = format::wrap_context(&scope, &purpose, version);
            let key = self.kek.unwrap(&kek_id, &wrapped, &context).await?;
            let rewrapped = self.kek.wrap(&key, &context).await?;
            // The only wrapped copy is replaced, so check the new one unwraps to the
            // same key before it is.
            let check = self.kek.unwrap(&current, &rewrapped, &context).await?;
            if !bool::from(check[..].ct_eq(&key[..])) {
                return Err(KekError::Refused(current).into());
            }
            done += sqlx::query(
                "UPDATE owt_crypt_keys SET kek_id = $1, wrapped = $2
                 WHERE scope = $3 AND purpose = $4 AND version = $5 AND kek_id = $6
                       AND wrapped = $7",
            )
            .bind(&current)
            .bind(&rewrapped)
            .bind(&scope)
            .bind(&purpose)
            .bind(to_i32(version))
            .bind(&kek_id)
            .bind(&wrapped)
            .execute(&self.pool)
            .await?
            .rows_affected();
        }
        Ok(done)
    }

    /// Delete every key of `scope` and record it as shredded: everything encrypted for
    /// it becomes unreadable for good, and the scope can never get keys again
    /// (crypto-shredding, for a tenant that leaves). The tombstone and the deletion are
    /// one transaction. The tombstone is permanent: a shredded scope id can never be
    /// reused, so an app that recycles tenant ids must not shred them.
    ///
    /// Other replicas may decrypt from their key caches for up to [`Crypt::cache_ttl`].
    /// Backups, WAL archives, replicas and logical-decoding slots hold the wrapped keys
    /// until they expire; shredding does not reach them. How many keys went.
    pub async fn shred(&self, scope: &str) -> Result<u64, CryptError> {
        check_scope(scope)?;
        let mut tx = self.pool.begin().await?;
        lock_scope(&mut tx, scope).await?;
        sqlx::query("INSERT INTO owt_crypt_shredded (scope) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(scope)
            .execute(&mut *tx)
            .await?;
        let gone = sqlx::query("DELETE FROM owt_crypt_keys WHERE scope = $1")
            .bind(scope)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        // Bump first: a key unwrapped before the bump is refused by `remember`, and one
        // cached before it is dropped by the retain.
        self.shreds.fetch_add(1, Ordering::SeqCst);
        self.invalidate(scope, true);
        self.cache().retain(|(s, _, _), _| s != scope);
        Ok(gone)
    }

    /// Drop every cached unwrapped key (each is zeroized as its last user lets go).
    pub fn forget_keys(&self) {
        self.cache().clear();
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The versions of `scope`'s `purpose` keys, newest first.
    async fn versions(&self, scope: &str, purpose: Purpose) -> Result<Vec<u32>, CryptError> {
        let versions: Vec<i32> = sqlx::query_scalar(
            "SELECT version FROM owt_crypt_keys WHERE scope = $1 AND purpose = $2
             ORDER BY version DESC",
        )
        .bind(scope)
        .bind(purpose.as_str())
        .fetch_all(&self.pool)
        .await?;
        Ok(versions
            .into_iter()
            .filter_map(|v| u32::try_from(v).ok())
            .collect())
    }

    /// The newest key of `scope` for `purpose`, made as version 1 if there is none.
    async fn current(&self, scope: &str, purpose: Purpose) -> Result<(u32, Arc<Key>), CryptError> {
        loop {
            if let Some(&v) = self.versions(scope, purpose).await?.first() {
                return Ok((v, self.key(scope, purpose, v).await?));
            }
            // Two replicas may race to make version 1; the loser reads the winner's.
            self.create(scope, purpose, 1).await?;
        }
    }

    /// Make and store key `version`, unless it exists. Its version when this call
    /// made it; [`CryptError::Shredded`] for a shredded scope.
    async fn create(
        &self,
        scope: &str,
        purpose: Purpose,
        version: u32,
    ) -> Result<Option<u32>, CryptError> {
        let epoch = self.shreds.load(Ordering::SeqCst);
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut key[..]).map_err(|e| {
            CryptError::Invalid(format!("the operating system's random generator: {e}"))
        })?;
        let context = format::wrap_context(scope, purpose.as_str(), version);
        let wrapped = self.kek.wrap(&key[..], &context).await?;
        // The lock orders this against `shred`: the insert's snapshot is taken after
        // any shred in flight has committed, so it sees the tombstone.
        let mut tx = self.pool.begin().await?;
        lock_scope(&mut tx, scope).await?;
        let made = sqlx::query(
            "INSERT INTO owt_crypt_keys (scope, purpose, version, kek_id, wrapped)
             SELECT $1, $2, $3, $4, $5
             WHERE NOT EXISTS (SELECT 1 FROM owt_crypt_shredded WHERE scope = $1)
             ON CONFLICT DO NOTHING",
        )
        .bind(scope)
        .bind(purpose.as_str())
        .bind(to_i32(version))
        .bind(self.kek.kek_id())
        .bind(&wrapped)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let shredded = !made && self.is_shredded(&mut tx, scope).await?;
        tx.commit().await?;
        if shredded {
            return Err(CryptError::Shredded(scope.into()));
        }
        if made {
            self.remember(scope, purpose, version, Arc::new(Key(key)), epoch);
            return Ok(Some(version));
        }
        Ok(None)
    }

    async fn is_shredded(
        &self,
        tx: &mut sqlx::PgConnection,
        scope: &str,
    ) -> Result<bool, CryptError> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM owt_crypt_shredded WHERE scope = $1)")
                .bind(scope)
                .fetch_one(tx)
                .await?,
        )
    }

    /// Key `version` of `scope` for `purpose`, from the cache or unwrapped.
    async fn key(
        &self,
        scope: &str,
        purpose: Purpose,
        version: u32,
    ) -> Result<Arc<Key>, CryptError> {
        let epoch = self.shreds.load(Ordering::SeqCst);
        if let Some((k, at)) = self.cache().get(&(scope.to_owned(), purpose, version))
            && at.elapsed() < self.cache_ttl
        {
            return Ok(k.clone());
        }
        let row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT kek_id, wrapped FROM owt_crypt_keys
             WHERE scope = $1 AND purpose = $2 AND version = $3",
        )
        .bind(scope)
        .bind(purpose.as_str())
        .bind(to_i32(version))
        .fetch_optional(&self.pool)
        .await?;
        let Some((kek_id, wrapped)) = row else {
            self.cache().remove(&(scope.to_owned(), purpose, version));
            return Err(CryptError::NoKey {
                scope: scope.into(),
                purpose,
                version,
            });
        };
        let context = format::wrap_context(scope, purpose.as_str(), version);
        let bytes = self.kek.unwrap(&kek_id, &wrapped, &context).await?;
        if bytes.len() != 32 {
            return Err(KekError::Refused(kek_id).into());
        }
        let mut raw = Zeroizing::new([0_u8; 32]);
        raw.copy_from_slice(&bytes);
        let key = Arc::new(Key(raw));
        // A shred that landed during the unwrap must not be undone by caching.
        let shredded: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM owt_crypt_shredded WHERE scope = $1)")
                .bind(scope)
                .fetch_one(&self.pool)
                .await?;
        if shredded {
            return Err(CryptError::Shredded(scope.into()));
        }
        self.remember(scope, purpose, version, key.clone(), epoch);
        Ok(key)
    }

    /// Cache `key`, unless a shred ran since `epoch` was read. Expired entries go on
    /// every insert, so a shredded scope's keys do not linger past the TTL.
    fn remember(&self, scope: &str, purpose: Purpose, version: u32, key: Arc<Key>, epoch: u64) {
        let mut cache = self.cache();
        if self.shreds.load(Ordering::SeqCst) != epoch {
            return;
        }
        let ttl = self.cache_ttl;
        cache.retain(|_, (_, at)| at.elapsed() < ttl);
        if cache.len() >= CACHE_MAX {
            let mut ages: Vec<Instant> = cache.values().map(|(_, at)| *at).collect();
            ages.sort_unstable();
            let cutoff = ages[ages.len() / 2];
            cache.retain(|_, (_, at)| *at > cutoff);
        }
        cache.insert((scope.to_owned(), purpose, version), (key, Instant::now()));
    }
}

/// What [`Crypt::reencrypt_column`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reencrypted {
    /// How many rows it re-encrypted.
    pub moved: u64,
    /// The ids of rows that could not be decrypted (malformed, an older key version
    /// shredded, or refused), left as they were. It stops collecting at 10,000.
    pub failed: Vec<String>,
    /// How many rows with a value sit under a scope that has no data key, so the job
    /// cannot read or move them. They are not in `failed`; any makes `complete` false.
    pub no_key: u64,
    /// Whether the column was walked until no row outside `failed` was left under an
    /// old key, and no row was left without a key (`no_key` is 0). False when the job
    /// gave up (no progress in a pass, or the failure cap) or `no_key` is not 0.
    /// Retire an old key version only after a complete run with nothing in `failed`.
    pub complete: bool,
}

/// Serialize key creation against `shred` for `scope` until the transaction ends.
async fn lock_scope(tx: &mut sqlx::PgConnection, scope: &str) -> Result<(), CryptError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('owt_crypt/' || $1, 0))")
        .bind(scope)
        .execute(tx)
        .await?;
    Ok(())
}

/// A column [`Crypt::reencrypt_column`] walks.
#[derive(Clone, Copy, Debug)]
pub struct Column<'a> {
    /// The table (a plain lowercase identifier, optionally `schema.table`).
    pub table: &'a str,
    /// The column holding each row's id, whose text form is the [`Field::row`] the
    /// values were sealed with.
    pub id: &'a str,
    /// The encrypted column.
    pub column: &'a str,
    /// Where each row's scope comes from.
    pub scope: Scope<'a>,
}

/// The scope of a column's values.
#[derive(Clone, Copy, Debug)]
pub enum Scope<'a> {
    /// The same for every row.
    Fixed(&'a str),
    /// A column of the row (its text form).
    Column(&'a str),
}

fn seal(key: &Key, version: u32, field: &Field<'_>, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    seal_with(key, version, field, plaintext, nonce)
}

/// [`seal`] with `plaintext` padded to `padding`'s bucket, in format `0x03`.
fn seal_padded(
    key: &Key,
    version: u32,
    field: &Field<'_>,
    plaintext: &[u8],
    padding: Padding,
) -> Vec<u8> {
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let padded = format::pad(plaintext, padding);
    seal_in(format::PADDED, key, version, field, &padded, nonce)
}

/// [`seal`] with a given nonce, in the current format.
fn seal_with(
    key: &Key,
    version: u32,
    field: &Field<'_>,
    plaintext: &[u8],
    nonce: [u8; 24],
) -> Vec<u8> {
    seal_in(format::CURRENT, key, version, field, plaintext, nonce)
}

/// XChaCha20-Poly1305 over `bytes` as they are, labelled `format` (`0x02`, or `0x03`
/// for bytes already padded).
fn seal_in(
    format: Format,
    key: &Key,
    version: u32,
    field: &Field<'_>,
    bytes: &[u8],
    nonce: [u8; 24],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0[..]).expect("a data key is 32 bytes");
    let aad = format::aad(format, field, version);
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: bytes,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 seals any length a Vec holds");
    format::assemble(format, version, &nonce, &sealed)
}

/// `sealed` (opened under `old`) sealed again under `key` at `version`, in the current
/// format: a padded value keeps its padding as it is, so its length does not change.
fn reseal(
    old: &Key,
    sealed: &Sealed<'_>,
    key: &Key,
    version: u32,
    field: &Field<'_>,
) -> Result<Vec<u8>, CryptError> {
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    if sealed.format == format::PADDED {
        let padded = open_raw(old, sealed, field)?;
        format::unpad(&padded).ok_or(CryptError::Malformed)?;
        return Ok(seal_in(format::PADDED, key, version, field, &padded, nonce));
    }
    let plain = open(old, sealed, field)?;
    Ok(seal_with(key, version, field, &plain, nonce))
}

/// Opens `sealed` with the cipher its format byte names and removes a padded format's
/// padding. Authentically sealed bytes whose padding is not [`format::pad`]'s are
/// [`CryptError::Malformed`].
fn open(
    key: &Key,
    sealed: &Sealed<'_>,
    field: &Field<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let mut opened = open_raw(key, sealed, field)?;
    if sealed.format == format::PADDED {
        let len = format::unpad(&opened).ok_or(CryptError::Malformed)?.len();
        opened.truncate(len);
    }
    Ok(opened)
}

/// Opens `sealed` with the cipher its format byte names, padding left on; the byte is
/// in the associated data, so an edited byte is refused.
fn open_raw(
    key: &Key,
    sealed: &Sealed<'_>,
    field: &Field<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let refused = || CryptError::Refused {
        table: field.table.into(),
        column: field.column.into(),
    };
    let aad = format::aad(sealed.format, field, sealed.version);
    let payload = Payload {
        msg: sealed.body,
        aad: &aad,
    };
    let opened = match sealed.format {
        Format::AesGcm => {
            let nonce: [u8; 12] = sealed.nonce.try_into().map_err(|_| refused())?;
            Aes256Gcm::new_from_slice(&key.0[..])
                .expect("a data key is 32 bytes")
                .decrypt(&Nonce::from(nonce), payload)
        }
        Format::XChaCha20Poly1305 | Format::XChaCha20Poly1305Padded => {
            let nonce: [u8; 24] = sealed.nonce.try_into().map_err(|_| refused())?;
            XChaCha20Poly1305::new_from_slice(&key.0[..])
                .expect("a data key is 32 bytes")
                .decrypt(&XNonce::from(nonce), payload)
        }
    };
    opened.map(Zeroizing::new).map_err(|_| refused())
}

fn mac(key: &Key, table: &str, column: &str, value: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key.0[..])
        .expect("HMAC takes any key length");
    m.update(format::INDEX_DOMAIN);
    m.update(&lp(table.as_bytes()));
    m.update(&lp(column.as_bytes()));
    m.update(&lp(value));
    m.finalize().into_bytes().into()
}

fn check_field(field: &Field<'_>) -> Result<(), CryptError> {
    check_scope(field.scope)?;
    for (name, part) in [
        ("table", field.table),
        ("column", field.column),
        ("row", field.row),
    ] {
        if part.is_empty() {
            return Err(CryptError::Invalid(format!(
                "a field's {name} is not empty"
            )));
        }
    }
    Ok(())
}

fn check_scope(scope: &str) -> Result<(), CryptError> {
    if scope.is_empty() || scope.len() > 200 || scope.chars().any(char::is_control) {
        return Err(CryptError::Invalid(format!(
            "a scope is 1 to 200 bytes, printable: {scope:?}"
        )));
    }
    Ok(())
}

/// A plain identifier, or `schema.name`, quoted.
fn ident(name: &str) -> Result<String, CryptError> {
    let part = |p: &str| {
        let mut b = p.bytes();
        p.len() <= 63
            && matches!(b.next(), Some(c) if c.is_ascii_lowercase() || c == b'_')
            && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    };
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 2 || !parts.iter().all(|p| part(p)) {
        return Err(CryptError::Invalid(format!(
            "not a plain identifier: {name:?}"
        )));
    }
    Ok(parts
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join("."))
}

fn to_i32(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Key {
        Key(Zeroizing::new([b; 32]))
    }

    #[test]
    fn a_ciphertext_opens_only_as_its_own_field() {
        let f = Field::new("t1", "notes", "body", "7");
        let ct = seal(&key(1), 3, &f, b"plain");
        let sealed = Sealed::parse(&ct).unwrap();
        assert_eq!(sealed.version, 3);
        assert_eq!(&open(&key(1), &sealed, &f).unwrap()[..], b"plain");
        for other in [
            Field::new("t2", "notes", "body", "7"),
            Field::new("t1", "notez", "body", "7"),
            Field::new("t1", "notes", "title", "7"),
            Field::new("t1", "notes", "body", "8"),
        ] {
            assert!(open(&key(1), &sealed, &other).is_err(), "{other:?}");
        }
        assert!(open(&key(2), &sealed, &f).is_err());
        // The version is bound too: a header edited to another version is refused.
        let mut bent = ct.clone();
        bent[4] = 4;
        let s = Sealed::parse(&bent).unwrap();
        assert!(open(&key(1), &s, &f).is_err());
        // Two seals of one value differ (fresh nonces).
        assert_ne!(seal(&key(1), 3, &f, b"plain"), ct);
    }

    const FIXTURE_PLAIN: &[u8] = b"Patient reports better sleep.";

    /// `FIXTURE_PLAIN` sealed as format `0x01` (AES-256-GCM) for
    /// `Field::new("t1", "notes", "body", "7")` under `key(1)`, version 3, nonce
    /// `00 01 .. 0b`. Made by an independent AES-GCM implementation (Python
    /// `cryptography`), and equal to [`seal_aes_gcm`]'s output.
    const AES_GCM_FIXTURE: &str = "0100000003000102030405060708090a0bebc7e14f459072598c0f97ab52\
        1dbb83cca31f7e90e365731daf5df08faa9fcbfd8e0b1d93c5ab8d58637a4b5d";

    /// The same value sealed as format `0x02` (XChaCha20-Poly1305), nonce
    /// `00 01 .. 17`, by an independent implementation (libsodium).
    const XCHACHA_FIXTURE: &str = "0200000003000102030405060708090a0b0c0d0e0f1011121314151617\
        28b1afecf8ffa3a891231a276646059097d3e8ba9d39a0a14c699ec1c1e220d0a7c249c55a8840\
        5908105d977f";

    fn unhex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        s.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn fixture_field() -> Field<'static> {
        Field::new("t1", "notes", "body", "7")
    }

    /// Seals as format `0x01` does: AES-256-GCM over the format-`0x01` associated data.
    /// The fixtures' writer.
    fn seal_aes_gcm(key: &Key, version: u32, field: &Field<'_>, plaintext: &[u8]) -> Vec<u8> {
        let nonce: [u8; 12] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let aad = format::aad(Format::AesGcm, field, version);
        let sealed = Aes256Gcm::new_from_slice(&key.0[..])
            .unwrap()
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        format::assemble(Format::AesGcm, version, &nonce, &sealed)
    }

    #[test]
    fn new_seals_are_xchacha20_poly1305() {
        let f = fixture_field();
        let ct = seal(&key(1), 3, &f, FIXTURE_PLAIN);
        let sealed = Sealed::parse(&ct).unwrap();
        assert_eq!(sealed.format, Format::XChaCha20Poly1305);
        assert_eq!(ct[0], 2);
        assert_eq!(sealed.nonce.len(), 24);
        assert_eq!(
            ct.len(),
            Format::XChaCha20Poly1305.min_len() + FIXTURE_PLAIN.len()
        );
        assert_eq!(&open(&key(1), &sealed, &f).unwrap()[..], FIXTURE_PLAIN);
        // Byte for byte the independent implementation's output, and it opens.
        let nonce: [u8; 24] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let known = unhex(XCHACHA_FIXTURE);
        assert_eq!(seal_with(&key(1), 3, &f, FIXTURE_PLAIN, nonce), known);
        let sealed = Sealed::parse(&known).unwrap();
        assert_eq!(&open(&key(1), &sealed, &f).unwrap()[..], FIXTURE_PLAIN);
    }

    #[test]
    fn aes_gcm_values_still_open() {
        let f = fixture_field();
        let old = unhex(AES_GCM_FIXTURE);
        assert_eq!(seal_aes_gcm(&key(1), 3, &f, FIXTURE_PLAIN), old);
        let sealed = Sealed::parse(&old).unwrap();
        assert_eq!((sealed.format, sealed.version), (Format::AesGcm, 3));
        assert_eq!(&open(&key(1), &sealed, &f).unwrap()[..], FIXTURE_PLAIN);
        // Bound to its field, version and key as before.
        for other in [
            Field::new("t2", "notes", "body", "7"),
            Field::new("t1", "notez", "body", "7"),
            Field::new("t1", "notes", "title", "7"),
            Field::new("t1", "notes", "body", "8"),
        ] {
            assert!(open(&key(1), &sealed, &other).is_err(), "{other:?}");
        }
        assert!(open(&key(2), &sealed, &f).is_err());
        let mut bent = old.clone();
        bent[4] = 4;
        assert!(open(&key(1), &Sealed::parse(&bent).unwrap(), &f).is_err());
    }

    #[test]
    fn a_tampered_byte_is_refused_in_both_formats() {
        let f = fixture_field();
        for ct in [unhex(AES_GCM_FIXTURE), seal(&key(1), 3, &f, FIXTURE_PLAIN)] {
            for i in 0..ct.len() {
                let mut bent = ct.clone();
                bent[i] ^= 0x01;
                if let Some(s) = Sealed::parse(&bent) {
                    assert!(
                        open(&key(1), &s, &f).is_err(),
                        "byte {i} of format {}",
                        ct[0]
                    );
                }
            }
            // Truncated, or a byte longer, refused too.
            let mut longer = ct.clone();
            longer.push(0);
            for bent in [&ct[..ct.len() - 1], &longer[..]] {
                if let Some(s) = Sealed::parse(bent) {
                    assert!(open(&key(1), &s, &f).is_err(), "format {}", ct[0]);
                }
            }
        }
    }

    #[test]
    fn the_format_byte_cannot_be_swapped() {
        let f = fixture_field();
        // A new value relabelled as AES-GCM parses (it is long enough) and is refused,
        // whether the reader takes the first 12 nonce bytes or the attacker drops the
        // rest of the nonce.
        let new = seal(&key(1), 3, &f, FIXTURE_PLAIN);
        let mut down = new.clone();
        down[0] = Format::AesGcm.byte();
        let s = Sealed::parse(&down).unwrap();
        assert_eq!(s.format, Format::AesGcm);
        assert!(open(&key(1), &s, &f).is_err());
        let parsed = Sealed::parse(&new).unwrap();
        let cut = format::assemble(Format::AesGcm, 3, &parsed.nonce[..12], parsed.body);
        assert!(open(&key(1), &Sealed::parse(&cut).unwrap(), &f).is_err());
        // An old value relabelled as XChaCha20-Poly1305 is refused too.
        let mut up = unhex(AES_GCM_FIXTURE);
        up[0] = Format::XChaCha20Poly1305.byte();
        let s = Sealed::parse(&up).unwrap();
        assert_eq!(s.format, Format::XChaCha20Poly1305);
        assert!(open(&key(1), &s, &f).is_err());
    }

    #[test]
    fn blind_indexes_are_per_column_and_key() {
        let a = mac(&key(1), "patients", "email", b"a@example.com");
        assert_eq!(a, mac(&key(1), "patients", "email", b"a@example.com"));
        assert_ne!(a, mac(&key(2), "patients", "email", b"a@example.com"));
        assert_ne!(a, mac(&key(1), "patients", "phone", b"a@example.com"));
        assert_ne!(mac(&key(1), "ab", "c", b""), mac(&key(1), "a", "bc", b""));
    }

    #[test]
    fn identifiers_are_plain() {
        assert_eq!(ident("notes").unwrap(), "\"notes\"");
        assert_eq!(ident("app.notes_2").unwrap(), "\"app\".\"notes_2\"");
        for bad in ["", "Notes", "a;b", "a.b.c", "1a", "a\"b", "a b"] {
            assert!(ident(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_do_not_print() {
        assert_eq!(format!("{:?}", key(9)), "Key([redacted])");
    }

    fn sixteen() -> Padding {
        Padding::new(std::num::NonZeroUsize::new(16).unwrap())
    }

    /// At the bucket edges a padded value opens to exactly what was sealed, and every
    /// length within one bucket seals to one ciphertext length.
    #[test]
    fn padded_values_round_trip_and_hide_their_length_within_a_bucket() {
        let f = fixture_field();
        let p = sixteen();
        let header = Format::XChaCha20Poly1305Padded.min_len();
        for (len, padded) in [(0, 16), (1, 16), (15, 16), (16, 32), (17, 32), (32, 48)] {
            let value: Vec<u8> = (0..len).map(|i| [0x80, 0x00, 0x41][i % 3]).collect();
            let ct = seal_padded(&key(1), 3, &f, &value, p);
            assert_eq!(ct[0], 3, "{len}");
            assert_eq!(ct.len(), header + padded, "{len}");
            let sealed = Sealed::parse(&ct).unwrap();
            assert_eq!(
                &open(&key(1), &sealed, &f).unwrap()[..],
                &value[..],
                "{len}"
            );
        }
        let lengths: Vec<usize> = (0..16)
            .map(|len| seal_padded(&key(1), 3, &f, &vec![b'x'; len], p).len())
            .collect();
        assert!(lengths.iter().all(|&l| l == header + 16), "{lengths:?}");
        assert_eq!(
            seal_padded(&key(1), 3, &f, b"ab", Padding::DEFAULT).len(),
            header + 64
        );
    }

    /// Any edited byte, a truncation, a relabelled format byte (padded presented as
    /// unpadded and the reverse) and an authentic seal of bytes that are not padding
    /// are all refused.
    #[test]
    fn a_tampered_padded_value_is_refused() {
        let f = fixture_field();
        let ct = seal_padded(&key(1), 3, &f, b"F32.1", sixteen());
        for i in 0..ct.len() {
            let mut bent = ct.clone();
            bent[i] ^= 0x01;
            if let Some(s) = Sealed::parse(&bent) {
                assert!(open(&key(1), &s, &f).is_err(), "byte {i}");
            }
        }
        assert!(open(&key(1), &Sealed::parse(&ct[..ct.len() - 1]).unwrap(), &f).is_err());
        let mut down = ct.clone();
        down[0] = Format::XChaCha20Poly1305.byte();
        assert!(open(&key(1), &Sealed::parse(&down).unwrap(), &f).is_err());
        let mut up = seal(&key(1), 3, &f, b"F32.1");
        up[0] = Format::XChaCha20Poly1305Padded.byte();
        assert!(open(&key(1), &Sealed::parse(&up).unwrap(), &f).is_err());
        // Labelled padded and authentic, but no `0x80` marker: malformed, not opened.
        let nonce = [7_u8; 24];
        let unpadded = seal_in(format::PADDED, &key(1), 3, &f, b"F32.1\0\0", nonce);
        assert!(matches!(
            open(&key(1), &Sealed::parse(&unpadded).unwrap(), &f),
            Err(CryptError::Malformed)
        ));
    }

    /// An unpadded seal is what it was: format `0x02`, the plaintext's length plus the
    /// overhead, and its bytes back on opening, trailing `0x80` and zeros included.
    #[test]
    fn unpadded_values_are_unaffected() {
        let f = fixture_field();
        for value in [
            &b""[..],
            b"F32.1",
            b"ends in a marker\x80",
            b"zeros\x80\0\0",
        ] {
            let ct = seal(&key(1), 3, &f, value);
            assert_eq!(ct[0], Format::XChaCha20Poly1305.byte());
            assert_eq!(ct.len(), Format::XChaCha20Poly1305.min_len() + value.len());
            assert_eq!(
                &open(&key(1), &Sealed::parse(&ct).unwrap(), &f).unwrap()[..],
                value
            );
        }
    }

    /// Moving a padded value to another key keeps it padded and its length unchanged;
    /// an unpadded one stays unpadded.
    #[test]
    fn resealing_keeps_the_padding() {
        let f = fixture_field();
        let ct = seal_padded(&key(1), 3, &f, b"F32.1", sixteen());
        let moved = reseal(&key(1), &Sealed::parse(&ct).unwrap(), &key(2), 4, &f).unwrap();
        assert_eq!((moved[0], moved.len()), (3, ct.len()));
        let s = Sealed::parse(&moved).unwrap();
        assert_eq!(s.version, 4);
        assert_eq!(&open(&key(2), &s, &f).unwrap()[..], b"F32.1");
        let plain = seal(&key(1), 3, &f, b"F32.1");
        let moved = reseal(&key(1), &Sealed::parse(&plain).unwrap(), &key(2), 4, &f).unwrap();
        assert_eq!((moved[0], moved.len()), (2, plain.len()));
        assert!(Format::XChaCha20Poly1305Padded.is_current() && !Format::AesGcm.is_current());
    }
}
