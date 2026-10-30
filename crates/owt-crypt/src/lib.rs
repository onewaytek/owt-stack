//! Envelope encryption of fields, with blind indexes for equality search.
//!
//! * **Data keys.** Each scope (a tenant) has its own AES-256 data keys, versioned,
//!   stored in `owt_crypt_keys` only wrapped by a KEK ([`kek::KekProvider`]). The
//!   newest version encrypts; every version decrypts. [`Crypt::rotate`] adds a
//!   version, and [`Crypt::reencrypt_column`] moves a column's values onto it.
//! * **Fields.** [`Crypt::encrypt`] seals a value with AES-256-GCM under its scope's
//!   current data key. The associated data binds the ciphertext to its [`Field`]
//!   (scope, table, column and row), so a value copied to another row, column or
//!   tenant does not decrypt there. The ciphertext is self-describing: format byte,
//!   key version, nonce, sealed bytes ([`format`]).
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
//! * **Shredding.** [`Crypt::shred`] deletes a scope's keys and records a tombstone, so
//!   the scope can never get keys again. Another replica's cache can still decrypt for
//!   up to the cache TTL after a shred; that TTL is the shred's latency.
//!
//! # Limits
//!
//! * A data key seals with random 96-bit nonces, so one key is good for about 2^32
//!   messages (NIST SP 800-38D). A high-volume scope, and every re-encryption, count
//!   against it: [`Crypt::rotate`] data keys well before that, yearly or every N writes.
//! * Concurrent [`Crypt::rotate`] calls may each add a version. That is harmless: the
//!   newest encrypts and all decrypt.
//! * AES-GCM is not key-committing. Keys are chosen by (scope, version) from the
//!   database and the associated data carries both, so this has no practical attack
//!   here.
//! * The `hmac` and `sha2` states derived from an index key are not zeroized.
//! * A `LocalKek` read from an environment variable leaves the secret in the process
//!   environment for the process's life; prefer `from_file`.

pub mod format;
pub mod kek;
mod migrations;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use migrations::{LEDGER, LOCK_ID, migrate, migrator};
pub use zeroize;

use crate::format::{Sealed, lp};
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

/// Why an operation failed. None carries a key or a plaintext.
#[derive(Debug, thiserror::Error)]
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
    cache_ttl: Duration,
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
            cache_ttl: DEFAULT_CACHE_TTL,
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
                return Ok(v);
            }
        }
    }

    /// The current version of `scope`'s data key, made if there is none.
    pub async fn current_version(&self, scope: &str) -> Result<u32, CryptError> {
        check_scope(scope)?;
        Ok(self.current(scope, Purpose::Data).await?.0)
    }

    /// `ciphertext` sealed again under its scope's current data key, or `None` when it
    /// already is.
    pub async fn reencrypt(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptError> {
        check_field(field)?;
        let sealed = Sealed::parse(ciphertext).ok_or(CryptError::Malformed)?;
        let (version, key) = self.current(field.scope, Purpose::Data).await?;
        if sealed.version == version {
            return Ok(None);
        }
        let old = self.key(field.scope, Purpose::Data, sealed.version).await?;
        let plain = open(&old, &sealed, field)?;
        Ok(Some(seal(&key, version, field, &plain)))
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
        if sealed.version == *version {
            return Ok(None);
        }
        let old = self.key(field.scope, Purpose::Data, sealed.version).await?;
        let plain = open(&old, &sealed, field)?;
        Ok(Some(seal(key, *version, field, &plain)))
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
    let cipher = Aes256Gcm::new_from_slice(&key.0[..]).expect("a data key is 32 bytes");
    let mut nonce = [0_u8; format::NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let aad = format::aad(field, version);
    let sealed = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-GCM seals any length a Vec holds");
    format::assemble(version, &nonce, &sealed)
}

fn open(
    key: &Key,
    sealed: &Sealed<'_>,
    field: &Field<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let cipher = Aes256Gcm::new_from_slice(&key.0[..]).expect("a data key is 32 bytes");
    let aad = format::aad(field, sealed.version);
    cipher
        .decrypt(
            &Nonce::from(sealed.nonce),
            Payload {
                msg: sealed.body,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptError::Refused {
            table: field.table.into(),
            column: field.column.into(),
        })
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
}
