//! A synchronous sealer for one scope, with its keys loaded ahead of time.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::format::Sealed;
use crate::{Crypt, CryptError, Field, Key, Purpose, ScopeState, check_field, mac, open, seal};

/// One scope's unwrapped keys, held so that sealing, opening and blind indexes need
/// no `.await`: for serde and template paths, `FromRow` decoding and other
/// synchronous code. Made by [`Crypt::sealer`], which does the asynchronous work
/// (the database, the KEK) once.
///
/// Its ciphertexts and its associated data are those of [`Crypt::encrypt`] and
/// [`Crypt::decrypt`], so the two APIs read each other's values.
///
/// # Staleness
///
/// A sealer is a snapshot. It seals, and computes blind indexes, only while the
/// snapshot is the scope's latest:
///
/// * [`Crypt::rotate`] or [`Crypt::shred`] on the same [`Crypt`] (or a clone) makes
///   it stale at once, through a shared counter: [`Sealer::seal`] and
///   [`Sealer::blind_index`] return [`CryptError::Stale`], so a new value never uses
///   an old key. It still opens old ciphertexts, which its keys still decrypt.
///   After a shred it refuses both, with [`CryptError::Shredded`].
/// * A rotation or shred on another replica is not visible to this process, so a
///   sealer is also bounded by a maximum age ([`Crypt::sealer_max_age`], by default
///   [`Crypt::cache_ttl`]): past it, every method returns [`CryptError::Stale`].
///   That bound is the longest another replica's rotation goes unseen here, and the
///   longest a shredded scope keeps opening here, as with the key cache.
///
/// Load a sealer per request or job, or call [`Sealer::refresh`] on `Stale`. Cloning
/// is cheap; clones share the keys, which are zeroized when the last one drops.
#[derive(Clone)]
pub struct Sealer {
    inner: Arc<Inner>,
}

struct Inner {
    scope: String,
    /// Every data key version of the scope at load time.
    data: BTreeMap<u32, Arc<Key>>,
    /// The newest data key's version.
    current: u32,
    /// The newest index key.
    index: (u32, Arc<Key>),
    state: Arc<ScopeState>,
    /// The scope's generation when loading began.
    generation: u64,
    loaded: Instant,
    max_age: Duration,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("scope", &self.inner.scope)
            .field("versions", &self.inner.data.keys().collect::<Vec<_>>())
            .field("keys", &"[redacted]")
            .finish()
    }
}

impl Crypt {
    /// A [`Sealer`] for `scope`: its current data key, every older data key version
    /// (to open values sealed before a rotation) and its current index key, loaded
    /// and unwrapped. Keys are made if the scope has none. Fails with
    /// [`CryptError::Shredded`] for a shredded scope.
    pub async fn sealer(&self, scope: &str) -> Result<Sealer, CryptError> {
        crate::check_scope(scope)?;
        let state = self.scope_state(scope);
        // Read before loading: a rotation that lands meanwhile leaves the snapshot
        // marked older than it is, which only makes it stale early.
        let generation = state.generation.load(Ordering::SeqCst);
        if state.shredded.load(Ordering::SeqCst) {
            return Err(CryptError::Shredded(scope.into()));
        }
        let (version, key) = self.current(scope, Purpose::Data).await?;
        let mut data = BTreeMap::from([(version, key)]);
        for v in self.versions(scope, Purpose::Data).await? {
            if let std::collections::btree_map::Entry::Vacant(slot) = data.entry(v) {
                match self.key(scope, Purpose::Data, v).await {
                    Ok(key) => {
                        slot.insert(key);
                    }
                    // Retired between the listing and the read.
                    Err(CryptError::NoKey { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let current = *data.keys().next_back().unwrap_or(&version);
        let index = self.current(scope, Purpose::Index).await?;
        Ok(Sealer {
            inner: Arc::new(Inner {
                scope: scope.into(),
                data,
                current,
                index,
                state,
                generation,
                loaded: Instant::now(),
                max_age: self.sealer_max_age.unwrap_or(self.cache_ttl),
            }),
        })
    }

    /// Bound a [`Sealer`]'s life to `age` (by default [`Crypt::cache_ttl`]): past
    /// it, the sealer returns [`CryptError::Stale`] from every method. It limits how
    /// long a rotation or shred on another replica goes unseen.
    #[must_use]
    pub fn sealer_max_age(mut self, age: Duration) -> Self {
        self.sealer_max_age = Some(age);
        self
    }

    /// The shared state of `scope`, made on first use.
    fn scope_state(&self, scope: &str) -> Arc<ScopeState> {
        self.scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(scope.to_owned())
            .or_default()
            .clone()
    }

    /// Mark the sealers of `scope` stale; `shredded` also makes them refuse to open.
    pub(crate) fn invalidate(&self, scope: &str, shredded: bool) {
        let state = self.scope_state(scope);
        if shredded {
            state.shredded.store(true, Ordering::SeqCst);
        }
        state.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl Sealer {
    /// The scope this sealer serves.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.inner.scope
    }

    /// The data key version [`Sealer::seal`] uses.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.inner.current
    }

    /// Whether [`Sealer::seal`] would refuse as stale or shredded: the scope was
    /// rotated or shredded here since loading, or the sealer is past its maximum age.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.check(true).is_err()
    }

    /// A sealer loaded afresh for the same scope, with the same [`Crypt`] settings.
    pub async fn refresh(&self, crypt: &Crypt) -> Result<Self, CryptError> {
        crypt.sealer(&self.inner.scope).await
    }

    /// Seal `plaintext` for `field` under the scope's data key as loaded. Fails with
    /// [`CryptError::Stale`] when the sealer is stale, [`CryptError::Shredded`] when
    /// the scope was shredded, and [`CryptError::Invalid`] when `field` is of another
    /// scope.
    pub fn seal(&self, field: &Field<'_>, plaintext: &[u8]) -> Result<Vec<u8>, CryptError> {
        self.check_field(field)?;
        self.check(true)?;
        let key = &self.inner.data[&self.inner.current];
        Ok(seal(key, self.inner.current, field, plaintext))
    }

    /// [`Sealer::seal`] of a string.
    pub fn seal_str(&self, field: &Field<'_>, plaintext: &str) -> Result<Vec<u8>, CryptError> {
        self.seal(field, plaintext.as_bytes())
    }

    /// Open a ciphertext sealed for `field`, under any data key version the sealer
    /// loaded. A version it did not load (made after loading) is
    /// [`CryptError::NotLoaded`]: [`Sealer::refresh`]. A sealer made stale by a
    /// rotation still opens; a shredded scope and a sealer past its maximum age do
    /// not.
    pub fn open(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        self.check_field(field)?;
        self.check(false)?;
        let sealed = Sealed::parse(ciphertext).ok_or(CryptError::Malformed)?;
        let key = self
            .inner
            .data
            .get(&sealed.version)
            .ok_or_else(|| CryptError::NotLoaded {
                scope: self.inner.scope.clone(),
                version: sealed.version,
            })?;
        open(key, &sealed, field)
    }

    /// [`Sealer::open`] of a string.
    pub fn open_string(
        &self,
        field: &Field<'_>,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<String>, CryptError> {
        let mut bytes = self.open(field, ciphertext)?;
        if std::str::from_utf8(&bytes).is_err() {
            return Err(CryptError::Malformed);
        }
        let taken = std::mem::take(&mut *bytes);
        Ok(Zeroizing::new(String::from_utf8(taken).unwrap_or_default()))
    }

    /// The blind index of `value` in the scope's `table.column`, under the index key
    /// as loaded; the same as [`Crypt::blind_index`]. It refuses as [`Sealer::seal`]
    /// does, so a stored index never uses an old index key.
    pub fn blind_index(
        &self,
        table: &str,
        column: &str,
        value: &[u8],
    ) -> Result<[u8; 32], CryptError> {
        self.check(true)?;
        Ok(mac(&self.inner.index.1, table, column, value))
    }

    fn check_field(&self, field: &Field<'_>) -> Result<(), CryptError> {
        check_field(field)?;
        if field.scope != self.inner.scope {
            return Err(CryptError::Invalid(format!(
                "a sealer for scope {:?} was given a field of scope {:?}",
                self.inner.scope, field.scope
            )));
        }
        Ok(())
    }

    /// Whether the sealer may be used: always not shredded and within its age; with
    /// `fresh`, also not superseded by a rotation here.
    fn check(&self, fresh: bool) -> Result<(), CryptError> {
        let i = &self.inner;
        if i.state.shredded.load(Ordering::SeqCst) {
            return Err(CryptError::Shredded(i.scope.clone()));
        }
        if i.loaded.elapsed() >= i.max_age
            || (fresh && i.state.generation.load(Ordering::SeqCst) != i.generation)
        {
            return Err(CryptError::Stale(i.scope.clone()));
        }
        Ok(())
    }
}
