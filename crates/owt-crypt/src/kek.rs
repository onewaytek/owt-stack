//! Key-encryption keys: what wraps each data key.
//!
//! A [`KekProvider`] wraps a data key under its current KEK and unwraps one wrapped
//! under any KEK it knows. Every wrap is bound to a context (the data key's scope,
//! purpose and version), so a wrapped key copied onto another key's row does not
//! unwrap there.
//!
//! * [`LocalKek`]: AES-256-GCM keys held in the process, read from an environment
//!   variable or a file. For development, CI and staging.
//! * `YubiHsmKek` (feature `yubihsm`): a wrap key inside a `YubiHSM 2`, which never
//!   leaves it.
//! * [`KekChain`]: one current provider and the ones before it, to move every data key
//!   from one to the next ([`crate::Crypt::rewrap`]).
//!
//! The trait is the seam for any other: a KMS, a Vault or `OpenBao` transit engine, a
//! PKCS#11 HSM.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::future::BoxFuture;
use rand::Rng;
use zeroize::Zeroizing;

/// Why a KEK operation failed.
#[derive(Debug, thiserror::Error)]
pub enum KekError {
    /// No provider here knows the KEK a key was wrapped under.
    #[error("no KEK provider knows the KEK {0:?}")]
    UnknownKek(String),
    /// The wrapped key did not unwrap: tampered with, moved to another row, or
    /// wrapped under another key of the same name.
    #[error("a wrapped data key did not unwrap under {0:?}")]
    Refused(String),
    /// The provider could not be reached or refused the session.
    #[error("the KEK provider is unavailable: {0}")]
    Unavailable(String),
    /// The provider's configuration is wrong.
    #[error("the KEK configuration is invalid: {0}")]
    Config(String),
}

/// Wraps and unwraps data keys. Object-safe, so an app picks its provider at runtime
/// (`Arc<dyn KekProvider>`): hardware in production, [`LocalKek`] elsewhere.
pub trait KekProvider: Send + Sync + fmt::Debug {
    /// The current KEK's id, stored beside every key it wraps (`local:2026-10`,
    /// `yubihsm:0x0064`).
    fn kek_id(&self) -> &str;

    /// Whether the current KEK lives in hardware it cannot be read out of.
    fn is_hardware(&self) -> bool;

    /// Whether this provider can unwrap keys wrapped under `kek_id`.
    fn knows(&self, kek_id: &str) -> bool;

    /// Wrap `key` under the current KEK, bound to `context`.
    fn wrap<'a>(
        &'a self,
        key: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, KekError>>;

    /// Unwrap `wrapped`, wrapped under `kek_id` and bound to `context`.
    fn unwrap<'a>(
        &'a self,
        kek_id: &'a str,
        wrapped: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, KekError>>;
}

/// AES-256-GCM KEKs held in memory: the first is current, the rest unwrap keys
/// wrapped before a rotation. Software: anyone who reads the environment or the file
/// holds every key it wraps. Not for production health data.
pub struct LocalKek {
    keys: Vec<(String, Zeroizing<[u8; 32]>)>,
}

impl fmt::Debug for LocalKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalKek")
            .field(
                "ids",
                &self.keys.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl LocalKek {
    /// Parse a keyring: `name:base64,name:base64,...`, the current KEK first. A name
    /// is 1 to 64 of ASCII letters, digits, `_`, `.` and `-`; a key is 32 bytes in
    /// standard base64. Whitespace and newlines between entries are ignored.
    pub fn parse(keyring: &str) -> Result<Self, KekError> {
        let mut keys: Vec<(String, Zeroizing<[u8; 32]>)> = Vec::new();
        for entry in keyring
            .split([',', '\n'])
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            let (name, b64) = entry
                .split_once(':')
                .ok_or_else(|| KekError::Config("an entry is `name:base64key`".into()))?;
            let ok_name = (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
            if !ok_name {
                return Err(KekError::Config(format!(
                    "a KEK name is [A-Za-z0-9_.-]{{1,64}}: {name:?}"
                )));
            }
            let id = format!("local:{name}");
            if keys.iter().any(|(k, _)| *k == id) {
                return Err(KekError::Config(format!("the KEK {name:?} is named twice")));
            }
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(b64.trim())
                    .map_err(|_| KekError::Config(format!("the KEK {name:?} is not base64")))?,
            );
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| KekError::Config(format!("the KEK {name:?} is not 32 bytes")))?;
            keys.push((id, Zeroizing::new(key)));
        }
        if keys.is_empty() {
            return Err(KekError::Config("the keyring holds no KEK".into()));
        }
        Ok(Self { keys })
    }

    /// The keyring in the environment variable `name`.
    pub fn from_env(name: &str) -> Result<Self, KekError> {
        let value = Zeroizing::new(
            std::env::var(name).map_err(|_| KekError::Config(format!("{name} is not set")))?,
        );
        Self::parse(&value)
    }

    /// The keyring in the file at `path` (a mounted Secret, say).
    pub fn from_file(path: &Path) -> Result<Self, KekError> {
        let value = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| KekError::Config(format!("reading {}: {e}", path.display())))?,
        );
        Self::parse(&value)
    }

    /// A fresh keyring entry, `name:base64`, from a cryptographically secure generator
    /// (rand's thread generator, seeded by the OS): what an
    /// operator puts first in the keyring to rotate.
    #[must_use]
    pub fn generate_entry(name: &str) -> Zeroizing<String> {
        let mut key = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(&mut key[..]);
        Zeroizing::new(format!("{name}:{}", STANDARD.encode(&key[..])))
    }

    fn key(&self, kek_id: &str) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .find(|(id, _)| id == kek_id)
            .map(|(_, k)| &**k)
    }
}

impl KekProvider for LocalKek {
    fn kek_id(&self) -> &str {
        &self.keys[0].0
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn knows(&self, kek_id: &str) -> bool {
        self.key(kek_id).is_some()
    }

    fn wrap<'a>(
        &'a self,
        key: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, KekError>> {
        Box::pin(async move {
            let cipher = Aes256Gcm::new_from_slice(&self.keys[0].1[..])
                .map_err(|_| KekError::Config("a KEK is 32 bytes".into()))?;
            let mut nonce = [0_u8; 12];
            rand::rng().fill_bytes(&mut nonce);
            let sealed = cipher
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: key,
                        aad: context,
                    },
                )
                .map_err(|_| KekError::Refused(self.kek_id().into()))?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&sealed);
            Ok(out)
        })
    }

    fn unwrap<'a>(
        &'a self,
        kek_id: &'a str,
        wrapped: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, KekError>> {
        Box::pin(async move {
            let kek = self
                .key(kek_id)
                .ok_or_else(|| KekError::UnknownKek(kek_id.into()))?;
            if wrapped.len() < 12 + 16 {
                return Err(KekError::Refused(kek_id.into()));
            }
            let cipher = Aes256Gcm::new_from_slice(&kek[..])
                .map_err(|_| KekError::Config("a KEK is 32 bytes".into()))?;
            let (nonce, sealed) = wrapped.split_at(12);
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| KekError::Refused(kek_id.into()))?;
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: sealed,
                        aad: context,
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| KekError::Refused(kek_id.into()))
        })
    }
}

/// A current provider and the providers before it: wraps with the current, unwraps
/// with whichever knows the key's KEK. Moving from one KEK to another (a software
/// KEK to an HSM, one HSM wrap key to the next) is a chain plus
/// [`crate::Crypt::rewrap`]; once every key is rewrapped, the old provider goes.
#[derive(Debug)]
pub struct KekChain {
    current: Arc<dyn KekProvider>,
    previous: Vec<Arc<dyn KekProvider>>,
}

impl KekChain {
    /// `current` wraps; `current`, then each of `previous` in order, unwraps.
    #[must_use]
    pub fn new(current: Arc<dyn KekProvider>, previous: Vec<Arc<dyn KekProvider>>) -> Self {
        Self { current, previous }
    }

    fn for_kek(&self, kek_id: &str) -> Option<&Arc<dyn KekProvider>> {
        std::iter::once(&self.current)
            .chain(&self.previous)
            .find(|p| p.knows(kek_id))
    }
}

impl KekProvider for KekChain {
    fn kek_id(&self) -> &str {
        self.current.kek_id()
    }

    fn is_hardware(&self) -> bool {
        self.current.is_hardware()
    }

    fn knows(&self, kek_id: &str) -> bool {
        self.for_kek(kek_id).is_some()
    }

    fn wrap<'a>(
        &'a self,
        key: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, KekError>> {
        self.current.wrap(key, context)
    }

    fn unwrap<'a>(
        &'a self,
        kek_id: &'a str,
        wrapped: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, KekError>> {
        match self.for_kek(kek_id) {
            Some(p) => p.unwrap(kek_id, wrapped, context),
            None => Box::pin(async move { Err(KekError::UnknownKek(kek_id.into())) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_local_kek_wraps_bound_to_its_context() {
        let kek = LocalKek::parse(&LocalKek::generate_entry("a")).unwrap();
        assert_eq!(kek.kek_id(), "local:a");
        let wrapped = kek
            .wrap(b"0123456789abcdef0123456789abcdef", b"ctx-1")
            .await
            .unwrap();
        let key = kek.unwrap("local:a", &wrapped, b"ctx-1").await.unwrap();
        assert_eq!(&key[..], b"0123456789abcdef0123456789abcdef");
        assert!(matches!(
            kek.unwrap("local:a", &wrapped, b"ctx-2").await,
            Err(KekError::Refused(_))
        ));
        assert!(matches!(
            kek.unwrap("local:b", &wrapped, b"ctx-1").await,
            Err(KekError::UnknownKek(_))
        ));
        let mut bent = wrapped.clone();
        bent[20] ^= 1;
        assert!(kek.unwrap("local:a", &bent, b"ctx-1").await.is_err());
        assert!(
            kek.unwrap("local:a", &wrapped[..10], b"ctx-1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_rotated_keyring_still_unwraps_the_old_kek() {
        let old = LocalKek::generate_entry("old");
        let wrapped = LocalKek::parse(&old)
            .unwrap()
            .wrap(b"k", b"c")
            .await
            .unwrap();
        let new = format!("{}\n{}", *LocalKek::generate_entry("new"), *old);
        let ring = LocalKek::parse(&new).unwrap();
        assert_eq!(ring.kek_id(), "local:new");
        assert_eq!(
            &ring.unwrap("local:old", &wrapped, b"c").await.unwrap()[..],
            b"k"
        );
        let chain = KekChain::new(
            Arc::new(LocalKek::parse(&LocalKek::generate_entry("next")).unwrap()),
            vec![Arc::new(ring)],
        );
        assert_eq!(chain.kek_id(), "local:next");
        assert!(chain.knows("local:old") && !chain.knows("local:other"));
        assert_eq!(
            &chain.unwrap("local:old", &wrapped, b"c").await.unwrap()[..],
            b"k"
        );
    }

    #[test]
    fn keyrings_are_checked() {
        for bad in [
            "",
            "nokey",
            "a:notbase64!",
            "a:AAAA",
            "bad name:AAAA",
            &format!("{0},{0}", *LocalKek::generate_entry("x")),
        ] {
            assert!(LocalKek::parse(bad).is_err(), "{bad}");
        }
        let kek = LocalKek::parse(&LocalKek::generate_entry("x")).unwrap();
        assert!(!format!("{kek:?}").contains(&STANDARD.encode(&kek.keys[0].1[..])));
    }
}
