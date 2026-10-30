//! A KEK inside a `YubiHSM 2` (feature `yubihsm`).
//!
//! The KEK is a wrap key object (AES-256-CCM) in the HSM with the `wrap-data` and
//! `unwrap-data` capabilities. Data keys go to the HSM to be wrapped and come back
//! wrapped; the wrap key never leaves it. Each wrap carries SHA-256 of its context
//! ahead of the key, checked on unwrap, since the HSM's wrap has no associated data.
//!
//! The HSM is reached through a connector: `yubihsm-connector` over HTTP (the usual
//! deployment: the daemon runs on the node the HSM is plugged into) or USB directly.
//! Commands are blocking, so they run on tokio's blocking pool; [`crate::Crypt`]
//! caches unwrapped data keys, so the HSM is asked once per key per process.
//!
//! Disaster recovery is a second HSM holding the same wrap key under the same object
//! id, so the KEK id matches (see the README's "Field encryption").

use std::fmt;
use std::sync::Arc;

use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use yubihsm::{Capability, Client, Connector, Credentials, object, wrap};
use zeroize::Zeroizing;

use crate::kek::{KekError, KekProvider};

/// The two HSM commands the provider uses, so tests can stand in for a device.
trait Device: Send + Sync {
    fn wrap_data(&self, wrap_key: object::Id, plaintext: Vec<u8>) -> Result<Vec<u8>, String>;
    fn unwrap_data(&self, wrap_key: object::Id, message: Vec<u8>) -> Result<Vec<u8>, String>;
}

impl Device for Client {
    fn wrap_data(&self, wrap_key: object::Id, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
        Client::wrap_data(self, wrap_key, plaintext)
            .map(wrap::Message::into_vec)
            .map_err(|e| e.to_string())
    }

    fn unwrap_data(&self, wrap_key: object::Id, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let message = wrap::Message::from_vec(message).map_err(|e| e.to_string())?;
        Client::unwrap_data(self, wrap_key, message).map_err(|e| e.to_string())
    }
}

/// A KEK that is a wrap key in a `YubiHSM 2`. Its id is `yubihsm:<object id>`, as
/// `yubihsm:0x0064`.
pub struct YubiHsmKek {
    device: Arc<dyn Device>,
    wrap_key: object::Id,
    id: String,
}

impl fmt::Debug for YubiHsmKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YubiHsmKek")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl YubiHsmKek {
    /// Open a session through `connector` with `credentials` (an authentication key
    /// id and its password; never the factory default in production), and check that
    /// `wrap_key` is an AES-256-CCM wrap key with `wrap-data` and `unwrap-data`.
    /// Blocking: call it at startup, or in `spawn_blocking`.
    pub fn open(
        connector: Connector,
        credentials: Credentials,
        wrap_key: object::Id,
    ) -> Result<Self, KekError> {
        let client = Client::open(connector, credentials, true)
            .map_err(|e| KekError::Unavailable(e.to_string()))?;
        let info = client
            .get_object_info(wrap_key, object::Type::WrapKey)
            .map_err(|e| KekError::Config(format!("wrap key {wrap_key:#06x}: {e}")))?;
        let needed = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        if !info.capabilities.contains(needed) {
            return Err(KekError::Config(format!(
                "wrap key {wrap_key:#06x} lacks wrap-data or unwrap-data"
            )));
        }
        if info.algorithm != yubihsm::Algorithm::Wrap(wrap::Algorithm::Aes256Ccm) {
            return Err(KekError::Config(format!(
                "wrap key {wrap_key:#06x} is not AES-256-CCM"
            )));
        }
        Ok(Self::with_device(Arc::new(client), wrap_key))
    }

    /// [`YubiHsmKek::open`] through `yubihsm-connector` at `addr:port` (it listens on
    /// `127.0.0.1:12345` by default), authenticating as `auth_key` with `password`.
    pub fn http(
        addr: &str,
        port: u16,
        auth_key: object::Id,
        password: &[u8],
        wrap_key: object::Id,
    ) -> Result<Self, KekError> {
        let config = yubihsm::HttpConfig {
            addr: addr.into(),
            port,
            ..yubihsm::HttpConfig::default()
        };
        Self::open(
            Connector::http(&config),
            Credentials::from_password(auth_key, password),
            wrap_key,
        )
    }

    fn with_device(device: Arc<dyn Device>, wrap_key: object::Id) -> Self {
        Self {
            device,
            wrap_key,
            id: format!("yubihsm:{wrap_key:#06x}"),
        }
    }
}

impl KekProvider for YubiHsmKek {
    fn kek_id(&self) -> &str {
        &self.id
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn knows(&self, kek_id: &str) -> bool {
        kek_id == self.id
    }

    fn wrap<'a>(
        &'a self,
        key: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, KekError>> {
        let mut plaintext = Zeroizing::new(Sha256::digest(context).to_vec());
        plaintext.extend_from_slice(key);
        let device = self.device.clone();
        let wrap_key = self.wrap_key;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || device.wrap_data(wrap_key, plaintext.to_vec()))
                .await
                .map_err(|e| KekError::Unavailable(e.to_string()))?
                .map_err(KekError::Unavailable)
        })
    }

    fn unwrap<'a>(
        &'a self,
        kek_id: &'a str,
        wrapped: &'a [u8],
        context: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, KekError>> {
        let device = self.device.clone();
        let wrap_key = self.wrap_key;
        let message = wrapped.to_vec();
        Box::pin(async move {
            if kek_id != self.id {
                return Err(KekError::UnknownKek(kek_id.into()));
            }
            let plain = Zeroizing::new(
                tokio::task::spawn_blocking(move || device.unwrap_data(wrap_key, message))
                    .await
                    .map_err(|e| KekError::Unavailable(e.to_string()))?
                    // The HSM refuses a message that does not authenticate.
                    .map_err(|_| KekError::Refused(kek_id.into()))?,
            );
            let digest = Sha256::digest(context);
            if plain.len() < digest.len() || !bool::from(plain[..digest.len()].ct_eq(&digest)) {
                return Err(KekError::Refused(kek_id.into()));
            }
            Ok(Zeroizing::new(plain[digest.len()..].to_vec()))
        })
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use yubihsm::{Domain, object};

    use super::*;

    /// Stands in for the HSM's wrap-data and unwrap-data, which `MockHsm` lacks.
    struct Fake(Aes256Gcm);

    impl Device for Fake {
        fn wrap_data(&self, _: object::Id, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
            let mut out = vec![7_u8; 12];
            out.extend(
                self.0
                    .encrypt(&Nonce::from([7; 12]), &plaintext[..])
                    .unwrap(),
            );
            Ok(out)
        }

        fn unwrap_data(&self, _: object::Id, message: Vec<u8>) -> Result<Vec<u8>, String> {
            let (nonce, sealed) = message.split_at(12);
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| "short".to_owned())?;
            self.0
                .decrypt(&Nonce::from(nonce), sealed)
                .map_err(|_| "refused".into())
        }
    }

    fn fake() -> YubiHsmKek {
        YubiHsmKek::with_device(Arc::new(Fake(Aes256Gcm::new(&[3; 32].into()))), 0x64)
    }

    #[tokio::test]
    async fn a_wrap_is_bound_to_its_context() {
        let kek = fake();
        assert_eq!(kek.kek_id(), "yubihsm:0x0064");
        assert!(kek.is_hardware());
        let wrapped = kek.wrap(b"data key", b"ctx-1").await.unwrap();
        assert_eq!(
            &kek.unwrap("yubihsm:0x0064", &wrapped, b"ctx-1")
                .await
                .unwrap()[..],
            b"data key"
        );
        assert!(matches!(
            kek.unwrap("yubihsm:0x0064", &wrapped, b"ctx-2").await,
            Err(KekError::Refused(_))
        ));
        assert!(matches!(
            kek.unwrap("yubihsm:0x0065", &wrapped, b"ctx-1").await,
            Err(KekError::UnknownKek(_))
        ));
        let mut bent = wrapped;
        bent[15] ^= 1;
        assert!(matches!(
            kek.unwrap("yubihsm:0x0064", &bent, b"ctx-1").await,
            Err(KekError::Refused(_))
        ));
    }

    fn mock_with_wrap_key(capabilities: Capability, algorithm: wrap::Algorithm) -> Connector {
        let connector = Connector::mockhsm();
        let client = Client::open(connector.clone(), Credentials::default(), true).unwrap();
        let len = if algorithm == wrap::Algorithm::Aes256Ccm {
            32
        } else {
            16
        };
        client
            .put_wrap_key(
                0x64,
                object::Label::from("owt-crypt kek"),
                Domain::DOM1,
                capabilities,
                Capability::empty(),
                algorithm,
                vec![9_u8; len],
            )
            .unwrap();
        connector
    }

    #[test]
    fn open_checks_the_wrap_key() {
        let both = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        let ok = YubiHsmKek::open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            Credentials::default(),
            0x64,
        )
        .unwrap();
        assert_eq!(ok.kek_id(), "yubihsm:0x0064");
        let missing = YubiHsmKek::open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            Credentials::default(),
            0x65,
        );
        assert!(matches!(missing, Err(KekError::Config(_))));
        let wrap_only = YubiHsmKek::open(
            mock_with_wrap_key(Capability::WRAP_DATA, wrap::Algorithm::Aes256Ccm),
            Credentials::default(),
            0x64,
        );
        assert!(matches!(wrap_only, Err(KekError::Config(_))));
        let short = YubiHsmKek::open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes128Ccm),
            Credentials::default(),
            0x64,
        );
        assert!(matches!(short, Err(KekError::Config(_))));
        let refused = YubiHsmKek::open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            Credentials::from_password(1, b"not the password"),
            0x64,
        );
        assert!(matches!(refused, Err(KekError::Unavailable(_))));
    }
}
