//! A KEK inside a `YubiHSM 2` (feature `yubihsm`).
//!
//! The KEK is a wrap key object (AES-256-CCM) in the HSM with the `wrap-data` and
//! `unwrap-data` capabilities, and optionally `exportable-under-wrap` (for the backup).
//! [`YubiHsmKek::open`] refuses one that also has `export-wrapped` or `import-wrapped`,
//! which would make it a transport key, and round-trips a random key before returning. Data keys go to the HSM to be wrapped and come back
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
use yubihsm::{Capability, Client, Connector, Credentials, client, device, object, wrap};
use zeroize::Zeroizing;

use crate::kek::{KekError, KekProvider};

/// Why the device did not unwrap a message.
#[derive(Debug, PartialEq, Eq)]
enum Unwrapped {
    /// The message is not a wrap message, or the device rejected it as invalid or
    /// not authentic: tampered, moved, or wrapped under another key.
    Refused,
    /// The device or the path to it failed: an outage, a busy device, a lost session.
    Unavailable(String),
}

/// Sort a failed unwrap by the error the client reported. Only a device-reported
/// invalid-data, wrong-length or authentication failure for the message is a refusal;
/// connection, session and protocol errors, and every other device error, are not
/// evidence about the message.
fn classify(kind: client::ErrorKind, device: Option<device::ErrorKind>) -> bool {
    matches!(
        (kind, device),
        (
            client::ErrorKind::DeviceError,
            Some(
                device::ErrorKind::InvalidData
                    | device::ErrorKind::WrongLength
                    | device::ErrorKind::AuthenticationFailed
            )
        )
    )
}

/// The HSM commands the provider uses, so tests can stand in for a device.
trait Device: Send + Sync {
    fn wrap_data(&self, wrap_key: object::Id, plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn unwrap_data(
        &self,
        wrap_key: object::Id,
        message: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Unwrapped>;
}

impl Device for Client {
    fn wrap_data(&self, wrap_key: object::Id, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // The yubihsm API takes an owned Vec and drops it without zeroizing: this one
        // copy of the plaintext is unavoidable. It is the digest and a wrapped key
        // (never a data key's plaintext beyond the HSM call), and short-lived.
        Client::wrap_data(self, wrap_key, plaintext.to_vec())
            .map(wrap::Message::into_vec)
            .map_err(|e| e.to_string())
    }

    fn unwrap_data(
        &self,
        wrap_key: object::Id,
        message: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Unwrapped> {
        let message = wrap::Message::from_vec(message).map_err(|_| Unwrapped::Refused)?;
        Client::unwrap_data(self, wrap_key, message)
            .map(Zeroizing::new)
            .map_err(|e| {
                if classify(*e.kind(), e.device_error()) {
                    Unwrapped::Refused
                } else {
                    Unwrapped::Unavailable(e.to_string())
                }
            })
    }
}

/// What the HSM wraps: SHA-256 of `context`, then `key`.
fn frame(context: &[u8], key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut plaintext = Zeroizing::new(Sha256::digest(context).to_vec());
    plaintext.extend_from_slice(key);
    plaintext
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
    /// `wrap_key` is an AES-256-CCM wrap key with `wrap-data` and `unwrap-data` and
    /// without `export-wrapped` or `import-wrapped` (it may have
    /// `exportable-under-wrap`). Then wrap and unwrap 32 random bytes as a self-test,
    /// which also proves the session's authentication key may use the wrap key.
    /// Blocking: call it at startup, or in `spawn_blocking`.
    pub fn open(
        connector: Connector,
        credentials: Credentials,
        wrap_key: object::Id,
    ) -> Result<Self, KekError> {
        Self::open_checked(connector, credentials, wrap_key, true)
    }

    /// [`YubiHsmKek::open`], with the round trip optional: `MockHsm` has no
    /// `wrap-data`, so tests of the checks skip it.
    fn open_checked(
        connector: Connector,
        credentials: Credentials,
        wrap_key: object::Id,
        self_test: bool,
    ) -> Result<Self, KekError> {
        let credentials_id = credentials.authentication_key_id;
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
        if info
            .capabilities
            .intersects(Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED)
        {
            return Err(KekError::Config(format!(
                "wrap key {wrap_key:#06x} has export-wrapped or import-wrapped: \
                 a KEK is not a transport key"
            )));
        }
        let auth_id = credentials_id;
        let auth = client
            .get_object_info(auth_id, object::Type::AuthenticationKey)
            .map_err(|e| KekError::Config(format!("authentication key {auth_id:#06x}: {e}")))?;
        let forbidden = Capability::EXPORT_WRAPPED
            | Capability::IMPORT_WRAPPED
            | Capability::PUT_WRAP_KEY
            | Capability::GENERATE_WRAP_KEY
            | Capability::DELETE_WRAP_KEY;
        if auth.capabilities.intersects(forbidden) {
            return Err(KekError::Config(format!(
                "authentication key {auth_id:#06x} may export, import, create or delete \
                 wrap keys: the app's key holds wrap-data and unwrap-data only"
            )));
        }
        let kek = Self::with_device(Arc::new(client), wrap_key);
        if self_test {
            kek.self_test()?;
        }
        Ok(kek)
    }

    /// Wrap and unwrap 32 random bytes under a test context.
    fn self_test(&self) -> Result<(), KekError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut key[..]).map_err(|e| KekError::Unavailable(e.to_string()))?;
        let context = b"owt-crypt/self-test";
        let wrapped = self
            .device
            .wrap_data(self.wrap_key, &frame(context, &key[..]))
            .map_err(|e| KekError::Config(format!("{} self-test wrap: {e}", self.id)))?;
        let plain = self
            .device
            .unwrap_data(self.wrap_key, wrapped)
            .map_err(|_| KekError::Config(format!("{} self-test unwrap failed", self.id)))?;
        if !bool::from(plain[..].ct_eq(&frame(context, &key[..])[..])) {
            return Err(KekError::Config(format!(
                "{} self-test returned other bytes",
                self.id
            )));
        }
        Ok(())
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
        let plaintext = frame(context, key);
        let device = self.device.clone();
        let wrap_key = self.wrap_key;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || device.wrap_data(wrap_key, &plaintext))
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
            // A device error is a refusal when the device still answers (a message that
            // does not authenticate), and an outage when a probe of the wrap key fails.
            let plain = tokio::task::spawn_blocking(move || device.unwrap_data(wrap_key, message))
                .await
                .map_err(|e| KekError::Unavailable(e.to_string()))?
                .map_err(|e| match e {
                    Unwrapped::Refused => KekError::Refused(kek_id.into()),
                    Unwrapped::Unavailable(why) => KekError::Unavailable(why),
                })?;
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use yubihsm::{Domain, object};

    use super::*;

    /// Stands in for the HSM's wrap-data and unwrap-data, which `MockHsm` lacks.
    struct Fake(Aes256Gcm, Arc<AtomicBool>);

    impl Device for Fake {
        fn wrap_data(&self, _: object::Id, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = vec![7_u8; 12];
            out.extend(self.0.encrypt(&Nonce::from([7; 12]), plaintext).unwrap());
            Ok(out)
        }

        fn unwrap_data(
            &self,
            _: object::Id,
            message: Vec<u8>,
        ) -> Result<Zeroizing<Vec<u8>>, Unwrapped> {
            if !self.1.load(Ordering::SeqCst) {
                return Err(Unwrapped::Unavailable("usb gone".into()));
            }
            let (nonce, sealed) = message.split_at(12);
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| Unwrapped::Refused)?;
            self.0
                .decrypt(&Nonce::from(nonce), sealed)
                .map(Zeroizing::new)
                .map_err(|_| Unwrapped::Refused)
        }
    }

    fn fake() -> YubiHsmKek {
        fake_with(Arc::default())
    }

    /// `up` false takes the fake device away: every command fails.
    fn fake_with(up: Arc<AtomicBool>) -> YubiHsmKek {
        up.store(true, Ordering::SeqCst);
        YubiHsmKek::with_device(Arc::new(Fake(Aes256Gcm::new(&[3; 32].into()), up)), 0x64)
    }

    #[test]
    fn errors_are_sorted_by_what_the_device_reported() {
        use device::ErrorKind as D;
        for refused in [D::InvalidData, D::WrongLength, D::AuthenticationFailed] {
            assert!(classify(client::ErrorKind::DeviceError, Some(refused)));
        }
        for other in [
            D::SessionsFull,
            D::ObjectNotFound,
            D::InsufficientPermissions,
        ] {
            assert!(!classify(client::ErrorKind::DeviceError, Some(other)));
        }
        assert!(!classify(client::ErrorKind::DeviceError, None));
        for kind in [
            client::ErrorKind::ConnectorError,
            client::ErrorKind::ClosedSessionError,
            client::ErrorKind::CreateFailed,
            client::ErrorKind::ProtocolError,
            client::ErrorKind::ResponseError,
            client::ErrorKind::AuthenticationError,
        ] {
            assert!(!classify(kind, Some(D::InvalidData)), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn an_outage_is_not_a_refusal() {
        let up = Arc::new(AtomicBool::new(true));
        let kek = fake_with(up.clone());
        assert!(kek.self_test().is_ok());
        let wrapped = kek.wrap(b"data key", b"ctx").await.unwrap();
        up.store(false, Ordering::SeqCst);
        assert!(matches!(
            kek.unwrap("yubihsm:0x0064", &wrapped, b"ctx").await,
            Err(KekError::Unavailable(_))
        ));
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
        for (id, capabilities) in [
            (2, Capability::WRAP_DATA | Capability::UNWRAP_DATA),
            (
                3,
                Capability::WRAP_DATA | Capability::UNWRAP_DATA | Capability::EXPORT_WRAPPED,
            ),
        ] {
            client
                .put_authentication_key(
                    id,
                    object::Label::from("app"),
                    Domain::all(),
                    capabilities,
                    Capability::empty(),
                    yubihsm::authentication::Algorithm::YubicoAes,
                    yubihsm::authentication::Key::derive_from_password(b"app"),
                )
                .unwrap();
        }
        connector
    }

    /// The app's authentication key: wrap-data and unwrap-data only.
    fn app() -> Credentials {
        Credentials::from_password(2, b"app")
    }

    /// Opens with the self-test skipped: `MockHsm` panics on wrap-data, which the
    /// self-test needs. The self-test itself runs against `Fake`.
    fn open(
        connector: Connector,
        credentials: Credentials,
        id: object::Id,
    ) -> Result<YubiHsmKek, KekError> {
        YubiHsmKek::open_checked(connector, credentials, id, false)
    }

    #[test]
    fn open_refuses_a_transport_key() {
        let both = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        for extra in [Capability::EXPORT_WRAPPED, Capability::IMPORT_WRAPPED] {
            let r = open(
                mock_with_wrap_key(both | extra, wrap::Algorithm::Aes256Ccm),
                app(),
                0x64,
            );
            assert!(matches!(r, Err(KekError::Config(_))), "{extra:?}");
        }
        // `exportable-under-wrap` is allowed (the backup needs it).
        let ok = open(
            mock_with_wrap_key(
                both | Capability::EXPORTABLE_UNDER_WRAP,
                wrap::Algorithm::Aes256Ccm,
            ),
            app(),
            0x64,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn open_refuses_an_authentication_key_that_can_export() {
        let both = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        // The mock's default key holds every capability; id 3 holds export-wrapped.
        for credentials in [
            Credentials::default(),
            Credentials::from_password(3, b"app"),
        ] {
            let r = open(
                mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
                credentials,
                0x64,
            );
            assert!(matches!(r, Err(KekError::Config(_))));
        }
    }

    #[test]
    fn open_checks_the_wrap_key() {
        let both = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
        let ok = open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            app(),
            0x64,
        )
        .unwrap();
        assert_eq!(ok.kek_id(), "yubihsm:0x0064");
        let missing = open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            app(),
            0x65,
        );
        assert!(matches!(missing, Err(KekError::Config(_))));
        let wrap_only = open(
            mock_with_wrap_key(Capability::WRAP_DATA, wrap::Algorithm::Aes256Ccm),
            app(),
            0x64,
        );
        assert!(matches!(wrap_only, Err(KekError::Config(_))));
        let short = open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes128Ccm),
            app(),
            0x64,
        );
        assert!(matches!(short, Err(KekError::Config(_))));
        let refused = open(
            mock_with_wrap_key(both, wrap::Algorithm::Aes256Ccm),
            Credentials::from_password(1, b"not the password"),
            0x64,
        );
        assert!(matches!(refused, Err(KekError::Unavailable(_))));
    }
}
