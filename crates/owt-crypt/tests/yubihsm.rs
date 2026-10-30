//! Against a real `YubiHSM` 2 through `yubihsm-connector`; skipped unless
//! `OWT_YUBIHSM_CONNECTOR` (`host:port`) is set. Also read: `OWT_YUBIHSM_AUTH_KEY`
//! (object id, default 2), `OWT_YUBIHSM_PASSWORD` and `OWT_YUBIHSM_WRAP_KEY` (object
//! id, default 100). The authentication key must hold `wrap-data` and `unwrap-data`
//! only, and the wrap key must be AES-256-CCM with those two capabilities.
#![cfg(feature = "yubihsm")]

use owt_crypt::kek::KekProvider;
use owt_crypt::yubihsm::YubiHsmKek;

#[tokio::test]
async fn a_real_device_opens_self_tests_and_round_trips() {
    let Ok(connector) = std::env::var("OWT_YUBIHSM_CONNECTOR") else {
        return;
    };
    let (host, port) = connector.rsplit_once(':').expect("host:port");
    let id = |name: &str, default: u16| {
        std::env::var(name).map_or(default, |v| v.parse().expect("an object id"))
    };
    let password = std::env::var("OWT_YUBIHSM_PASSWORD").expect("OWT_YUBIHSM_PASSWORD");
    let (host, port) = (host.to_owned(), port.parse().expect("a port"));
    let (auth, wrap) = (
        id("OWT_YUBIHSM_AUTH_KEY", 2),
        id("OWT_YUBIHSM_WRAP_KEY", 100),
    );
    // `open` runs the capability checks and the self-test.
    let kek = tokio::task::spawn_blocking(move || {
        YubiHsmKek::http(&host, port, auth, password.as_bytes(), wrap)
    })
    .await
    .unwrap()
    .expect("the device opens");
    let key = [9_u8; 32];
    let wrapped = kek.wrap(&key, b"ctx").await.unwrap();
    let back = kek.unwrap(kek.kek_id(), &wrapped, b"ctx").await.unwrap();
    assert_eq!(&back[..], &key[..]);
    assert!(kek.unwrap(kek.kek_id(), &wrapped, b"other").await.is_err());
}
