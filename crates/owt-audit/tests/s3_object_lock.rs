//! Against a real S3 endpoint with Object Lock; skipped unless configured:
//! `OWT_ANCHOR_S3_ENDPOINT`, `_BUCKET` (created with Object Lock), `_REGION`
//! (default `us-east-1`), `_ACCESS_KEY`, `_SECRET_KEY`.
#![cfg(feature = "s3")]

use std::time::Duration;

use owt_audit::anchor::{Anchor, S3Config, S3ObjectLock};

fn config() -> Option<S3Config> {
    let var = |n: &str| std::env::var(format!("OWT_ANCHOR_S3_{n}")).ok();
    Some(S3Config {
        endpoint: var("ENDPOINT")?,
        allow_insecure_http: false,
        bucket: var("BUCKET")?,
        region: var("REGION").unwrap_or_else(|| "us-east-1".into()),
        access_key: var("ACCESS_KEY")?,
        secret_key: var("SECRET_KEY")?.into(),
        retention: Duration::from_hours(24),
    })
}

#[tokio::test]
async fn locks_refuses_overwrites_and_reads_back() {
    let Some(config) = config() else {
        eprintln!("skipped: OWT_ANCHOR_S3_* is not set");
        return;
    };
    let store = S3ObjectLock::new(config).unwrap();
    store.verify_bucket().await.unwrap();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let key = format!("owt-audit-test/{nonce}.json");
    let receipt = store.put(&key, b"{\"a\":1}").await.unwrap();
    assert_ne!(receipt, "");
    assert_eq!(
        store.fetch(&key, Some(&receipt)).await.unwrap(),
        b"{\"a\":1}"
    );
    // The same key is not replaced, and the anchored version still reads back.
    assert!(store.put(&key, b"{\"a\":2}").await.is_err());
    assert_eq!(
        store.fetch(&key, Some(&receipt)).await.unwrap(),
        b"{\"a\":1}"
    );
    assert!(store.fetch("../escape", None).await.is_err());
}
