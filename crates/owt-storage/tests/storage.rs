//! owt-storage over an in-memory store, with owt-crypt keys in a real Postgres
//! (`DATABASE_URL`); skipped when it is unset. Each test takes a schema of its own.

use std::sync::Arc;

use bytes::Bytes;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{ObjectStoreExt, PutPayload};
use owt_crypt::Crypt;
use owt_crypt::kek::LocalKek;
use owt_storage::sealed::CHUNK;
use owt_storage::{Storage, StorageError};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};

struct Fixture {
    storage: Storage,
    store: Arc<InMemory>,
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

async fn fixture() -> Option<Fixture> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let schema = format!(
        "owt_storage_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
    admin
        .execute(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .await
        .unwrap();
    let opts: PgConnectOptions = url.parse().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    owt_crypt::migrate(&pool).await.unwrap();
    let kek = Arc::new(LocalKek::parse(&LocalKek::generate_entry("k")).unwrap());
    let store = Arc::new(InMemory::new());
    let storage = Storage::from_store(store.clone()).encrypted(Crypt::new(pool.clone(), kek));
    Some(Fixture {
        storage,
        store,
        pool,
        admin,
        schema,
    })
}

impl Fixture {
    async fn drop(self) {
        self.pool.close().await;
        self.admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP SCHEMA {} CASCADE",
                self.schema
            )))
            .await
            .unwrap();
    }

    async fn raw(&self, key: &str) -> Vec<u8> {
        self.store
            .get(&Path::from(key))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec()
    }

    async fn set_raw(&self, key: &str, bytes: Vec<u8>) {
        self.store
            .put(&Path::from(key), PutPayload::from(bytes))
            .await
            .unwrap();
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

#[tokio::test]
async fn sealed_objects_round_trip_at_every_chunk_boundary() {
    let Some(f) = fixture().await else { return };
    for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 7] {
        let key = format!("rec/{n}");
        let plain = pattern(n);
        let written = f
            .storage
            .upload_sealed("t1", &key, &plain[..])
            .await
            .unwrap();
        assert_eq!(written, n as u64);
        let raw = f.raw(&key).await;
        assert!(raw.starts_with(b"OWTS"));
        if n > 64 {
            assert!(
                !raw.windows(64).any(|w| w == &plain[..64]),
                "ciphertext only, n = {n}"
            );
        }
        assert_eq!(
            &f.storage.get_sealed("t1", &key).await.unwrap()[..],
            &plain[..],
            "n = {n}"
        );
    }
    f.drop().await;
}

#[tokio::test]
async fn an_altered_truncated_or_moved_object_is_refused() {
    let Some(f) = fixture().await else { return };
    let plain = pattern(2 * CHUNK + 100);
    f.storage.put_sealed("t1", "a", &plain).await.unwrap();
    let raw = f.raw("a").await;

    // Another scope, or another key, does not open it.
    assert!(f.storage.get_sealed("t2", "a").await.is_err());
    f.set_raw("b", raw.clone()).await;
    assert!(f.storage.get_sealed("t1", "b").await.is_err());

    let refused = |r: Result<_, StorageError>| match r {
        Err(StorageError::Refused(_)) => {}
        Err(e) => panic!("refused, not {e}"),
        Ok(_) => panic!("refused, not opened"),
    };
    // A flipped bit in a chunk, or in the header.
    let mut bent = raw.clone();
    let last = bent.len() - 1;
    bent[last] ^= 1;
    f.set_raw("a", bent).await;
    refused(f.storage.get_sealed("t1", "a").await);
    let mut bent = raw.clone();
    bent[5] ^= 1;
    f.set_raw("a", bent).await;
    assert!(f.storage.get_sealed("t1", "a").await.is_err());
    // The last chunk dropped: the one before it is not marked last.
    let header_len = raw.len() - (2 * (CHUNK + 16) + 100 + 16);
    f.set_raw("a", raw[..header_len + 2 * (CHUNK + 16)].to_vec())
        .await;
    refused(f.storage.get_sealed("t1", "a").await);
    // Two chunks swapped.
    let mut swapped = raw[..header_len].to_vec();
    swapped.extend_from_slice(&raw[header_len + CHUNK + 16..header_len + 2 * (CHUNK + 16)]);
    swapped.extend_from_slice(&raw[header_len..header_len + CHUNK + 16]);
    swapped.extend_from_slice(&raw[header_len + 2 * (CHUNK + 16)..]);
    f.set_raw("a", swapped).await;
    refused(f.storage.get_sealed("t1", "a").await);
    // Not an encrypted object at all.
    f.set_raw("a", b"plain text".to_vec()).await;
    refused(f.storage.get_sealed("t1", "a").await);
    assert!(matches!(
        f.storage.get_sealed("t1", "missing").await,
        Err(StorageError::NotFound(_))
    ));
    f.drop().await;
}

#[tokio::test]
async fn deletion_is_verified() {
    let Some(f) = fixture().await else { return };
    f.storage.put("x", Bytes::from_static(b"1")).await.unwrap();
    assert_eq!(f.storage.head("x").await.unwrap(), Some(1));
    f.storage.delete_verified("x").await.unwrap();
    assert_eq!(f.storage.head("x").await.unwrap(), None);
    // Already gone is deleted.
    f.storage.delete_verified("x").await.unwrap();
    assert!(matches!(
        f.storage.get("x").await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        f.storage.delete_verified("../x").await,
        Err(StorageError::BadKey(_))
    ));
    f.drop().await;
}

#[tokio::test]
async fn a_plaintext_upload_is_sealed_and_removed() {
    let Some(f) = fixture().await else { return };
    let plain = pattern(CHUNK + 3);
    f.storage
        .put("incoming/u1", Bytes::from(plain.clone()))
        .await
        .unwrap();
    let n = f
        .storage
        .seal_uploaded("t1", "incoming/u1", "rec/u1")
        .await
        .unwrap();
    assert_eq!(n, plain.len() as u64);
    assert_eq!(f.storage.head("incoming/u1").await.unwrap(), None);
    assert_eq!(
        &f.storage.get_sealed("t1", "rec/u1").await.unwrap()[..],
        &plain[..]
    );
    f.drop().await;
}

#[tokio::test]
async fn sealed_operations_need_a_crypt() {
    let plain = Storage::from_store(Arc::new(InMemory::new()));
    assert!(matches!(
        plain.put_sealed("t", "k", b"x").await,
        Err(StorageError::NoCrypt)
    ));
}
