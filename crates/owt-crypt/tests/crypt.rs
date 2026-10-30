//! owt-crypt against a real Postgres (`DATABASE_URL`); skipped when it is unset. Each
//! test takes a schema of its own and drops it.

use std::sync::Arc;

use owt_crypt::kek::{KekChain, KekProvider, LocalKek};
use std::time::Duration;

use owt_crypt::{Column, Crypt, CryptError, Field, Purpose, Reencrypted, Scope};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};

struct Db {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl Db {
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let schema = format!("owt_crypt_{}_{}", std::process::id(), rand::random::<u32>());
        let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
        admin
            .execute(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .await
            .unwrap();
        let opts: PgConnectOptions = url.parse().unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(opts.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        owt_crypt::migrate(&pool).await.unwrap();
        owt_crypt::migrate(&pool).await.unwrap();
        Some(Self {
            pool,
            admin,
            schema,
        })
    }

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
}

fn local(name: &str) -> Arc<dyn KekProvider> {
    Arc::new(LocalKek::parse(&LocalKek::generate_entry(name)).unwrap())
}

#[tokio::test]
async fn fields_round_trip_per_tenant_and_bind_to_their_place() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    let f = Field::new("practice-1", "notes", "body", "6f1c");
    let ct = crypt
        .encrypt_str(&f, "Patient reports better sleep.")
        .await
        .unwrap();
    assert!(!ct.windows(7).any(|w| w == b"Patient"));
    assert_eq!(
        &*crypt.decrypt_string(&f, &ct).await.unwrap(),
        "Patient reports better sleep."
    );
    // Another tenant's keys, row or column do not open it.
    for other in [
        Field::new("practice-2", "notes", "body", "6f1c"),
        Field::new("practice-1", "notes", "body", "6f1d"),
        Field::new("practice-1", "notes", "summary", "6f1c"),
    ] {
        assert!(crypt.decrypt(&other, &ct).await.is_err(), "{other:?}");
    }
    // A fresh process (no cache) unwraps through the KEK.
    crypt.forget_keys();
    assert_eq!(
        &*crypt.decrypt_string(&f, &ct).await.unwrap(),
        "Patient reports better sleep."
    );
    // Reading makes no key: only practice-1's exists.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM owt_crypt_keys")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(matches!(
        crypt.decrypt(&f, b"not a ciphertext").await,
        Err(CryptError::Malformed)
    ));
    db.drop().await;
}

#[tokio::test]
async fn first_use_races_make_one_key() {
    let Some(db) = Db::new().await else { return };
    let kek = local("k1");
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let crypt = Crypt::new(db.pool.clone(), kek.clone());
        set.spawn(async move {
            let f = Field::new("t", "x", "y", "1");
            crypt.encrypt(&f, b"v").await.unwrap()
        });
    }
    let all = set.join_all().await;
    let crypt = Crypt::new(db.pool.clone(), kek);
    for ct in all {
        crypt
            .decrypt(&Field::new("t", "x", "y", "1"), &ct)
            .await
            .unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM owt_crypt_keys")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    db.drop().await;
}

#[tokio::test]
async fn rotation_keeps_old_values_readable_and_the_job_moves_them() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    db.pool
        .execute("CREATE TABLE notes (id bigint PRIMARY KEY, tenant text NOT NULL, body bytea)")
        .await
        .unwrap();
    for id in 1..=25_i64 {
        let tenant = if id % 2 == 0 { "a" } else { "b" };
        let ct = crypt
            .encrypt(
                &Field::new(tenant, "notes", "body", &id.to_string()),
                format!("n{id}").as_bytes(),
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO notes VALUES ($1, $2, $3)")
            .bind(id)
            .bind(tenant)
            .bind(ct)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO notes VALUES (99, 'a', NULL)")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(crypt.rotate("a", Purpose::Data).await.unwrap(), 2);
    assert_eq!(crypt.current_version("a").await.unwrap(), 2);
    assert_eq!(crypt.current_version("b").await.unwrap(), 1);
    let column = Column {
        table: "notes",
        id: "id",
        column: "body",
        scope: Scope::Column("tenant"),
    };
    assert_eq!(
        crypt.reencrypt_column(&column, 5).await.unwrap().moved,
        12,
        "tenant a's rows"
    );
    assert_eq!(
        crypt.reencrypt_column(&column, 5).await.unwrap(),
        Reencrypted {
            moved: 0,
            failed: Vec::new(),
            no_key: 0,
            complete: true
        },
        "nothing left"
    );
    let rows: Vec<(i64, String, Vec<u8>)> =
        sqlx::query_as("SELECT id, tenant, body FROM notes WHERE body IS NOT NULL ORDER BY id")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    for (id, tenant, ct) in rows {
        let version = u32::from_be_bytes(ct[1..5].try_into().unwrap());
        assert_eq!(version, if tenant == "a" { 2 } else { 1 });
        let plain = crypt
            .decrypt(&Field::new(&tenant, "notes", "body", &id.to_string()), &ct)
            .await
            .unwrap();
        assert_eq!(&plain[..], format!("n{id}").as_bytes());
    }
    // A fixed scope, and identifiers that are not plain, refused.
    crypt.rotate("b", Purpose::Data).await.unwrap();
    let fixed = Column {
        scope: Scope::Fixed("b"),
        ..column
    };
    assert_eq!(crypt.reencrypt_column(&fixed, 100).await.unwrap().moved, 13);
    let bad = Column {
        table: "notes; DROP TABLE notes",
        ..column
    };
    assert!(matches!(
        crypt.reencrypt_column(&bad, 1).await,
        Err(CryptError::Invalid(_))
    ));
    db.drop().await;
}

#[tokio::test]
async fn blind_indexes_find_equal_values_within_a_tenant() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    let a = crypt
        .blind_index("t1", "patients", "email", b"ann@example.com")
        .await
        .unwrap();
    assert_eq!(
        a,
        crypt
            .blind_index("t1", "patients", "email", b"ann@example.com")
            .await
            .unwrap()
    );
    assert_ne!(
        a,
        crypt
            .blind_index("t2", "patients", "email", b"ann@example.com")
            .await
            .unwrap()
    );
    assert_ne!(
        a,
        crypt
            .blind_index("t1", "patients", "email", b"bob@example.com")
            .await
            .unwrap()
    );
    // The index key is not the data key: rotating data keys leaves indexes alone.
    crypt.rotate("t1", Purpose::Data).await.unwrap();
    assert_eq!(
        a,
        crypt
            .blind_index("t1", "patients", "email", b"ann@example.com")
            .await
            .unwrap()
    );
    // Rotating the index key: the old index stays a candidate until rows are redone.
    crypt.rotate("t1", Purpose::Index).await.unwrap();
    let candidates = crypt
        .blind_index_candidates("t1", "patients", "email", b"ann@example.com")
        .await
        .unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[1], a);
    assert_ne!(candidates[0], a);
    db.drop().await;
}

#[tokio::test]
async fn a_kek_rotation_rewraps_keys_without_touching_data() {
    let Some(db) = Db::new().await else { return };
    let old = local("old");
    let crypt = Crypt::new(db.pool.clone(), old.clone());
    let f = Field::new("t", "notes", "body", "1");
    let ct = crypt.encrypt(&f, b"kept").await.unwrap();
    crypt
        .blind_index("t", "patients", "email", b"x")
        .await
        .unwrap();

    // The new KEK alone cannot read the old keys.
    let new = local("new");
    assert!(
        Crypt::new(db.pool.clone(), new.clone())
            .decrypt(&f, &ct)
            .await
            .is_err()
    );

    let chain: Arc<dyn KekProvider> = Arc::new(KekChain::new(new.clone(), vec![old]));
    let moving = Crypt::new(db.pool.clone(), chain);
    assert_eq!(moving.rewrap().await.unwrap(), 2);
    assert_eq!(moving.rewrap().await.unwrap(), 0);
    let after = Crypt::new(db.pool.clone(), new.clone());
    assert_eq!(&after.decrypt(&f, &ct).await.unwrap()[..], b"kept");
    let ids: Vec<String> = sqlx::query_scalar("SELECT DISTINCT kek_id FROM owt_crypt_keys")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(ids, [new.kek_id().to_owned()]);
    db.drop().await;
}

#[tokio::test]
async fn a_wrapped_key_moved_to_another_tenant_does_not_unwrap() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    let ct_a = crypt
        .encrypt(&Field::new("a", "n", "b", "1"), b"secret a")
        .await
        .unwrap();
    crypt
        .encrypt(&Field::new("b", "n", "b", "1"), b"secret b")
        .await
        .unwrap();
    // Someone with write access copies tenant a's wrapped key onto tenant b's row,
    // and copies a's value into b's place.
    db.pool
        .execute(
            "UPDATE owt_crypt_keys SET wrapped = (SELECT wrapped FROM owt_crypt_keys WHERE scope = 'a')
             WHERE scope = 'b'",
        )
        .await
        .unwrap();
    crypt.forget_keys();
    let err = crypt
        .decrypt(&Field::new("b", "n", "b", "1"), &ct_a)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptError::Kek(_)), "{err}");
    db.drop().await;
}

#[tokio::test]
async fn shredding_a_tenant_makes_its_data_unreadable() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    let f = Field::new("leaving", "notes", "body", "1");
    let ct = crypt.encrypt(&f, b"gone").await.unwrap();
    let kept = crypt
        .encrypt(&Field::new("staying", "notes", "body", "1"), b"kept")
        .await
        .unwrap();
    assert_eq!(crypt.shred("leaving").await.unwrap(), 1);
    assert!(matches!(
        crypt.decrypt(&f, &ct).await,
        Err(CryptError::NoKey { version: 1, .. })
    ));
    crypt
        .decrypt(&Field::new("staying", "notes", "body", "1"), &kept)
        .await
        .unwrap();
    db.drop().await;
}

#[tokio::test]
async fn production_refuses_a_software_kek() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    assert!(matches!(
        crypt.clone().require_hardware_kek(true),
        Err(CryptError::SoftwareKek(id)) if id == "local:k1"
    ));
    assert!(crypt.require_hardware_kek(false).is_ok());
    db.drop().await;
}

#[tokio::test]
async fn another_replica_stops_decrypting_a_shredded_scope_after_the_ttl() {
    let Some(db) = Db::new().await else { return };
    let kek = local("k1");
    let ttl = Duration::from_millis(100);
    let a = Crypt::new(db.pool.clone(), kek.clone()).cache_ttl(ttl);
    let b = Crypt::new(db.pool.clone(), kek).cache_ttl(ttl);
    let f = Field::new("leaving", "notes", "body", "1");
    let ct = a.encrypt(&f, b"gone").await.unwrap();
    assert_eq!(&b.decrypt(&f, &ct).await.unwrap()[..], b"gone");
    a.shred("leaving").await.unwrap();
    // Within the TTL b's cache still answers; after it, b asks the database.
    tokio::time::sleep(ttl * 3).await;
    assert!(matches!(
        b.decrypt(&f, &ct).await,
        Err(CryptError::NoKey { .. } | CryptError::Shredded(_))
    ));
    // Neither replica can bring the scope back.
    for c in [&a, &b] {
        assert!(matches!(
            c.encrypt(&f, b"again").await,
            Err(CryptError::Shredded(s)) if s == "leaving"
        ));
        assert!(matches!(
            c.rotate("leaving", Purpose::Data).await,
            Err(CryptError::Shredded(_))
        ));
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM owt_crypt_keys WHERE scope = 'leaving'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    db.drop().await;
}

#[tokio::test]
async fn reencrypt_column_reports_a_bad_row_and_terminates() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    db.pool
        .execute("CREATE TABLE notes (id bigint PRIMARY KEY, body bytea)")
        .await
        .unwrap();
    for id in 1..=6_i64 {
        let ct = crypt
            .encrypt(&Field::new("a", "notes", "body", &id.to_string()), b"v")
            .await
            .unwrap();
        sqlx::query("INSERT INTO notes VALUES ($1, $2)")
            .bind(id)
            .bind(ct)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    // Rows that are not ciphertexts, ahead of good ones in a batch of two.
    sqlx::query(
        "INSERT INTO notes VALUES (7, '\\x0200000001'::bytea), (8, '\\x01000000010203'::bytea)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    crypt.rotate("a", Purpose::Data).await.unwrap();
    let column = Column {
        table: "notes",
        id: "id",
        column: "body",
        scope: Scope::Fixed("a"),
    };
    let done = crypt.reencrypt_column(&column, 2).await.unwrap();
    assert_eq!(done.moved, 6);
    let mut failed = done.failed.clone();
    failed.sort();
    assert_eq!(failed, ["7", "8"]);
    // A second run finds the same two and still ends.
    let again = crypt.reencrypt_column(&column, 2).await.unwrap();
    assert_eq!((again.moved, again.failed.len()), (0, 2));
    db.drop().await;
}

#[tokio::test]
async fn reencrypt_column_counts_rows_whose_scope_has_no_key() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    db.pool
        .execute("CREATE TABLE notes (id bigint PRIMARY KEY, tenant text, body bytea)")
        .await
        .unwrap();
    let ct = crypt
        .encrypt(&Field::new("a", "notes", "body", "1"), b"v")
        .await
        .unwrap();
    sqlx::query("INSERT INTO notes VALUES (1, 'a', $1), (2, 'ghost', '\\x0100000001'::bytea)")
        .bind(ct)
        .execute(&db.pool)
        .await
        .unwrap();
    crypt.rotate("a", Purpose::Data).await.unwrap();
    let column = Column {
        table: "notes",
        id: "id",
        column: "body",
        scope: Scope::Column("tenant"),
    };
    let done = crypt.reencrypt_column(&column, 10).await.unwrap();
    assert_eq!((done.moved, done.no_key, done.complete), (1, 1, false));
    assert_eq!(done.failed, [] as [String; 0]);
    let fixed = Column {
        scope: Scope::Fixed("ghost"),
        ..column
    };
    let done = crypt.reencrypt_column(&fixed, 10).await.unwrap();
    assert_eq!((done.moved, done.no_key, done.complete), (0, 2, false));
    db.drop().await;
}

#[tokio::test]
async fn software_wrapped_keys_lists_local_kek_ids() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    assert_eq!(crypt.software_wrapped_keys().await.unwrap().len(), 0);
    crypt
        .encrypt(&Field::new("t", "n", "b", "1"), b"v")
        .await
        .unwrap();
    assert_eq!(crypt.software_wrapped_keys().await.unwrap(), ["local:k1"]);
    db.drop().await;
}

#[tokio::test]
async fn empty_field_parts_are_refused() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    for f in [
        Field::new("t", "n", "b", ""),
        Field::new("t", "", "b", "1"),
        Field::new("t", "n", "", "1"),
    ] {
        assert!(matches!(
            crypt.encrypt(&f, b"v").await,
            Err(CryptError::Invalid(_))
        ));
    }
    db.drop().await;
}

#[tokio::test]
async fn a_swallowed_update_is_not_reported_as_complete() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    db.pool
        .execute("CREATE TABLE notes (id bigint PRIMARY KEY, body bytea)")
        .await
        .unwrap();
    for id in 1..=3_i64 {
        let ct = crypt
            .encrypt(&Field::new("a", "notes", "body", &id.to_string()), b"v")
            .await
            .unwrap();
        sqlx::query("INSERT INTO notes VALUES ($1, $2)")
            .bind(id)
            .bind(ct)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    crypt.rotate("a", Purpose::Data).await.unwrap();
    db.pool
        .execute(
            "CREATE FUNCTION swallow() RETURNS trigger AS $$ BEGIN RETURN NULL; END $$ LANGUAGE plpgsql",
        )
        .await
        .unwrap();
    db.pool
        .execute(
            "CREATE TRIGGER swallow BEFORE UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION swallow()",
        )
        .await
        .unwrap();
    let column = Column {
        table: "notes",
        id: "id",
        column: "body",
        scope: Scope::Fixed("a"),
    };
    let done = crypt.reencrypt_column(&column, 10).await.unwrap();
    assert_eq!((done.moved, done.complete), (0, false));
    assert_eq!(done.failed.len(), 0);
    db.drop().await;
}

#[tokio::test]
async fn a_chain_with_software_rows_fails_the_hardware_check() {
    let Some(db) = Db::new().await else { return };
    let crypt = Crypt::new(db.pool.clone(), local("k1"));
    crypt.check_keys_hardware().await.unwrap();
    crypt
        .encrypt(&Field::new("t", "n", "b", "1"), b"v")
        .await
        .unwrap();
    assert!(matches!(
        crypt.check_keys_hardware().await,
        Err(CryptError::SoftwareKek(ids)) if ids == "local:k1"
    ));
    db.drop().await;
}
