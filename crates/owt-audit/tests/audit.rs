//! owt-audit against a real Postgres (`DATABASE_URL`); skipped when it is unset. Each
//! test takes a schema of its own and drops it.

use owt_audit::anchor::{self, NoAnchor};
use owt_audit::{ActorKind, Audit, Broken, Event, Outcome, VerifyError, verify, verify_anchor};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};

struct Db {
    pool: PgPool,
    admin: PgPool,
    schema: String,
    url: String,
}

impl Db {
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let schema = format!("owt_audit_{}_{}", std::process::id(), rand::random::<u32>());
        let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
        admin
            .execute(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .await
            .unwrap();
        let pool = pool_in(&url, &schema, None).await;
        owt_audit::migrate(&pool).await.unwrap();
        owt_audit::migrate(&pool).await.unwrap();
        Some(Self {
            pool,
            admin,
            schema,
            url,
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

    /// Run `sql` with the append-only triggers off: what the table's owner could do.
    async fn as_owner_without_triggers(&self, sql: &str) {
        let mut tx = self.pool.begin().await.unwrap();
        tx.execute("ALTER TABLE owt_audit_events DISABLE TRIGGER USER")
            .await
            .unwrap();
        tx.execute(sqlx::AssertSqlSafe(sql.to_owned()))
            .await
            .unwrap();
        tx.execute("ALTER TABLE owt_audit_events ENABLE TRIGGER USER")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

async fn pool_in(url: &str, schema: &str, role: Option<&str>) -> PgPool {
    let opts: PgConnectOptions = url.parse().unwrap();
    let schema = schema.to_owned();
    let role = role.map(str::to_owned);
    PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |conn, _| {
            let (schema, role) = (schema.clone(), role.clone());
            Box::pin(async move {
                conn.execute(sqlx::AssertSqlSafe(format!("SET search_path = {schema}")))
                    .await?;
                if let Some(role) = role {
                    conn.execute(sqlx::AssertSqlSafe(format!("SET ROLE {role}")))
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(opts)
        .await
        .unwrap()
}

fn view(tenant: &str, patient: &str) -> Event {
    Event::new(ActorKind::Account, "17", "record.view", "chart")
        .tenant(tenant)
        .subject(patient)
        .resource_id(patient)
        .purpose("treatment")
        .client(
            Some("2001:db8::1".parse().unwrap()),
            Some("Mozilla/5.0"),
            Some("req-1"),
        )
}

#[tokio::test]
async fn each_tenant_has_a_chain_that_verifies() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    for i in 0..5 {
        let a = audit.record(&view("t1", &format!("p{i}"))).await.unwrap();
        assert_eq!(a.seq, i + 1);
        assert_eq!(a.hash, a.computed_hash());
    }
    let b = audit.record(&view("t2", "p9")).await.unwrap();
    assert_eq!((b.seq, b.prev), (1, owt_audit::GENESIS));
    let sys = audit
        .record(
            &Event::new(ActorKind::System, "system", "key.rotate", "kek").outcome(Outcome::Failure),
        )
        .await
        .unwrap();
    assert_eq!(sys.seq, 1);
    assert_eq!(verify(&db.pool, "t1").await.unwrap().events, 5);
    assert_eq!(verify(&db.pool, "t2").await.unwrap().events, 1);
    assert_eq!(verify(&db.pool, "").await.unwrap().events, 1);
    assert_eq!(verify(&db.pool, "none").await.unwrap().head, None);
    let heads = owt_audit::heads(&db.pool).await.unwrap();
    let names: Vec<_> = heads.iter().map(|h| (h.tenant.as_str(), h.seq)).collect();
    assert_eq!(names, [("", 1), ("t1", 5), ("t2", 1)]);
    // An invalid event writes nothing.
    let mut bad = view("t1", "p1");
    bad.action = "Viewed Ann's chart".into();
    assert!(matches!(
        audit.record(&bad).await,
        Err(owt_audit::RecordError::Invalid(_))
    ));
    db.drop().await;
}

#[tokio::test]
async fn an_insert_cannot_choose_its_place_or_links() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    audit.record(&view("t", "p1")).await.unwrap();
    // A direct insert naming its own seq, time, prev and hash: all replaced.
    db.pool
        .execute(
            "INSERT INTO owt_audit_events (tenant, seq, at, actor, actor_kind, action, resource_type,
                                           outcome, prev, hash)
             VALUES ('t', 9223372036854775807, 'infinity', 'x', 'system', 'forged', 'chart',
                     'success', decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex'))",
        )
        .await
        .unwrap();
    let after = audit.record(&view("t", "p2")).await.unwrap();
    assert_eq!(after.seq, 3);
    assert_eq!(verify(&db.pool, "t").await.unwrap().events, 3);
    // A malformed address or a control character is refused by the table itself.
    for bad in [
        "INSERT INTO owt_audit_events (tenant, actor, actor_kind, action, resource_type, outcome, ip)
         VALUES ('t', 'x', 'system', 'a', 'b', 'success', 'not an ip')",
        "INSERT INTO owt_audit_events (tenant, actor, actor_kind, action, resource_type, outcome)
         VALUES ('t', E'x\\ny', 'system', 'a', 'b', 'success')",
    ] {
        assert!(db.pool.execute(bad).await.is_err(), "{bad}");
    }
    // A temporary table of the same name cannot stand in for the chain.
    let mut conn = db.pool.acquire().await.unwrap();
    conn.execute(
        "CREATE TEMP TABLE owt_audit_events (tenant text, seq bigint, hash bytea);
         INSERT INTO pg_temp.owt_audit_events VALUES ('t', 1000, decode(repeat('ee', 32), 'hex'))",
    )
    .await
    .unwrap();
    // The real table, by its schema, while the temporary one shadows the name.
    conn.execute(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {}.owt_audit_events (tenant, actor, actor_kind, action, resource_type, outcome)
         VALUES ('t', 'x', 'system', 'a', 'b', 'success')",
        db.schema
    )))
    .await
    .unwrap();
    conn.execute("DROP TABLE pg_temp.owt_audit_events")
        .await
        .unwrap();
    drop(conn);
    assert_eq!(verify(&db.pool, "t").await.unwrap().events, 4);
    // Under REPEATABLE READ the last event could be stale: refused.
    let mut tx = db.pool.begin().await.unwrap();
    tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    let e = owt_audit::record_in(&mut tx, &view("t", "p3"))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("READ COMMITTED"), "{e}");
    tx.rollback().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn a_forged_anchor_record_is_caught() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    audit.record(&view("t", "p")).await.unwrap();
    anchor::anchor(&db.pool, &NoAnchor).await.unwrap();
    // An anchor row whose manifest anchors nothing, with a digest that is not its own.
    db.pool
        .execute(
            "INSERT INTO owt_audit_anchors (manifest, digest, provider, receipt)
             VALUES (convert_to('{\"format\":\"owt-audit/manifest/v1\",\"at_us\":0,\"prev\":null,\"heads\":[]}', 'UTF8'),
                     decode(repeat('00', 32), 'hex'), 'none', '')",
        )
        .await
        .unwrap();
    // Skipped, not trusted, and it blocks nothing.
    let latest = anchor::latest(&db.pool).await.unwrap().unwrap();
    assert_eq!(latest.heads.len(), 1);
    anchor::anchor(&db.pool, &NoAnchor).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn concurrent_appends_to_one_chain_stay_contiguous() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    let mut set = tokio::task::JoinSet::new();
    for i in 0..40 {
        let audit = audit.clone();
        set.spawn(async move { audit.record(&view(["a", "b"][i % 2], "p")).await.unwrap() });
    }
    set.join_all().await;
    assert_eq!(verify(&db.pool, "a").await.unwrap().events, 20);
    assert_eq!(verify(&db.pool, "b").await.unwrap().events, 20);
    db.drop().await;
}

#[tokio::test]
async fn an_event_commits_with_its_transaction() {
    let Some(db) = Db::new().await else { return };
    let mut tx = db.pool.begin().await.unwrap();
    owt_audit::record_in(&mut tx, &view("t", "p"))
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let mut tx = db.pool.begin().await.unwrap();
    let r = owt_audit::record_in(&mut tx, &view("t", "p"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(r.seq, 1);
    db.drop().await;
}

#[tokio::test]
async fn changes_are_refused_even_to_the_owner() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    audit.record(&view("t", "p")).await.unwrap();
    anchor::anchor(&db.pool, &NoAnchor).await.unwrap();
    for sql in [
        "UPDATE owt_audit_events SET actor = '18'",
        "DELETE FROM owt_audit_events",
        "TRUNCATE owt_audit_events",
        "UPDATE owt_audit_anchors SET receipt = 'x'",
        "DELETE FROM owt_audit_anchors",
        "TRUNCATE owt_audit_anchors",
    ] {
        let e = db.pool.execute(sql).await.expect_err(sql);
        assert!(e.to_string().contains("append-only"), "{sql}: {e}");
    }
    db.drop().await;
}

#[tokio::test]
async fn the_app_role_may_insert_and_select_only() {
    let Some(db) = Db::new().await else { return };
    let role = format!("{}_app", db.schema);
    for sql in [
        format!("CREATE ROLE {role} NOLOGIN"),
        format!("GRANT USAGE ON SCHEMA {} TO {role}", db.schema),
        format!("GRANT SELECT, INSERT ON owt_audit_events, owt_audit_anchors TO {role}"),
    ] {
        db.pool.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
    }
    let app = pool_in(&db.url, &db.schema, Some(&role)).await;
    let audit = Audit::new(app.clone());
    audit.record(&view("t", "p")).await.unwrap();
    audit.record(&view("t", "p")).await.unwrap();
    assert_eq!(verify(&app, "t").await.unwrap().events, 2);
    anchor::anchor(&app, &NoAnchor).await.unwrap();
    for sql in [
        "ALTER TABLE owt_audit_events DISABLE TRIGGER USER",
        "DROP TRIGGER owt_audit_events_no_change ON owt_audit_events",
        "TRUNCATE owt_audit_events",
    ] {
        let e = app.execute(sql).await.expect_err(sql);
        assert!(
            e.to_string().contains("must be owner") || e.to_string().contains("permission denied"),
            "{sql}: {e}"
        );
    }
    app.close().await;
    db.pool
        .execute(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON ALL TABLES IN SCHEMA {0} FROM {role}; REVOKE ALL ON SCHEMA {0} FROM {role}; DROP ROLE {role}",
            db.schema
        )))
        .await
        .unwrap();
    db.drop().await;
}

/// The privileges `owt_runtime::db::grant_runtime` and then `owt_audit::grant_runtime`
/// leave the runtime role: full DML on an app's table, read-only ledgers, append-only
/// audit events, read-only anchors, and nothing that changes a table or its triggers.
#[tokio::test]
async fn grant_runtime_gives_the_runtime_role_exactly_what_serving_needs() {
    let Some(db) = Db::new().await else { return };
    let role = format!("{}_rt", db.schema);
    for sql in [
        format!("CREATE ROLE {role} NOLOGIN"),
        "CREATE TABLE app_things (id bigserial PRIMARY KEY, v text)".to_owned(),
    ] {
        db.pool.execute(sqlx::AssertSqlSafe(sql)).await.unwrap();
    }
    for _ in 0..2 {
        owt_runtime::db::grant_runtime(&db.pool, &role)
            .await
            .unwrap();
        owt_audit::grant_runtime(&db.pool, &role).await.unwrap();
    }
    let all = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ];
    for (table, want) in [
        ("app_things", &["SELECT", "INSERT", "UPDATE", "DELETE"][..]),
        (owt_audit::LEDGER, &["SELECT"][..]),
        ("owt_audit_events", &["SELECT", "INSERT"][..]),
        ("owt_audit_anchors", &["SELECT"][..]),
    ] {
        let mut have = Vec::new();
        for privilege in all {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_table_privilege($1, format('%I.%I', $2::text, $3::text), $4)",
            )
            .bind(&role)
            .bind(&db.schema)
            .bind(table)
            .bind(privilege)
            .fetch_one(&db.pool)
            .await
            .unwrap();
            if granted {
                have.push(privilege);
            }
        }
        assert_eq!(have, want, "{table}");
    }
    let (create, sequence): (bool, bool) = sqlx::query_as(
        "SELECT has_schema_privilege($1, $2, 'CREATE'),
                has_sequence_privilege($1, format('%I.app_things_id_seq', $2::text), 'USAGE')",
    )
    .bind(&role)
    .bind(&db.schema)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(!create, "the runtime role creates no table");
    assert!(sequence, "the runtime role draws ids");

    let app = pool_in(&db.url, &db.schema, Some(&role)).await;
    app.execute("INSERT INTO app_things (v) VALUES ('a'); UPDATE app_things SET v = 'b'; DELETE FROM app_things")
        .await
        .unwrap();
    let audit = Audit::new(app.clone());
    audit.record(&view("t", "p")).await.unwrap();
    assert_eq!(verify(&app, "t").await.unwrap().events, 1);
    for sql in [
        "ALTER TABLE owt_audit_events DISABLE TRIGGER USER",
        "ALTER TABLE owt_audit_events OWNER TO CURRENT_USER",
        "ALTER TABLE owt_audit_anchors DISABLE TRIGGER USER",
        "DROP TRIGGER owt_audit_events_no_change ON owt_audit_events",
        "DROP TABLE owt_audit_events",
        "DROP TABLE owt_audit_anchors",
        "TRUNCATE owt_audit_events",
        "UPDATE owt_audit_events SET action = 'x'",
        "DELETE FROM owt_audit_events",
        "INSERT INTO owt_audit_anchors DEFAULT VALUES",
        "DELETE FROM _owt_audit_migrations",
        "ALTER TABLE app_things ADD COLUMN w text",
        "CREATE TABLE app_more (id int)",
    ] {
        let e = app.execute(sql).await.expect_err(sql);
        assert!(
            e.to_string().contains("must be owner") || e.to_string().contains("permission denied"),
            "{sql}: {e}"
        );
    }
    app.close().await;
    db.pool
        .execute(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON ALL TABLES IN SCHEMA {0} FROM {role}; \
             REVOKE ALL ON ALL SEQUENCES IN SCHEMA {0} FROM {role}; \
             REVOKE ALL ON SCHEMA {0} FROM {role}; DROP ROLE {role}",
            db.schema
        )))
        .await
        .unwrap();
    db.drop().await;
}

#[tokio::test]
async fn tampering_breaks_the_chain_or_the_anchor() {
    let Some(db) = Db::new().await else { return };
    let audit = Audit::new(db.pool.clone());
    for i in 0..4 {
        audit.record(&view("t", &format!("p{i}"))).await.unwrap();
    }
    let anchored = anchor::anchor(&db.pool, &NoAnchor).await.unwrap();
    assert_eq!(anchored.manifest.heads.len(), 1);
    assert_eq!(
        anchor::latest(&db.pool).await.unwrap(),
        Some(anchored.manifest.clone())
    );
    verify_anchor(&db.pool, &anchored.manifest).await.unwrap();
    // Appending keeps the anchor valid, and the next anchor links to it.
    audit.record(&view("t", "p4")).await.unwrap();
    verify_anchor(&db.pool, &anchored.manifest).await.unwrap();
    let next = anchor::anchor(&db.pool, &NoAnchor).await.unwrap();
    assert_eq!(
        next.manifest.prev,
        Some(owt_audit::hex(&anchored.manifest.digest()))
    );

    // An edited event no longer matches its hash.
    db.as_owner_without_triggers("UPDATE owt_audit_events SET subject = 'p9' WHERE seq = 2")
        .await;
    assert!(matches!(
        verify(&db.pool, "t").await,
        Err(VerifyError::Broken(Broken::Hash { seq: 2, .. }))
    ));
    db.as_owner_without_triggers("UPDATE owt_audit_events SET subject = 'p1' WHERE seq = 2")
        .await;
    verify(&db.pool, "t").await.unwrap();

    // A removed event leaves a gap; a removed last event, a missing anchored head.
    db.as_owner_without_triggers("DELETE FROM owt_audit_events WHERE seq = 5")
        .await;
    verify(&db.pool, "t").await.unwrap();
    assert!(verify_anchor(&db.pool, &next.manifest).await.is_err());
    db.as_owner_without_triggers("DELETE FROM owt_audit_events WHERE seq = 3")
        .await;
    assert!(matches!(
        verify(&db.pool, "t").await,
        Err(VerifyError::Broken(Broken::Gap {
            expected: 3,
            found: 4,
            ..
        }))
    ));

    // A chain rewritten from event 3 on, hashes recomputed, verifies on its own, but
    // not against the heads anchored before.
    db.as_owner_without_triggers("DELETE FROM owt_audit_events WHERE seq >= 3")
        .await;
    audit.record(&view("t", "forged")).await.unwrap();
    audit.record(&view("t", "forged")).await.unwrap();
    verify(&db.pool, "t").await.unwrap();
    assert!(matches!(
        verify_anchor(&db.pool, &anchored.manifest).await,
        Err(VerifyError::Broken(Broken::Anchor { seq: 4, .. }))
    ));

    // A link to another event breaks at the event after the swap.
    db.as_owner_without_triggers(
        "UPDATE owt_audit_events SET prev = (SELECT prev FROM owt_audit_events WHERE seq = 1) WHERE seq = 3",
    )
    .await;
    assert!(matches!(
        verify(&db.pool, "t").await,
        Err(VerifyError::Broken(Broken::Link { seq: 3, .. }))
    ));
    db.drop().await;
}
