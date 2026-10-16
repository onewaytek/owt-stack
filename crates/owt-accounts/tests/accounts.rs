//! The crate against a real Postgres (`DATABASE_URL`); skipped without it, except
//! for the nested-router wall test, which asks nothing of the database. Each
//! test takes a schema of its own, so they run in parallel and leave nothing.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use owt_accounts::session::{self, Data};
use owt_accounts::{Accounts, Maybe, New, Signed, Staff, identities, links, store};
use owt_auth::oauth;
use owt_web::session::{Session, Sessions};
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

/// The crate's migrations as a migrator, for these tests alone. The crate exports
/// none: sqlx keeps one migration ledger per database, so an app installs the files
/// through its own migrator (see `owt_accounts::migrations`).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

struct Db {
    pool: PgPool,
    schema: String,
    admin: PgPool,
}

impl Db {
    async fn fresh() -> Option<Self> {
        let url = owt_runtime::env::var("DATABASE_URL")?;
        let schema = format!(
            "owt_accounts_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        );
        let admin = PgPool::connect(&url).await.expect("DATABASE_URL connects");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let opts: PgConnectOptions = url.parse().unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_with(opts.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        Some(Self {
            pool,
            schema,
            admin,
        })
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

macro_rules! db {
    () => {
        match Db::fresh().await {
            Some(db) => db,
            None => return,
        }
    };
}

fn new<'a>(username: &'a str, email: &'a str, password: Option<&'a str>) -> New<'a> {
    New {
        username,
        email,
        password,
        is_staff: false,
    }
}

#[tokio::test]
async fn create_normalizes_refuses_duplicates_and_authenticate_opens_by_name_or_email() {
    let db = db!();
    let ada = store::create(
        &db.pool,
        new(" Ada ", "Ada@Example.com", Some("correct horse battery")),
    )
    .await
    .unwrap();
    assert_eq!(
        (ada.username.as_str(), ada.email.as_str()),
        ("ada", "ada@example.com")
    );

    let dup = store::create(&db.pool, new("ADA", "", None))
        .await
        .unwrap_err();
    assert_eq!(
        dup.refused(),
        Some(&owt_accounts::Refused::UsernameTaken("ada".into()))
    );
    let dup = store::create(&db.pool, new("ada2", "ADA@example.com", None))
        .await
        .unwrap_err();
    assert_eq!(
        dup.refused(),
        Some(&owt_accounts::Refused::EmailTaken("ada@example.com".into()))
    );
    let weak = store::create(&db.pool, new("bob", "", Some("bob12345")))
        .await
        .unwrap_err();
    assert!(matches!(
        weak.refused(),
        Some(owt_accounts::Refused::Password(p)) if p.contains(&owt_accounts::password::Problem::Similar)
    ));

    for login in ["ada", "ADA ", "ada@example.com"] {
        let opened = store::authenticate(&db.pool, login, "correct horse battery")
            .await
            .unwrap();
        assert_eq!(opened.as_ref().map(|a| a.id), Some(ada.id), "{login}");
    }
    assert!(
        store::authenticate(&db.pool, "ada", "wrong")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::authenticate(&db.pool, "nobody", "correct horse battery")
            .await
            .unwrap()
            .is_none()
    );
    // No password: nothing opens it, including the empty string.
    let link_only = store::create(&db.pool, new("ghost", "", None))
        .await
        .unwrap();
    assert!(
        store::authenticate(&db.pool, "ghost", "")
            .await
            .unwrap()
            .is_none()
    );
    assert!(!store::has_password(&db.pool, link_only.id).await.unwrap());
    db.drop().await;
}

/// With self-signup, a username shaped like someone else's email would shadow their
/// sign-in by email (the squatter's hash would be checked). No username has an `@`,
/// in the library and in the table's constraint.
#[tokio::test]
async fn a_username_is_never_an_address_so_no_account_shadows_anothers_email() {
    let db = db!();
    let owner = store::create(
        &db.pool,
        new("owner", "shared@example.com", Some("tea and biscuits")),
    )
    .await
    .unwrap();
    let err = store::create(
        &db.pool,
        new("shared@example.com", "", Some("lemon and ginger")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::Username));
    let around_the_library = sqlx::query("INSERT INTO accounts (username) VALUES ('x@y')")
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(
        around_the_library
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_check_violation),
        "{around_the_library}"
    );
    let opened = store::authenticate(&db.pool, "shared@example.com", "tea and biscuits")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.id, owner.id);
    db.drop().await;
}

#[tokio::test]
async fn changing_the_password_deactivating_or_demoting_moves_the_epoch() {
    let db = db!();
    let a = store::create(
        &db.pool,
        new("ada", "ada@example.com", Some("correct horse battery")),
    )
    .await
    .unwrap();
    // A change meets the same rules as a sign-up, the similarity rule included.
    for like in ["ada-forever", "ADA.example"] {
        let err = store::set_password(&db.pool, &a, like).await.unwrap_err();
        assert!(
            matches!(
                err.refused(),
                Some(owt_accounts::Refused::Password(p)) if p.contains(&owt_accounts::password::Problem::Similar)
            ),
            "{like}: {err}"
        );
    }
    assert!(
        store::set_password(&db.pool, &a, "another good passphrase")
            .await
            .unwrap()
    );
    let after = store::by_id(&db.pool, a.id).await.unwrap().unwrap();
    assert_eq!(after.session_epoch, a.session_epoch + 1);
    assert!(
        store::by_id_in_epoch(&db.pool, a.id, a.session_epoch)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::authenticate(&db.pool, "ada", "another good passphrase")
            .await
            .unwrap()
            .is_some()
    );

    store::set_staff(&db.pool, a.id, true).await.unwrap();
    let staff = store::by_id(&db.pool, a.id).await.unwrap().unwrap();
    assert_eq!(
        staff.session_epoch, after.session_epoch,
        "granting changes no session"
    );
    store::set_staff(&db.pool, a.id, false).await.unwrap();
    let demoted = store::by_id(&db.pool, a.id).await.unwrap().unwrap();
    assert_eq!(
        demoted.session_epoch,
        staff.session_epoch + 1,
        "revoking signs out"
    );

    store::set_active(&db.pool, a.id, false).await.unwrap();
    assert!(store::by_id(&db.pool, a.id).await.unwrap().is_none());
    assert!(
        store::authenticate(&db.pool, "ada", "another good passphrase")
            .await
            .unwrap()
            .is_none()
    );
    let row = store::by_username(&db.pool, "ada").await.unwrap().unwrap();
    assert_eq!(row.session_epoch, demoted.session_epoch + 1);
    store::set_active(&db.pool, a.id, true).await.unwrap();
    let back = store::by_id(&db.pool, a.id).await.unwrap().unwrap();
    assert_eq!(
        back.session_epoch, row.session_epoch,
        "re-activating changes no session"
    );
    let gone = store::Account {
        id: 999_999,
        ..back
    };
    assert!(
        !store::set_password(&db.pool, &gone, "another good passphrase")
            .await
            .unwrap()
    );
    db.drop().await;
}

/// The test app: `extra` routes are merged before the layers, which wrap only what
/// is already there.
fn app(db: &Db, sessions: &Sessions<Data>, extra: Router) -> Router {
    async fn whoami(Maybe(account): Maybe) -> String {
        account.map_or_else(|| "anonymous".to_owned(), |a| a.username)
    }
    async fn private(Signed(account): Signed) -> String {
        format!("private for {}", account.username)
    }
    async fn staff(Staff(account): Staff) -> String {
        format!("staff room for {}", account.username)
    }
    async fn sign_out(session: Session<Data>) -> &'static str {
        session::sign_out(&session);
        "out"
    }
    let accounts = Accounts::new(db.pool.clone(), "/login");
    Router::new()
        .merge(extra)
        .route("/whoami", get(whoami))
        .route("/private", get(private))
        .route("/staff", get(staff))
        .route("/out", post(sign_out))
        .layer(from_fn_with_state(accounts, Accounts::load::<Data>))
        .layer(axum::middleware::from_fn_with_state(
            sessions.clone(),
            Sessions::layer,
        ))
}

fn sessions() -> Sessions<Data> {
    let key = owt_web::session::key_from_base64(&base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [7u8; 64],
    ))
    .unwrap();
    Sessions::new(key, "s", Duration::from_secs(3600), false)
}

/// A cookie signed in as `account`, sealed as the app would seal it.
fn cookie_for(sessions: &Sessions<Data>, account: &store::Account) -> String {
    let mut data = Data::default();
    session::Signed::set_signature(
        &mut data,
        Some(session::Signature {
            account: account.id,
            epoch: account.session_epoch,
        }),
    );
    sessions.seal(&owt_web::session::new_id(), &data)
}

#[tokio::test]
async fn the_layer_loads_the_account_walls_the_private_pages_and_drops_a_revoked_signature() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(app(&db, &sessions, Router::new()));

    let r = client.get("/whoami").await;
    assert_eq!(r.text(), "anonymous");
    let r = client.get("/private").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/login?next=%2Fprivate"));

    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    assert_eq!(client.get("/whoami").await.text(), "ada");
    assert_eq!(client.get("/private").await.text(), "private for ada");
    let r = client.get("/staff").await;
    assert_eq!(r.status, 403);

    store::set_staff(&db.pool, ada.id, true).await.unwrap();
    // Granting keeps the epoch: the same cookie now opens the staff room.
    assert_eq!(client.get("/staff").await.text(), "staff room for ada");

    // Signed out everywhere: the next request is anonymous and the cookie no longer
    // carries the signature.
    store::sign_out_everywhere(&db.pool, ada.id).await.unwrap();
    let r = client.get("/whoami").await;
    assert_eq!(r.text(), "anonymous");
    let resealed = client.cookie("s").expect("the cookie was rewritten");
    let (_, data) = sessions.unseal(&resealed).expect("still a session");
    assert_eq!(session::Signed::signature(&data), None);
    assert_eq!(client.get("/private").await.status, 303);
    db.drop().await;
}

/// With the database unreachable the layer can say neither "signed in" nor "revoked":
/// the walled pages answer 503 (the sign-in page could not help), the open ones see
/// an anonymous visitor, and the cookie keeps its signature for when it is back.
#[tokio::test]
async fn an_outage_answers_503_at_the_wall_and_keeps_the_cookie() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(app(&db, &sessions, Router::new()));
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let sealed = cookie_for(&sessions, &ada);
    client.set_cookie("s", &sealed);
    assert_eq!(client.get("/private").await.text(), "private for ada");

    // The layer holds a clone of the pool; closing it fails every query from here on.
    db.pool.close().await;
    let r = client.get("/private").await;
    assert_eq!(r.status, 503, "{}", r.text());
    assert!(r.text().contains("try again"));
    assert_eq!(r.header("retry-after"), Some("5"));
    assert_eq!(client.get("/staff").await.status, 503);
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    let (_, data) = sessions
        .unseal(&client.cookie("s").unwrap())
        .expect("still a session");
    assert_eq!(data.account, Some(ada.id), "the signature is not dropped");
    db.drop().await;
}

/// The session ids the sign-in handler saw on entry.
type Seen = Arc<std::sync::Mutex<Vec<Option<String>>>>;

async fn sign_in_handler(
    axum::extract::State((pool, seen)): axum::extract::State<(PgPool, Seen)>,
    session: Session<Data>,
) -> String {
    seen.lock().unwrap().push(session.id());
    let ada = store::authenticate(&pool, "ada", "correct horse battery")
        .await
        .unwrap()
        .unwrap();
    session::sign_in(&session, &ada);
    session.id().unwrap()
}

#[tokio::test]
async fn signing_in_cycles_the_id_and_signing_out_empties_the_session() {
    let db = db!();
    let sessions = sessions();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    let pool = db.pool.clone();
    let sign_in = Router::new().route("/in", post(sign_in_handler).with_state((pool, seen2)));
    let router = app(&db, &sessions, sign_in);
    let client = owt_test::Client::new(router);
    // An anonymous session first, so there is an id to cycle.
    client.set_cookie("s", &sessions.seal("anonymous-id", &Data::default()));
    let new_id = client.post_form("/in", &[]).await.text();
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[Some("anonymous-id".to_owned())]
    );
    assert_ne!(new_id, "anonymous-id");
    assert_eq!(client.get("/whoami").await.text(), "ada");
    let (id, data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    assert_eq!(id, new_id);
    assert_eq!(data.account, Some(ada.id));

    client.post_form("/out", &[]).await;
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    let (id, data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    assert_ne!(id, new_id);
    assert_eq!(data, Data::default());
    db.drop().await;
}

fn identity(uid: &str, email: Option<&str>, verified: bool) -> oauth::Identity {
    oauth::Identity {
        uid: uid.into(),
        email: email.map(str::to_owned),
        email_verified: verified,
        display_name: Some("Ada Lovelace".into()),
        extra: serde_json::json!({"name": "Ada Lovelace", "email": email}),
    }
}

fn sso(issuer: &str) -> oauth::Provider {
    oauth::oidc(
        "sso",
        "SSO",
        issuer,
        "https://sso.example/a",
        "https://sso.example/t",
        "https://sso.example/u",
    )
    .unwrap()
}

#[tokio::test]
async fn an_identity_arrives_by_its_subject_or_creates_an_account() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        record_email: true,
    };
    // Unknown, with nothing allowed.
    let arrival = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g1", None, false),
        identities::Welcome::default(),
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);

    // Created, with a username from the name.
    let arrival = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g1", Some("ada@example.com"), true),
        open,
    )
    .await
    .unwrap();
    let identities::Arrival::Created(ada) = arrival else {
        panic!("{arrival:?}")
    };
    assert_eq!(ada.username, "adalovelace");
    assert_eq!(ada.email, "ada@example.com");

    // Known on the next arrival, though the email changed at the provider.
    let again = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g1", Some("ada@new.example"), true),
        open,
    )
    .await
    .unwrap();
    assert_eq!(again, identities::Arrival::Known(ada.clone()));

    // An empty subject is nobody, whatever the email says.
    let err = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("", Some("ada@example.com"), true),
        open,
    )
    .await
    .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::NoSubject));
    let err = identities::link(
        &db.pool,
        ada.id,
        &oauth::google(),
        &identity("", None, true),
    )
    .await
    .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::NoSubject));

    // Linking an identity another account holds is refused.
    let other = store::create(&db.pool, new("other", "", None))
        .await
        .unwrap();
    let err = identities::link(
        &db.pool,
        other.id,
        &oauth::google(),
        &identity("g1", None, true),
    )
    .await
    .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::IdentityTaken));

    // Linked from the signed-in account, a second provider signs in to it.
    identities::link(
        &db.pool,
        ada.id,
        &oauth::discord(),
        &identity("d1", None, false),
    )
    .await
    .unwrap();
    let arrival = identities::arrive(
        &db.pool,
        &oauth::discord(),
        &identity("d1", None, false),
        open,
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Known(ada.clone()));

    // A deactivated account's identity signs nobody in.
    store::set_active(&db.pool, ada.id, false).await.unwrap();
    let arrival = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g1", None, false),
        open,
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);
    db.drop().await;
}

#[tokio::test]
async fn the_last_way_in_cannot_be_unlinked() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    // Unlinking the only way in is refused; with a password it goes.
    let lone = identities::arrive(
        &db.pool,
        &oauth::twitch(),
        &identity("t1", None, false),
        open,
    )
    .await
    .unwrap();
    let identities::Arrival::Created(lone) = lone else {
        panic!("{lone:?}")
    };
    let only = identities::list(&db.pool, lone.id).await.unwrap()[0].id;
    let err = identities::unlink(&db.pool, lone.id, only)
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::LastWayIn));
    store::set_password(&db.pool, &lone, "a passphrase of her own")
        .await
        .unwrap();
    assert!(identities::unlink(&db.pool, lone.id, only).await.unwrap());
    assert!(!identities::unlink(&db.pool, lone.id, only).await.unwrap());

    db.drop().await;
}

/// The account-takeover shape: someone holds, at another provider, an address an
/// account here was created with (it changed hands, or the provider vouches loosely).
/// A verified match must not open the account, link to it, or reveal it.
#[tokio::test]
async fn a_verified_email_never_opens_someone_elses_account() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        record_email: true,
    };
    let ada = store::create(
        &db.pool,
        new("ada", "ada@example.com", Some("correct horse battery")),
    )
    .await
    .unwrap();
    for (provider, uid) in [
        (oauth::google(), "g9"),
        (oauth::discord(), "d9"),
        (oauth::twitch(), "t9"),
        (sso("https://sso.example/realms/x"), "s9"),
    ] {
        let arrival = identities::arrive(
            &db.pool,
            &provider,
            &identity(uid, Some("ADA@example.com"), true),
            open,
        )
        .await
        .unwrap();
        let identities::Arrival::Created(stranger) = arrival else {
            panic!("{arrival:?}")
        };
        assert_ne!(stranger.id, ada.id);
        // The address stays with its holder; the newcomer gets none.
        assert_eq!(stranger.email, "");
    }
    assert_eq!(
        identities::list(&db.pool, ada.id).await.unwrap(),
        Vec::new()
    );

    // With self-signup off, the same arrival is simply unknown.
    let arrival = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g10", Some("ada@example.com"), true),
        identities::Welcome::default(),
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);
    db.drop().await;
}

/// An OIDC provider's subjects belong to its issuer: an app that re-points its `sso`
/// id at another realm does not sign that realm's `sub` into the old realm's person.
#[tokio::test]
async fn an_oidc_subject_belongs_to_its_issuer() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    let first = identities::arrive(
        &db.pool,
        &sso("https://sso.example/realms/a"),
        &identity("42", None, false),
        open,
    )
    .await
    .unwrap();
    let second = identities::arrive(
        &db.pool,
        &sso("https://sso.example/realms/b"),
        &identity("42", None, false),
        open,
    )
    .await
    .unwrap();
    let (identities::Arrival::Created(a), identities::Arrival::Created(b)) = (&first, &second)
    else {
        panic!("{first:?} {second:?}")
    };
    assert_ne!(a.id, b.id);
    let linked = identities::list(&db.pool, a.id).await.unwrap();
    assert_eq!(linked[0].provider, "https://sso.example/realms/a");
    db.drop().await;
}

#[tokio::test]
async fn a_sign_in_link_opens_once_within_its_lifetime() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let minted = links::mint(&db.pool, ada.id, Duration::from_secs(600), "new account")
        .await
        .unwrap();
    assert_eq!(minted.token.len(), 43);
    let err = links::redeem(&db.pool, "not-a-token", "203.0.113.9")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::Link));
    let opened = links::redeem(&db.pool, &minted.token, "203.0.113.9")
        .await
        .unwrap();
    assert_eq!(opened.id, ada.id);
    let err = links::redeem(&db.pool, &minted.token, "203.0.113.9")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::Link));

    let expired = links::mint(&db.pool, ada.id, Duration::ZERO, "late")
        .await
        .unwrap();
    assert!(links::redeem(&db.pool, &expired.token, "x").await.is_err());
    // An absurd lifetime is capped, not an "interval out of range" from Postgres.
    let forever = links::mint(&db.pool, ada.id, Duration::MAX, "forever")
        .await
        .unwrap();
    assert_eq!(
        links::redeem(&db.pool, &forever.token, "x")
            .await
            .unwrap()
            .id,
        ada.id
    );

    let voided = links::mint(&db.pool, ada.id, Duration::from_secs(600), "reset")
        .await
        .unwrap();
    // The expired link is unused too, so two are voided.
    assert_eq!(links::void_all(&db.pool, ada.id).await.unwrap(), 2);
    assert!(links::redeem(&db.pool, &voided.token, "x").await.is_err());

    // Only digests are stored.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_sha256 FROM sign_in_links")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert!(stored.iter().all(|d| d.len() == 32));
    db.drop().await;
}

/// The wall under `Router::nest` names the whole path in `?next=`, prefix included.
/// No database is asked: an anonymous request makes no query, so the pool never
/// connects, and this test runs without `DATABASE_URL`.
#[tokio::test]
async fn the_wall_under_a_nested_router_keeps_the_prefix_in_next() {
    async fn private(_: Signed) -> &'static str {
        "hi"
    }
    async fn staff(_: Staff) -> &'static str {
        "hi"
    }
    let pool = PgPool::connect_lazy("postgres://localhost/unused").unwrap();
    let app = Router::new()
        .nest(
            "/es",
            Router::new()
                .route("/profile", get(private))
                .route("/admin", get(staff)),
        )
        .layer(from_fn_with_state(
            Accounts::new(pool, "/es/login"),
            Accounts::load::<Data>,
        ));
    let client = owt_test::Client::new(app);
    let r = client.get("/es/profile?tab=2").await;
    assert_eq!(r.status, 303);
    assert_eq!(
        r.location(),
        Some("/es/login?next=%2Fes%2Fprofile%3Ftab%3D2")
    );
    let r = client.get("/es/admin").await;
    assert_eq!(r.location(), Some("/es/login?next=%2Fes%2Fadmin"));
}

/// A callback opened twice at once: both first sign-ins with one identity resolve to
/// the one account, and no second account is left that nothing signs in to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_first_sign_ins_make_one_account() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        record_email: true,
    };
    // Every connection open first, so the racers start together.
    let mut warm = Vec::new();
    for _ in 0..4 {
        warm.push(db.pool.acquire().await.unwrap());
    }
    drop(warm);
    for round in 0..10 {
        let who = identity(
            &format!("race-{round}"),
            Some(&format!("r{round}@example.com")),
            true,
        );
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(4));
        let mut racing = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let (pool, who, start) = (db.pool.clone(), who.clone(), start.clone());
            racing.spawn(async move {
                start.wait().await;
                identities::arrive(&pool, &oauth::google(), &who, open).await
            });
        }
        let mut accounts = std::collections::BTreeSet::new();
        while let Some(arrival) = racing.join_next().await {
            accounts.insert(arrival.unwrap().unwrap().account().unwrap().id);
        }
        assert_eq!(accounts.len(), 1, "round {round}: {accounts:?}");
        let account = store::by_id(&db.pool, *accounts.first().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.email, format!("r{round}@example.com"));
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(total, 10);
    db.drop().await;
}

/// Two unlinks at once on an account whose identities are its only way in: one of
/// them goes, never both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_unlinks_leave_a_way_in() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    for round in 0..10 {
        let first = identity(&format!("u{round}"), None, false);
        let identities::Arrival::Created(account) =
            identities::arrive(&db.pool, &oauth::google(), &first, open)
                .await
                .unwrap()
        else {
            panic!("not created")
        };
        identities::link(
            &db.pool,
            account.id,
            &oauth::discord(),
            &identity(&format!("d{round}"), None, false),
        )
        .await
        .unwrap();
        let ids: Vec<i64> = identities::list(&db.pool, account.id)
            .await
            .unwrap()
            .iter()
            .map(|l| l.id)
            .collect();
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut racing = tokio::task::JoinSet::new();
        for id in ids {
            let (pool, start) = (db.pool.clone(), start.clone());
            racing.spawn(async move {
                start.wait().await;
                identities::unlink(&pool, account.id, id).await
            });
        }
        while racing.join_next().await.is_some() {}
        let left = identities::list(&db.pool, account.id).await.unwrap();
        assert_eq!(left.len(), 1, "round {round}");
    }
    db.drop().await;
}

/// Unlinking an identity that is not the account's is "no such link", even on an
/// account whose only way in is one identity.
#[tokio::test]
async fn unlinking_another_accounts_identity_is_no_such_link() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    let arrive = |uid: &'static str| {
        let pool = db.pool.clone();
        async move {
            match identities::arrive(&pool, &oauth::google(), &identity(uid, None, false), open)
                .await
                .unwrap()
            {
                identities::Arrival::Created(a) => a,
                other => panic!("{other:?}"),
            }
        }
    };
    let (lone, other) = (arrive("x1").await, arrive("x2").await);
    let theirs = identities::list(&db.pool, other.id).await.unwrap()[0].id;
    assert!(!identities::unlink(&db.pool, lone.id, theirs).await.unwrap());
    assert!(
        !identities::unlink(&db.pool, lone.id, i64::MAX)
            .await
            .unwrap()
    );
    assert_eq!(identities::list(&db.pool, other.id).await.unwrap().len(), 1);
    db.drop().await;
}

/// A created account takes the provider's address only when the app says so.
#[tokio::test]
async fn a_created_account_records_the_email_only_when_asked() {
    let db = db!();
    let created = |uid: &'static str, record_email| {
        let pool = db.pool.clone();
        async move {
            let welcome = identities::Welcome {
                create: true,
                record_email,
            };
            let who = identity(uid, Some(&format!("{uid}@example.com")), true);
            match identities::arrive(&pool, &oauth::google(), &who, welcome)
                .await
                .unwrap()
            {
                identities::Arrival::Created(a) => a,
                other => panic!("{other:?}"),
            }
        }
    };
    assert_eq!(created("e1", false).await.email, "");
    assert_eq!(created("e2", true).await.email, "e2@example.com");
    db.drop().await;
}

/// Identities stored under a key no provider gives are found, and moved; a subject
/// the new key has already stays where it is, for a person to decide.
#[tokio::test]
async fn identities_under_an_old_key_are_found_and_moved() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    let realm = sso("https://sso.example/realms/x");
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let bob = store::create(&db.pool, new("bob", "", Some("correct horse battery")))
        .await
        .unwrap();
    for (account, subject) in [(ada.id, "s1"), (bob.id, "s2")] {
        sqlx::query(
            "INSERT INTO account_identities (account_id, provider, subject, claims)
             VALUES ($1, 'sso', $2, '{}')",
        )
        .bind(account)
        .bind(subject)
        .execute(&db.pool)
        .await
        .unwrap();
    }
    assert_eq!(
        identities::unconfigured(&db.pool, &[&realm, &oauth::google()])
            .await
            .unwrap(),
        vec![("sso".to_owned(), 2)]
    );
    // Bob signed in after the deploy and before the rekey: a second account.
    identities::arrive(&db.pool, &realm, &identity("s2", None, false), open)
        .await
        .unwrap();
    let configured = [&realm, &oauth::google()];
    assert!(matches!(
        identities::rekey(&db.pool, "google", &realm, &configured).await,
        Err(identities::RekeyError::InUse(_))
    ));
    assert!(matches!(
        identities::rekey(&db.pool, realm.key(), &realm, &configured).await,
        Err(identities::RekeyError::SameKey(_))
    ));
    let done = identities::rekey(&db.pool, "sso", &realm, &configured)
        .await
        .unwrap();
    assert_eq!(done.moved, 1);
    assert_eq!(done.conflicts, vec!["s2".to_owned()]);
    let found = identities::find(&db.pool, &realm, "s1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.account_id, ada.id);
    db.drop().await;
}

/// A role the tests declare, as an app would.
struct Host;
impl owt_accounts::roles::Named for Host {
    const ROLE: owt_accounts::roles::Role =
        owt_accounts::roles::Role::new("host", "Host", "May run a live session.").held_by_staff();
}
const EDITOR: owt_accounts::roles::Role =
    owt_accounts::roles::Role::new("editor", "Editor", "May edit the content.");

#[tokio::test]
async fn roles_are_granted_held_and_revoked_at_the_next_request() {
    use owt_accounts::roles::{self, Holds, Named};
    async fn host(Holds(me, _): Holds<Host>) -> String {
        format!("hosting: {}", me.username)
    }
    /// What page chrome asks: may the viewer host?
    async fn may_host(req: axum::extract::Request) -> String {
        roles::signed_in_holds(req.extensions(), &Host::ROLE).to_string()
    }
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(app(
        &db,
        &sessions,
        Router::new()
            .route("/host", get(host))
            .route("/may-host", get(may_host)),
    ));
    assert_eq!(client.get("/host").await.status, 303);
    assert_eq!(client.get("/may-host").await.text(), "false");

    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    let r = client.get("/host").await;
    assert_eq!(r.status, 403);
    assert!(r.text().contains("Host"), "{}", r.text());

    assert!(
        roles::grant(&db.pool, ada.id, &Host::ROLE, Some(boss.id))
            .await
            .unwrap()
    );
    assert!(
        !roles::grant(&db.pool, ada.id, &Host::ROLE, None)
            .await
            .unwrap()
    );
    assert_eq!(client.get("/host").await.text(), "hosting: ada");
    assert_eq!(client.get("/may-host").await.text(), "true");
    let ada_now = store::by_id(&db.pool, ada.id).await.unwrap().unwrap();
    assert_eq!(ada_now.roles, vec!["host".to_owned()]);
    assert!(ada_now.holds(&Host::ROLE) && !ada_now.holds(&EDITOR));

    // Holders: granted ones and, for a role staff hold, staff.
    let names = |v: Vec<store::Account>| v.into_iter().map(|a| a.username).collect::<Vec<_>>();
    assert_eq!(
        names(roles::holders(&db.pool, &Host::ROLE).await.unwrap()),
        ["ada", "boss"]
    );
    assert_eq!(
        names(roles::holders(&db.pool, &EDITOR).await.unwrap()),
        Vec::<String>::new()
    );

    // Revoked: refused at the next request, still signed in.
    assert!(roles::revoke(&db.pool, ada.id, &Host::ROLE).await.unwrap());
    assert_eq!(client.get("/host").await.status, 403);
    assert_eq!(client.get("/whoami").await.text(), "ada");

    // Staff hold it without a grant.
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    assert_eq!(client.get("/host").await.text(), "hosting: boss");
    db.drop().await;
}

/// Text made safe for HTML, as an app's layout must make the page's title.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The admin at `/staff/accounts`, drawn in a bare shell.
fn admin(db: &Db) -> owt_accounts::admin::Admin {
    use owt_accounts::admin::{Admin, Page};
    use owt_accounts::roles::Named;
    let chrome = |page: Page<'_>| -> owt_web::Result<axum::response::Response> {
        use axum::response::IntoResponse;
        Ok(axum::response::Html(format!(
            "<title>{}</title><p>me: {}</p>{}",
            escaped(page.title),
            escaped(&page.me.username),
            page.body
        ))
        .into_response())
    };
    Admin::new(db.pool.clone(), "/staff/accounts", chrome).roles(&[Host::ROLE, EDITOR])
}

/// The test app with the whole admin.
fn admin_app(db: &Db, sessions: &Sessions<Data>) -> Router {
    let admin = admin(db)
        .sign_in_links(Duration::from_secs(86_400), |token| {
            format!("https://app.example/login/link/{token}")
        })
        .more("Profile", |a| format!("/staff/profiles/{}", a.id));
    app(db, sessions, admin.routes())
}

/// Under the app's enforcing CSP, an admin page keeps the app's whole policy (the
/// admin adds no policy of its own, which would make the layer skip the app's) and is
/// never framed.
#[tokio::test]
async fn an_admin_page_keeps_the_apps_csp() {
    use owt_web::headers::Csp;
    let db = db!();
    let sessions = sessions();
    let app = admin_app(&db, &sessions).layer(from_fn_with_state(Csp::new(), Csp::layer));
    let client = owt_test::Client::new(app);
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let r = client.get("/staff/accounts").await;
    assert_eq!(r.status, 200);
    let policy = r
        .header("content-security-policy")
        .unwrap_or_default()
        .to_owned();
    assert!(
        policy.contains("script-src") && policy.contains("frame-ancestors 'none'"),
        "{policy}"
    );
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    db.drop().await;
}

/// The value of the one-time secret on an admin page.
fn secret(html: &str) -> String {
    html.split("owt-secret-value\">")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .expect("a secret on the page")
        .replace("&#x2f;", "/")
        .replace("&#47;", "/")
}

#[tokio::test]
async fn the_admin_is_for_staff_and_finds_accounts_by_name_email_and_role() {
    use owt_accounts::roles;
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let r = client.get("/staff/accounts").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/login?next=%2Fstaff%2Faccounts"));

    let ada = store::create(&db.pool, new("ada", "ada@example.com", None))
        .await
        .unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let cy = store::create(&db.pool, new("cy_50%", "", None))
        .await
        .unwrap();
    roles::grant(&db.pool, cy.id, &EDITOR, None).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    assert_eq!(client.get("/staff/accounts").await.status, 403);

    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let r = client.get("/staff/accounts").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"), "never framed");
    let html = r.text();
    assert!(
        html.contains("<title>Accounts</title><p>me: boss</p>"),
        "{html}"
    );
    assert!(
        html.contains("3 accounts") && html.contains("ada@example.com"),
        "{html}"
    );
    assert!(
        html.contains(r#"<span class="owt-badge">Editor</span>"#),
        "{html}"
    );

    let found = |q: &str| {
        let client = &client;
        let q = q.to_owned();
        async move {
            let html = client.get(&format!("/staff/accounts?{q}")).await.text();
            ["ada", "boss", "cy_50%"]
                .into_iter()
                .filter(|u| html.contains(&format!(">{u}</a>")))
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(found("q=EXAMPLE.com").await, ["ada"]);
    // `%` and `_` are themselves, not wildcards.
    assert_eq!(found("q=%25").await, ["cy_50%"]);
    assert_eq!(found("q=_").await, ["cy_50%"]);
    assert_eq!(found("role=staff").await, ["boss"]);
    assert_eq!(found("role=editor").await, ["cy_50%"]);
    // Staff hold the host role: they are listed as its holders.
    assert_eq!(found("role=host").await, ["boss"]);
    // An unknown filter shows everyone rather than nothing.
    assert_eq!(found("role=nope").await.len(), 3);
    store::set_active(&db.pool, cy.id, false).await.unwrap();
    assert_eq!(found("role=inactive").await, ["cy_50%"]);
    db.drop().await;
}

#[tokio::test]
async fn the_admin_creates_and_changes_accounts_and_never_locks_out_its_user() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));

    let html = client.get("/staff/accounts/new").await.text();
    assert!(
        html.contains(r#"name="role" value="host""#) && html.contains("Staff hold it anyway."),
        "{html}"
    );
    let r = client
        .post_form(
            "/staff/accounts",
            &[
                ("username", "Ada"),
                ("email", "ada@example.com"),
                ("role", "host"),
                ("role", "nonsense"),
            ],
        )
        .await;
    assert_eq!(r.status, 303, "{}", r.text());
    let ada = store::by_username(&db.pool, "ada").await.unwrap().unwrap();
    assert_eq!(
        r.location(),
        Some(format!("/staff/accounts/{}?notice=created", ada.id).as_str())
    );
    assert_eq!(ada.roles, ["host"]);
    assert!(!ada.is_staff);
    assert!(!store::has_password(&db.pool, ada.id).await.unwrap());

    // A taken username: the form again, with the reason and what was typed.
    let r = client
        .post_form("/staff/accounts", &[("username", "ada"), ("email", "")])
        .await;
    assert_eq!(r.status, 422);
    assert!(r.text().contains("owt-alert-error"), "{}", r.text());

    let page = client
        .get(&format!("/staff/accounts/{}?notice=created", ada.id))
        .await
        .text();
    assert!(
        page.contains("Account created.") && page.contains(r#"href="/staff/profiles/"#),
        "{page}"
    );

    // Change: email, staff on, host off, editor on.
    let at = format!("/staff/accounts/{}", ada.id);
    let r = client
        .post_form(
            &at,
            &[
                ("email", "ada@new.example"),
                ("active", "on"),
                ("staff", "on"),
                ("role", "editor"),
            ],
        )
        .await;
    assert_eq!(r.location(), Some(format!("{at}?notice=saved").as_str()));
    let ada = store::by_username(&db.pool, "ada").await.unwrap().unwrap();
    assert_eq!(
        (ada.email.as_str(), ada.is_staff, ada.roles.clone()),
        ("ada@new.example", true, vec!["editor".to_owned()])
    );

    // A refused email keeps the form and changes nothing.
    store::create(&db.pool, new("cy", "cy@example.com", None))
        .await
        .unwrap();
    let r = client
        .post_form(&at, &[("email", "cy@example.com"), ("active", "on")])
        .await;
    assert_eq!(r.status, 422);
    assert!(r.text().contains("cy@example.com"));
    assert!(
        store::by_username(&db.pool, "ada")
            .await
            .unwrap()
            .unwrap()
            .is_staff
    );

    // Deactivating and removing staff sign the account out.
    let r = client.post_form(&at, &[("email", "ada@new.example")]).await;
    assert_eq!(r.status, 303);
    let row = store::by_username(&db.pool, "ada").await.unwrap().unwrap();
    assert!(!row.is_active && !row.is_staff && row.session_epoch > ada.session_epoch);
    db.drop().await;
}

#[tokio::test]
async fn the_admin_never_lets_its_user_lock_themselves_out() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let mine = format!("/staff/accounts/{}", boss.id);
    for fields in [
        &[("email", ""), ("active", "on")][..],
        &[("email", ""), ("staff", "on")][..],
    ] {
        let r = client.post_form(&mine, fields).await;
        assert_eq!(r.status, 403, "{}", r.text());
    }
    let me = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    assert!(me.is_staff && me.is_active);
    assert!(
        client
            .get(&mine)
            .await
            .text()
            .contains("You cannot take away your own staff access.")
    );
    db.drop().await;
}

#[tokio::test]
async fn the_admin_gives_a_way_in_once_and_takes_them_away() {
    use owt_auth::oauth;
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let at = format!("/staff/accounts/{}", ada.id);

    // A generated password, shown in the answer to the POST and nowhere after.
    let r = client.post_form(&format!("{at}/password"), &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let password = secret(&r.text());
    assert_eq!(password.len(), 20);
    assert!(
        store::authenticate(&db.pool, "ada", &password)
            .await
            .unwrap()
            .is_some()
    );
    assert!(!client.get(&at).await.text().contains(&password));

    // A sign-in link at the app's URL, good once.
    let r = client.post_form(&format!("{at}/link"), &[]).await;
    let url = secret(&r.text());
    assert!(r.text().contains("within 1 day"), "{}", r.text());
    let token = url
        .strip_prefix("https://app.example/login/link/")
        .expect(&url);
    let opened = links::redeem(&db.pool, token, "203.0.113.9").await.unwrap();
    assert_eq!(opened.id, ada.id);

    // Signed out everywhere: the epoch moves.
    let before = store::by_id(&db.pool, ada.id)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    let r = client.post_form(&format!("{at}/sign-out"), &[]).await;
    assert_eq!(
        r.location(),
        Some(format!("{at}?notice=signed-out").as_str())
    );
    assert!(
        store::by_id(&db.pool, ada.id)
            .await
            .unwrap()
            .unwrap()
            .session_epoch
            > before
    );

    // A connection can be removed while a password remains; the last way in cannot.
    let who = identity("g1", None, false);
    let linked = identities::link(&db.pool, ada.id, &oauth::google(), &who)
        .await
        .unwrap();
    assert!(client.get(&at).await.text().contains(">google</td>"));
    let epoch = store::by_id(&db.pool, ada.id)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    let r = client
        .post_form(&format!("{at}/identities/{}/unlink", linked.id), &[])
        .await;
    assert_eq!(r.location(), Some(format!("{at}?notice=unlinked").as_str()));
    // Whoever signed in through it is signed out.
    assert!(
        store::by_id(&db.pool, ada.id)
            .await
            .unwrap()
            .unwrap()
            .session_epoch
            > epoch
    );
    let lone = identities::arrive(
        &db.pool,
        &oauth::discord(),
        &identity("d1", None, false),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let lone = lone.account().unwrap().clone();
    let only = identities::list(&db.pool, lone.id).await.unwrap()[0].id;
    let r = client
        .post_form(
            &format!("/staff/accounts/{}/identities/{only}/unlink", lone.id),
            &[],
        )
        .await;
    assert_eq!(
        r.location(),
        Some(format!("/staff/accounts/{}?notice=last-way-in", lone.id).as_str())
    );
    assert_eq!(identities::list(&db.pool, lone.id).await.unwrap().len(), 1);

    assert_eq!(client.get("/staff/accounts/999999").await.status, 404);
    db.drop().await;
}

/// Only staff, from this origin, reach the admin's actions: a signed-in user gets a
/// 403 from every one, and so does staff's own browser posting from another site
/// (a sibling subdomain is same-site, so `SameSite=Lax` would have sent the cookie).
#[tokio::test]
async fn the_admin_refuses_everyone_but_staff_and_every_other_origin() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    let linked = identities::link(
        &db.pool,
        ada.id,
        &owt_auth::oauth::google(),
        &identity("g1", None, false),
    )
    .await
    .unwrap();
    let at = format!("/staff/accounts/{}", ada.id);
    let actions = [
        "/staff/accounts".to_owned(),
        at.clone(),
        format!("{at}/password"),
        format!("{at}/link"),
        format!("{at}/sign-out"),
        format!("{at}/identities/{}/unlink", linked.id),
    ];
    let fields = [
        ("username", "x"),
        ("email", ""),
        ("active", "on"),
        ("staff", "on"),
    ];

    client.set_cookie("s", &cookie_for(&sessions, &ada));
    for path in &actions {
        let r = client.post_form(path, &fields).await;
        assert_eq!(r.status, 403, "{path}: {}", r.text());
    }
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    for path in &actions {
        for site in ["cross-site", "same-site"] {
            let r = client
                .send(
                    axum::http::Request::post(path)
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("sec-fetch-site", site)
                        .body(axum::body::Body::from("email=&active=on&staff=on"))
                        .unwrap(),
                )
                .await;
            assert_eq!(r.status, 403, "{site} {path}");
        }
    }
    // Nothing changed.
    let ada_now = store::by_id(&db.pool, ada.id).await.unwrap().unwrap();
    assert!(!ada_now.is_staff && ada_now.session_epoch == ada.session_epoch);
    assert!(
        store::authenticate(&db.pool, "ada", "correct horse battery")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 1);
    assert!(store::by_username(&db.pool, "x").await.unwrap().is_none());
    db.drop().await;
}

/// Two staff taking each other's staff access away at the same moment: the changes
/// queue on the rows, the second finds its author no longer staff, and staff never
/// reach zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staff_removing_each_other_at_once_leave_one() {
    let db = db!();
    let sessions = sessions();
    let router = admin_app(&db, &sessions);
    let a = store::create(&db.pool, new("ann", "", None)).await.unwrap();
    let b = store::create(&db.pool, new("bea", "", None)).await.unwrap();
    for round in 0..10 {
        for id in [a.id, b.id] {
            store::set_staff(&db.pool, id, true).await.unwrap();
        }
        let ann = store::by_id(&db.pool, a.id).await.unwrap().unwrap();
        let bea = store::by_id(&db.pool, b.id).await.unwrap().unwrap();
        let (as_ann, as_bea) = (
            owt_test::Client::new(router.clone()),
            owt_test::Client::new(router.clone()),
        );
        as_ann.set_cookie("s", &cookie_for(&sessions, &ann));
        as_bea.set_cookie("s", &cookie_for(&sessions, &bea));
        let demote = |client: owt_test::Client, target: i64| async move {
            client
                .post_form(
                    &format!("/staff/accounts/{target}"),
                    &[("email", ""), ("active", "on")],
                )
                .await
                .status
        };
        let (one, two) = tokio::join!(
            tokio::spawn(demote(as_ann, bea.id)),
            tokio::spawn(demote(as_bea, ann.id)),
        );
        let staff: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE is_staff")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            staff,
            1,
            "round {round}: {:?} {:?}",
            one.unwrap(),
            two.unwrap()
        );
    }
    db.drop().await;
}

/// A role the app stopped declaring stays visible, revocable and never grantable.
#[tokio::test]
async fn an_undeclared_role_is_shown_and_can_only_be_revoked() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let cy = store::create(&db.pool, new("cy", "", None)).await.unwrap();
    sqlx::query("INSERT INTO account_roles (account_id, role) VALUES ($1, 'retired')")
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        client
            .get("/staff/accounts")
            .await
            .text()
            .contains("retired (undeclared)")
    );
    let at = format!("/staff/accounts/{}", ada.id);
    let page = client.get(&at).await.text();
    assert!(
        page.contains(r#"name="role" value="retired" checked"#),
        "{page}"
    );
    // Kept while ticked; another account cannot be given it.
    client
        .post_form(&at, &[("email", ""), ("active", "on"), ("role", "retired")])
        .await;
    client
        .post_form(
            &format!("/staff/accounts/{}", cy.id),
            &[("email", ""), ("active", "on"), ("role", "retired")],
        )
        .await;
    let held = |id| {
        let pool = db.pool.clone();
        async move { store::by_id(&pool, id).await.unwrap().unwrap().roles }
    };
    assert_eq!(held(ada.id).await, ["retired"]);
    assert_eq!(held(cy.id).await, Vec::<String>::new());
    // Unticked: revoked.
    client
        .post_form(&at, &[("email", ""), ("active", "on")])
        .await;
    assert_eq!(held(ada.id).await, Vec::<String>::new());
    db.drop().await;
}

/// Revoking a way in voids the sign-in links still out; a deactivated account gets
/// none; an unknown or another account's connection is a 404; without links
/// configured the action is a 404.
#[tokio::test]
async fn the_admin_leaves_no_way_back_in_behind() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let at = format!("/staff/accounts/{}", ada.id);
    let mint = || {
        let pool = db.pool.clone();
        async move {
            links::mint(&pool, ada.id, Duration::from_secs(600), "test")
                .await
                .unwrap()
                .token
        }
    };
    let spent = |token: String| {
        let pool = db.pool.clone();
        async move { links::redeem(&pool, &token, "test").await.is_err() }
    };
    for action in ["password", "sign-out"] {
        let token = mint().await;
        client.post_form(&format!("{at}/{action}"), &[]).await;
        assert!(spent(token).await, "{action} left a link alive");
    }
    let token = mint().await;
    client.post_form(&at, &[("email", "")]).await; // deactivated
    store::set_active(&db.pool, ada.id, true).await.unwrap();
    assert!(spent(token).await, "deactivating left a link alive");

    store::set_active(&db.pool, ada.id, false).await.unwrap();
    let r = client.post_form(&format!("{at}/link"), &[]).await;
    assert_eq!(r.status, 409);
    assert!(!r.text().contains("owt-secret-value"));

    let cy = store::create(&db.pool, new("cy", "", Some("correct horse battery")))
        .await
        .unwrap();
    let cys = identities::link(
        &db.pool,
        cy.id,
        &owt_auth::oauth::google(),
        &identity("g-cy", None, false),
    )
    .await
    .unwrap();
    for path in [
        format!("{at}/identities/{}/unlink", cys.id),
        format!("{at}/identities/999999/unlink"),
    ] {
        assert_eq!(client.post_form(&path, &[]).await.status, 404, "{path}");
    }
    assert_eq!(identities::list(&db.pool, cy.id).await.unwrap().len(), 1);

    let bare = owt_test::Client::new(app(&db, &sessions, admin(&db).routes()));
    bare.set_cookie("s", &cookie_for(&sessions, &boss));
    assert_eq!(bare.post_form(&format!("{at}/link"), &[]).await.status, 404);
    db.drop().await;
}

/// A username is the page's title: the app's layout escapes it, and the admin's
/// own body escapes everything it shows.
#[tokio::test]
async fn a_username_is_text_on_every_admin_page() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let evil = store::create(&db.pool, new("</title><svg/onload=alert(1)>", "", None))
        .await
        .unwrap();
    for path in [
        "/staff/accounts".to_owned(),
        format!("/staff/accounts/{}", evil.id),
    ] {
        let html = client.get(&path).await.text();
        assert!(!html.contains("<svg"), "{path}: {html}");
    }
    db.drop().await;
}

/// The list pages past fifty accounts and keeps its search and filter on each page.
#[tokio::test]
async fn the_list_pages_and_keeps_its_filter() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    sqlx::query(
        "WITH made AS (
            INSERT INTO accounts (username, email, password_hash)
            SELECT 'ed' || lpad(n::text, 3, '0'), '', '' FROM generate_series(1, 55) n
            RETURNING id)
         INSERT INTO account_roles (account_id, role) SELECT id, 'editor' FROM made",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let first = client.get("/staff/accounts?q=ed&role=editor").await.text();
    assert!(
        first.contains("55 accounts")
            && first.contains(">ed050</a>")
            && !first.contains(">ed051</a>"),
        "{first}"
    );
    assert!(
        first.contains("?q=ed&#38;role=editor&#38;page=2"),
        "{first}"
    );
    let second = client
        .get("/staff/accounts?q=ed&role=editor&page=2")
        .await
        .text();
    assert!(
        second.contains(">ed055</a>") && !second.contains(">ed001</a>"),
        "{second}"
    );
    db.drop().await;
}
