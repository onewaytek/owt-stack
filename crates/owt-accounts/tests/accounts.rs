//! The crate against a real Postgres (`DATABASE_URL`); skipped without it. Each
//! test takes a schema of its own, so they run in parallel and leave nothing.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use owt_accounts::session::{self, Data};
use owt_accounts::{Accounts, Maybe, New, Signed, Staff, identities, links, store};
use owt_web::session::{Session, Sessions};
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

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
        owt_accounts::migrations::MIGRATOR.run(&pool).await.unwrap();
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

#[tokio::test]
async fn a_username_equal_to_another_accounts_email_opens_its_own_account() {
    let db = db!();
    let owner = store::create(
        &db.pool,
        new("owner", "shared@example.com", Some("tea and biscuits")),
    )
    .await
    .unwrap();
    let squatter = store::create(
        &db.pool,
        new("shared@example.com", "", Some("lemon and ginger")),
    )
    .await
    .unwrap();
    let opened = store::authenticate(&db.pool, "shared@example.com", "lemon and ginger")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.id, squatter.id);
    let opened = store::authenticate(&db.pool, "shared@example.com", "tea and biscuits")
        .await
        .unwrap();
    assert!(
        opened.is_none(),
        "the email login is shadowed, not opened by the owner's password"
    );
    assert_eq!(
        store::by_email(&db.pool, "shared@example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        owner.id
    );
    db.drop().await;
}

#[tokio::test]
async fn changing_the_password_deactivating_or_demoting_moves_the_epoch() {
    let db = db!();
    let a = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    assert!(
        store::set_password(&db.pool, a.id, "another good passphrase")
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
    assert!(
        !store::set_password(&db.pool, 999_999, "another good passphrase")
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

fn identity(uid: &str, email: Option<&str>, verified: bool) -> owt_auth::oauth::Identity {
    owt_auth::oauth::Identity {
        uid: uid.into(),
        email: email.map(str::to_owned),
        email_verified: verified,
        display_name: Some("Ada Lovelace".into()),
        extra: serde_json::json!({"name": "Ada Lovelace", "email": email}),
    }
}

#[tokio::test]
async fn an_identity_arrives_by_link_then_by_verified_email_then_by_creation() {
    let db = db!();
    let open = identities::Welcome {
        match_verified_email: true,
        create: true,
    };
    // Unknown, with nothing allowed.
    let arrival = identities::arrive(
        &db.pool,
        "google",
        &identity("g1", None, false),
        identities::Welcome::default(),
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);

    // Created, with a username from the name.
    let arrival = identities::arrive(
        &db.pool,
        "google",
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

    // Known on the next arrival.
    let again = identities::arrive(
        &db.pool,
        "google",
        &identity("g1", Some("ada@example.com"), true),
        open,
    )
    .await
    .unwrap();
    assert_eq!(again, identities::Arrival::Known(ada.clone()));

    // Another provider, verified email matching: linked to the same account.
    let arrival = identities::arrive(
        &db.pool,
        "discord",
        &identity("d1", Some("ADA@example.com"), true),
        open,
    )
    .await
    .unwrap();
    assert_eq!(arrival, identities::Arrival::Matched(ada.clone()));
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 2);

    // An unverified matching email creates a second account, without that email.
    let arrival = identities::arrive(
        &db.pool,
        "twitch",
        &identity("t1", Some("ada@example.com"), false),
        open,
    )
    .await
    .unwrap();
    let identities::Arrival::Created(other) = arrival else {
        panic!("{arrival:?}")
    };
    assert_eq!(other.username, "adalovelace2");
    assert_eq!(other.email, "");

    // Linking an identity another account holds is refused.
    let err = identities::link(&db.pool, other.id, "google", "g1", &serde_json::Value::Null)
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::IdentityTaken));

    // Unlinking the only way in is refused; with a password it goes.
    let only = identities::list(&db.pool, other.id).await.unwrap()[0].id;
    let err = identities::unlink(&db.pool, other.id, only)
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::LastWayIn));
    store::set_password(&db.pool, other.id, "a passphrase of her own")
        .await
        .unwrap();
    assert!(identities::unlink(&db.pool, other.id, only).await.unwrap());
    assert!(!identities::unlink(&db.pool, other.id, only).await.unwrap());

    // A deactivated account's identity signs nobody in.
    store::set_active(&db.pool, ada.id, false).await.unwrap();
    let arrival = identities::arrive(&db.pool, "google", &identity("g1", None, false), open)
        .await
        .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);
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
