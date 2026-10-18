//! The crate against a real Postgres (`DATABASE_URL`); skipped without it, except
//! for the nested-router wall test, which asks nothing of the database. Each
//! test takes a schema of its own, so they run in parallel and leave nothing.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use owt_accounts::session::{self, Data};
use owt_accounts::{
    Accounts, Maybe, MaybeWith, New, Signed, SignedWith, Staff, identities, links, store,
};
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
        let db = Self::empty().await?;
        MIGRATOR.run(&db.pool).await.unwrap();
        // As an app does before serving.
        let done = owt_accounts::migrations::complete(&db.pool).await.unwrap();
        assert!(done.validated, "{done:?}");
        Some(db)
    }

    /// A schema of its own with nothing installed.
    async fn empty() -> Option<Self> {
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
    let around_the_library =
        sqlx::query("INSERT INTO accounts (username, username_skeleton) VALUES ('x@y', 'x@y')")
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
        (0..64u8).collect::<Vec<_>>(),
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

/// What a test app reads about the viewer beside the account: a column of its own on
/// `accounts`, and one from a table of its own that a viewer may have no row in.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct Viewer {
    display_name: Option<String>,
    beta: bool,
}

impl store::Extra for Viewer {
    // A trailing comment: the statement closes the lateral on a line of its own.
    const QUERY: &'static str = "SELECT accounts.beta, (SELECT p.display_name
        FROM profiles p WHERE p.account_id = accounts.id) AS display_name -- the profile";
}

async fn add_viewer_tables(db: &Db) {
    sqlx::raw_sql(
        "ALTER TABLE accounts ADD COLUMN beta boolean NOT NULL DEFAULT false;
         CREATE TABLE profiles (
             id bigserial PRIMARY KEY,
             account_id bigint NOT NULL UNIQUE REFERENCES accounts (id),
             display_name text NOT NULL
         );",
    )
    .execute(&db.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn an_extra_is_read_with_the_account_in_its_epoch() {
    let db = db!();
    add_viewer_tables(&db).await;
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let bob = store::create(&db.pool, new("bob", "", None)).await.unwrap();
    sqlx::query("INSERT INTO profiles (account_id, display_name) VALUES ($1, 'Ada L.')")
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET beta = true WHERE id = $1")
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();

    let read =
        |a: &store::Account, epoch| store::by_id_in_epoch_with::<Viewer>(&db.pool, a.id, epoch);
    let (account, viewer) = read(&ada, ada.session_epoch).await.unwrap().unwrap();
    assert_eq!(account, ada);
    let ada_viewer = Viewer {
        display_name: Some("Ada L.".into()),
        beta: true,
    };
    assert_eq!(viewer, ada_viewer);
    // No profile row: the account still loads, without a name.
    let (account, viewer) = read(&bob, bob.session_epoch).await.unwrap().unwrap();
    assert_eq!(account, bob);
    assert_eq!(
        viewer,
        Viewer {
            display_name: None,
            beta: false
        }
    );
    assert_eq!(read(&ada, ada.session_epoch + 1).await.unwrap(), None);
    store::set_active(&db.pool, bob.id, false).await.unwrap();
    assert_eq!(read(&bob, bob.session_epoch + 1).await.unwrap(), None);
    db.drop().await;
}

/// A join whose table has an `id` of its own, selected under another name.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct Joined {
    profile_id: Option<i64>,
    display_name: Option<String>,
}

impl store::Extra for Joined {
    const QUERY: &'static str = "SELECT p.id AS profile_id, p.display_name
        FROM profiles p WHERE p.account_id = accounts.id";
}

/// Every column of the joined row, `id` included: a name the account's row has.
#[derive(Clone, Debug, sqlx::FromRow)]
struct Everything {
    #[allow(dead_code)]
    display_name: Option<String>,
}

impl store::Extra for Everything {
    const QUERY: &'static str = "SELECT p.* FROM profiles p WHERE p.account_id = accounts.id";
}

/// An extra that would hand the account a role `account_roles` does not grant.
#[derive(Clone, Debug, sqlx::FromRow)]
struct Sneaky {
    #[allow(dead_code)]
    roles: Vec<String>,
}

impl store::Extra for Sneaky {
    const QUERY: &'static str = "SELECT ARRAY['editor']::text[] AS roles";
}

/// An extra whose column does not decode as its field.
#[derive(Clone, Debug, sqlx::FromRow)]
struct Mistyped {
    #[allow(dead_code)]
    beta: String,
}

impl store::Extra for Mistyped {
    const QUERY: &'static str = "SELECT accounts.beta";
}

/// An extra that names `accounts` in its own `FROM`: every account's row, not the
/// viewer's.
#[derive(Clone, Debug, sqlx::FromRow)]
struct WholeTable {
    #[allow(dead_code)]
    who: String,
}

impl store::Extra for WholeTable {
    const QUERY: &'static str = "SELECT accounts.beta, accounts.username AS who FROM accounts";
}

fn app_with<X: store::Extra + Clone>(db: &Db, sessions: &Sessions<Data>) -> Router {
    async fn whoami(Maybe(me): Maybe) -> String {
        me.map_or_else(|| "anonymous".to_owned(), |a| a.username)
    }
    Router::new()
        .route("/whoami", get(whoami))
        .route(
            "/private",
            get(|Signed(me): Signed| async move { me.username }),
        )
        .route("/staff", get(|Staff(me): Staff| async move { me.username }))
        .layer(from_fn_with_state(
            Accounts::new(db.pool.clone(), "/login"),
            Accounts::load_with::<Data, X>,
        ))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer))
}

/// A name the account's row has already is refused, never read in place of the
/// account's; so is a column that does not decode. Either fails the load as an
/// outage does, on every walled page.
#[tokio::test]
async fn an_extra_cannot_stand_in_for_the_account_and_a_bad_one_fails_closed() {
    let db = db!();
    add_viewer_tables(&db).await;
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    store::set_staff(&db.pool, ada.id, true).await.unwrap(); // granting keeps the epoch
    sqlx::query("INSERT INTO profiles (account_id, display_name) VALUES ($1, 'Ada L.')")
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();
    let epoch = ada.session_epoch;

    let (account, joined) = store::by_id_in_epoch_with::<Joined>(&db.pool, ada.id, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.id, ada.id);
    assert_eq!(joined.display_name.as_deref(), Some("Ada L."));
    assert!(joined.profile_id.is_some());

    let err = store::by_id_in_epoch_with::<Sneaky>(&db.pool, ada.id, epoch)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("\"roles\", which the row already has"),
        "{err}"
    );
    let err = store::by_id_in_epoch_with::<Everything>(&db.pool, ada.id, epoch)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("\"id\", which the row already has"),
        "{err}"
    );
    store::by_id_in_epoch_with::<Mistyped>(&db.pool, ada.id, epoch)
        .await
        .unwrap_err();
    // With a second account, the whole table is two rows: refused, not the first.
    store::create(&db.pool, new("bob", "", None)).await.unwrap();
    let err = store::by_id_in_epoch_with::<WholeTable>(&db.pool, ada.id, epoch)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("several rows"), "{err}");

    let sessions = sessions();
    let sealed = cookie_for(&sessions, &ada);
    for app in [
        app_with::<Sneaky>(&db, &sessions),
        app_with::<Everything>(&db, &sessions),
        app_with::<Mistyped>(&db, &sessions),
        app_with::<WholeTable>(&db, &sessions),
    ] {
        let client = owt_test::Client::new(app);
        client.set_cookie("s", &sealed);
        assert_eq!(client.get("/private").await.status, 503);
        assert_eq!(client.get("/staff").await.status, 503);
        assert_eq!(client.get("/whoami").await.text(), "anonymous");
    }
    let client = owt_test::Client::new(app_with::<Joined>(&db, &sessions));
    client.set_cookie("s", &sealed);
    assert_eq!(client.get("/staff").await.text(), "ada");
    db.drop().await;
}

#[tokio::test]
async fn the_layer_with_an_extra_hands_it_to_the_handler_and_still_revokes() {
    async fn named(SignedWith(me, viewer): SignedWith<Viewer>) -> String {
        viewer.display_name.unwrap_or(me.username)
    }
    async fn chrome(MaybeWith(me): MaybeWith<Viewer>) -> String {
        me.map_or_else(
            || "anonymous".to_owned(),
            |(_, v)| format!("beta {}", v.beta),
        )
    }
    let db = db!();
    add_viewer_tables(&db).await;
    let sessions = sessions();
    let accounts = Accounts::new(db.pool.clone(), "/login");
    let with = Router::new()
        .route("/named", get(named))
        .route("/chrome", get(chrome))
        .route(
            "/private",
            get(|Signed(me): Signed| async move { me.username }),
        )
        .layer(from_fn_with_state(
            accounts.clone(),
            Accounts::load_with::<Data, Viewer>,
        ))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer));
    let without = Router::new()
        .route("/named", get(named))
        .route("/chrome", get(chrome))
        .layer(from_fn_with_state(accounts, Accounts::load::<Data>))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer));
    let client = owt_test::Client::new(with);
    let plain = owt_test::Client::new(without);

    assert_eq!(client.get("/chrome").await.text(), "anonymous");
    assert_eq!(client.get("/named").await.status, 303);

    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    sqlx::query("INSERT INTO profiles (account_id, display_name) VALUES ($1, 'Ada L.')")
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();
    let sealed = cookie_for(&sessions, &ada);
    client.set_cookie("s", &sealed);
    assert_eq!(client.get("/named").await.text(), "Ada L.");
    assert_eq!(client.get("/chrome").await.text(), "beta false");
    assert_eq!(client.get("/private").await.text(), "ada");

    // Under the plain layer the extra was never read: a wiring mistake, not a wall.
    plain.set_cookie("s", &sealed);
    assert_eq!(plain.get("/named").await.status, 500);
    assert_eq!(plain.get("/chrome").await.text(), "anonymous");

    store::sign_out_everywhere(&db.pool, ada.id).await.unwrap();
    assert_eq!(client.get("/chrome").await.text(), "anonymous");
    let (_, data) = sessions
        .unseal(&client.cookie("s").expect("the cookie was rewritten"))
        .expect("still a session");
    assert_eq!(session::Signed::signature(&data), None);
    assert_eq!(client.get("/named").await.status, 303);
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

/// Arrive as `g1` on `tx`, then keep that account's tokens there.
async fn keep(tx: &mut sqlx::PgConnection, welcome: identities::Welcome) -> store::Account {
    let arrival =
        identities::arrive_in(tx, &oauth::google(), &identity("g1", None, false), welcome)
            .await
            .unwrap();
    let account = arrival.account().unwrap().clone();
    sqlx::query("INSERT INTO provider_tokens VALUES ($1, 'sealed')")
        .bind(account.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    account
}

/// `arrive_in` inside the app's transaction: what the app writes beside it commits
/// with the arrival, or neither does.
#[tokio::test]
async fn an_arrival_can_share_the_apps_transaction() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    sqlx::raw_sql(
        "CREATE TABLE provider_tokens (
            account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            sealed text NOT NULL)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let counts = async || {
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT (SELECT count(*) FROM accounts), (SELECT count(*) FROM account_identities),
                    (SELECT count(*) FROM provider_tokens)",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap()
    };

    // Rolled back: no account, identity or tokens.
    let mut tx = db.pool.begin().await.unwrap();
    keep(&mut tx, open).await;
    tx.rollback().await.unwrap();
    assert_eq!(counts().await, (0, 0, 0));

    // A refusal undoes only its own writes: the transaction goes on.
    let mut tx = db.pool.begin().await.unwrap();
    let ada = keep(&mut tx, open).await;
    let err = identities::arrive_in(&mut tx, &oauth::google(), &identity("", None, false), open)
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::NoSubject));
    tx.commit().await.unwrap();
    assert_eq!(counts().await, (1, 1, 1));
    // And the plain arrival finds it.
    let again = identities::arrive(
        &db.pool,
        &oauth::google(),
        &identity("g1", None, false),
        open,
    )
    .await
    .unwrap();
    assert_eq!(again, identities::Arrival::Known(ada));
    db.drop().await;
}

/// The README's trigger on `accounts.session_epoch`: every way an account's sessions
/// are revoked forgets what the app kept for it, in the same statement, and nothing
/// else does.
#[tokio::test]
async fn a_trigger_on_the_epoch_hears_every_revocation() {
    let db = db!();
    let readme = include_str!("../../../README.md");
    let at = readme
        .find("CREATE TABLE provider_tokens")
        .expect("the README's example");
    let start = readme[..at].rfind("```sql\n").unwrap() + "```sql\n".len();
    let end = at + readme[at..].find("```").unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(&readme[start..end]))
        .execute(&db.pool)
        .await
        .unwrap();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let keep = async || {
        sqlx::query("INSERT INTO provider_tokens VALUES ($1, 'sealed') ON CONFLICT DO NOTHING")
            .bind(ada.id)
            .execute(&db.pool)
            .await
            .unwrap();
    };
    let kept = async || {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM provider_tokens)")
            .fetch_one(&db.pool)
            .await
            .unwrap()
    };

    keep().await;
    store::sign_out_everywhere(&db.pool, ada.id).await.unwrap();
    assert!(!kept().await, "sign_out_everywhere");
    keep().await;
    store::set_password(&db.pool, &ada, "another good passphrase")
        .await
        .unwrap();
    assert!(!kept().await, "set_password");

    // Granting, and setting what is already so, revoke nothing.
    keep().await;
    store::set_staff(&db.pool, ada.id, true).await.unwrap();
    store::set_active(&db.pool, ada.id, true).await.unwrap();
    store::set_email(&db.pool, ada.id, "ada@example.com")
        .await
        .unwrap();
    assert!(kept().await, "nothing was revoked");
    store::set_staff(&db.pool, ada.id, false).await.unwrap();
    assert!(!kept().await, "set_staff");
    keep().await;
    store::set_active(&db.pool, ada.id, false).await.unwrap();
    assert!(!kept().await, "set_active");
    db.drop().await;
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

/// An account an app reaches by a key and subject of its own: found and created with
/// no provider, apart from every provider's subjects, and opened by no password.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one account's ways in, and out")]
async fn a_local_identity_reaches_an_account_no_password_opens() {
    use identities::Arrival;
    use owt_accounts::Refused;
    let db = db!();
    // Found only: nothing yet.
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", None)
        .await
        .unwrap();
    assert_eq!(arrival, Arrival::Unknown);

    // Created under the name given (a number after it when taken), with no email.
    store::create(&db.pool, new("front-desk", "", None))
        .await
        .unwrap();
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("Front-Desk"))
        .await
        .unwrap();
    let Arrival::Created(desk) = arrival else {
        panic!("{arrival:?}")
    };
    assert_eq!(
        (desk.username.as_str(), desk.email.as_str()),
        ("front-desk2", "")
    );
    let again = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("front-desk"))
        .await
        .unwrap();
    assert_eq!(again, Arrival::Known(desk.clone()));

    // The subject is the key's alone: under another key, or at a provider whose key
    // is the same word, it is someone else.
    let other = identities::arrive_as(&db.pool, "system", "desk-1", Some("jobs"))
        .await
        .unwrap();
    assert_ne!(other.account().map(|a| a.id), Some(desk.id));
    let local = identities::arrive_as(&db.pool, "google", "g1", Some("local"))
        .await
        .unwrap();
    let open = identities::Welcome {
        create: true,
        record_email: false,
    };
    let google = oauth::google();
    let stranger = identities::arrive(&db.pool, &google, &identity("g1", None, true), open)
        .await
        .unwrap();
    assert!(matches!(stranger, Arrival::Created(_)), "{stranger:?}");
    assert_ne!(stranger.account(), local.account());
    // And no provider's list or check sees one.
    assert_eq!(identities::list(&db.pool, desk.id).await.unwrap(), []);
    assert_eq!(
        identities::unconfigured(&db.pool, &[&google])
            .await
            .unwrap(),
        []
    );

    // No password opens it, by name or email, and none can be set.
    assert!(!store::has_password(&db.pool, desk.id).await.unwrap());
    let err = store::set_password(&db.pool, &desk, "a good long passphrase")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&Refused::NoPasswordSignIn));
    store::set_email(&db.pool, desk.id, "desk@example.com")
        .await
        .unwrap();
    assert!(
        store::by_email(&db.pool, "desk@example.com")
            .await
            .unwrap()
            .is_none()
    );
    // Written around the library, the hash is refused too.
    let err = sqlx::query("UPDATE accounts SET password_hash = $2 WHERE id = $1")
        .bind(desk.id)
        .bind(
            owt_auth::password::hash("a good long passphrase")
                .await
                .unwrap(),
        )
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(
        err.as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_check_violation),
        "{err}"
    );

    // Turned on, a password can be set and opens it; turned off, it is gone, the
    // sessions with it.
    store::set_password_sign_in(&db.pool, desk.id, true)
        .await
        .unwrap();
    assert!(
        store::set_password(&db.pool, &desk, "a good long passphrase")
            .await
            .unwrap()
    );
    for login in ["front-desk2", "desk@example.com"] {
        assert!(
            store::authenticate(&db.pool, login, "a good long passphrase")
                .await
                .unwrap()
                .is_some(),
            "{login}"
        );
    }
    // A link handed out while passwords opened it (a lost-password one, say).
    let old_link = links::mint(&db.pool, desk.id, Duration::from_secs(900), "lost")
        .await
        .unwrap();
    let before = store::by_id(&db.pool, desk.id).await.unwrap().unwrap();
    store::set_password_sign_in(&db.pool, desk.id, false)
        .await
        .unwrap();
    let after = store::by_id(&db.pool, desk.id).await.unwrap().unwrap();
    assert_eq!(after.session_epoch, before.session_epoch + 1);
    let err = links::redeem(&db.pool, &old_link.token, "203.0.113.9")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&Refused::Link));
    // One an operator mints after still opens it, and turning it off again voids
    // nothing and moves nothing.
    let new_link = links::mint(&db.pool, desk.id, Duration::from_secs(900), "kiosk")
        .await
        .unwrap();
    assert!(!store::has_password(&db.pool, desk.id).await.unwrap());
    for login in ["front-desk2", "desk@example.com"] {
        assert!(
            store::authenticate(&db.pool, login, "a good long passphrase")
                .await
                .unwrap()
                .is_none(),
            "{login}"
        );
    }
    store::set_password_sign_in(&db.pool, desk.id, false)
        .await
        .unwrap();
    let still = store::by_id(&db.pool, desk.id).await.unwrap().unwrap();
    assert_eq!(still.session_epoch, after.session_epoch);
    let opened = links::redeem(&db.pool, &new_link.token, "203.0.113.9")
        .await
        .unwrap();
    assert_eq!(opened.id, desk.id);
    // The local identity still reaches it.
    let back = identities::arrive_as(&db.pool, "kiosk", "desk-1", None)
        .await
        .unwrap();
    assert_eq!(back.account().map(|a| a.id), Some(desk.id));

    // Nobody, and a name the rules refuse.
    for (key, subject) in [("", "desk-1"), ("kiosk", "")] {
        let err = identities::arrive_as(&db.pool, key, subject, Some("desk"))
            .await
            .unwrap_err();
        assert_eq!(err.refused(), Some(&Refused::NoSubject));
    }
    let err = identities::arrive_as(&db.pool, "kiosk", "desk-2", Some("front desk"))
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&Refused::Username));

    // A deactivated account's local identity signs nobody in.
    store::set_active(&db.pool, desk.id, false).await.unwrap();
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("front-desk"))
        .await
        .unwrap();
    assert_eq!(arrival, Arrival::Unknown);
    db.drop().await;
}

/// Two first arrivals with one local identity at once make one account.
#[tokio::test]
async fn racing_local_arrivals_make_one_account() {
    let db = db!();
    let arrive = || identities::arrive_as(&db.pool, "kiosk", "desk-9", Some("desk"));
    let (a, b) = tokio::join!(arrive(), arrive());
    let (a, b) = (a.unwrap(), b.unwrap());
    let (Some(a), Some(b)) = (a.account(), b.account()) else {
        panic!("{a:?} {b:?}")
    };
    assert_eq!(a.id, b.id);
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(accounts, 1);
    db.drop().await;
}

/// A local identity is a way in: a provider linked beside it can be removed. Retired,
/// the pair reaches nothing, and what it opened is closed.
#[tokio::test]
async fn a_local_identity_is_a_way_in_until_it_is_forgotten() {
    let db = db!();
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("desk"))
        .await
        .unwrap();
    let desk = arrival.account().unwrap().clone();
    let google = identities::link(
        &db.pool,
        desk.id,
        &oauth::google(),
        &identity("g1", None, true),
    )
    .await
    .unwrap();
    assert!(
        identities::unlink(&db.pool, desk.id, google.id)
            .await
            .unwrap()
    );

    let link = links::mint(&db.pool, desk.id, Duration::from_secs(900), "setup")
        .await
        .unwrap();
    assert_eq!(
        identities::forget_as(&db.pool, "kiosk", "desk-1")
            .await
            .unwrap(),
        Some(desk.id)
    );
    assert_eq!(
        identities::forget_as(&db.pool, "kiosk", "desk-1")
            .await
            .unwrap(),
        None
    );
    let after = store::by_id(&db.pool, desk.id).await.unwrap().unwrap();
    assert_eq!(after.session_epoch, desk.session_epoch + 1);
    let err = links::redeem(&db.pool, &link.token, "203.0.113.9")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::Link));
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", None)
        .await
        .unwrap();
    assert_eq!(arrival, identities::Arrival::Unknown);
    // Enrolled again, it is a new account: nothing of the old one carries over.
    let again = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("desk"))
        .await
        .unwrap();
    assert_ne!(again.account().map(|a| a.id), Some(desk.id));
    db.drop().await;
}

/// A password sign-in under way when password sign-in is turned off does not stand.
#[tokio::test]
async fn a_sign_in_in_flight_does_not_outlive_password_sign_in() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    // Turned off in a transaction not yet committed: the sign-in reads the row as it
    // was (on, with the hash), checks the password, and its last statement waits on
    // the row's lock.
    let mut off = db.pool.begin().await.unwrap();
    let off_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *off)
        .await
        .unwrap();
    store::set_password_sign_in(&mut *off, ada.id, false)
        .await
        .unwrap();
    let pool = db.pool.clone();
    let signing_in =
        tokio::spawn(
            async move { store::authenticate(&pool, "ada", "correct horse battery").await },
        );
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                            WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(off_pid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        if waiting {
            break;
        }
        assert!(
            !signing_in.is_finished(),
            "the sign-in never reached the lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    off.commit().await.unwrap();
    assert_eq!(signing_in.await.unwrap().unwrap(), None);
    db.drop().await;
}

/// Staff cannot give a password to an account that signs in without one.
#[tokio::test]
async fn the_admin_sets_no_password_where_password_sign_in_is_off() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let arrival = identities::arrive_as(&db.pool, "system", "jobs", Some("jobs"))
        .await
        .unwrap();
    let jobs = arrival.account().unwrap();
    let r = client
        .post_form(&format!("/staff/accounts/{}/password", jobs.id), &[])
        .await;
    assert_eq!(r.status, 409);
    assert!(
        r.text().contains("does not sign in with a password"),
        "{}",
        r.text()
    );
    assert!(!store::has_password(&db.pool, jobs.id).await.unwrap());
    db.drop().await;
}

/// An account with password sign-in off says so, in the list and on its page, which
/// offers no password; staff turn it on, and then a password may be set.
#[tokio::test]
async fn the_admin_shows_and_turns_password_sign_in() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let arrival = identities::arrive_as(&db.pool, "system", "jobs", Some("jobs"))
        .await
        .unwrap();
    let jobs = arrival.account().unwrap().clone();
    let at = format!("/staff/accounts/{}", jobs.id);

    let html = client.get("/staff/accounts?q=jobs").await.text();
    assert!(
        html.contains(r#"<span class="owt-badge owt-badge-quiet">Password sign-in off</span>"#),
        "{html}"
    );
    // The chrome sees the page's own URI, not the nested router's stripped one.
    assert!(html.contains("<p>at: /staff/accounts?q=jobs</p>"), "{html}");
    let html = client.get("/staff/accounts?q=boss").await.text();
    assert!(!html.contains("Password sign-in off"), "{html}");
    let html = client.get(&at).await.text();
    assert!(
        html.contains("Password sign-in off: no password opens it.")
            && !html.contains("Set a generated password")
            && html.contains(r#"name="password_sign_in" value="on""#),
        "{html}"
    );

    let r = client
        .post_form(
            &format!("{at}/password-sign-in"),
            &[("password_sign_in", "maybe")],
        )
        .await;
    assert_eq!(r.status, 422);
    assert_admin_headers(&r);
    let r = client
        .post_form(
            &format!("{at}/password-sign-in"),
            &[("password_sign_in", "on")],
        )
        .await;
    assert_eq!(r.status, 303);
    assert_admin_headers(&r);
    let html = client.get(r.location().unwrap()).await.text();
    assert!(
        html.contains("Password sign-in is on.")
            && html.contains("No password.")
            && html.contains("Set a generated password"),
        "{html}"
    );
    let r = client.post_form(&format!("{at}/password"), &[]).await;
    assert_eq!(r.status, 200);
    let password = secret(&r.text());
    assert!(
        store::authenticate(&db.pool, "jobs", &password)
            .await
            .unwrap()
            .is_some()
    );

    // Off again: the password goes and every session with it.
    let r = client
        .post_form(
            &format!("{at}/password-sign-in"),
            &[("password_sign_in", "off")],
        )
        .await;
    assert_eq!(r.status, 303);
    assert_admin_headers(&r);
    let now = store::by_id(&db.pool, jobs.id).await.unwrap().unwrap();
    assert!(now.session_epoch > jobs.session_epoch);
    assert!(!store::has_password(&db.pool, jobs.id).await.unwrap());
    assert!(
        store::authenticate(&db.pool, "jobs", &password)
            .await
            .unwrap()
            .is_none()
    );

    // Never on yourself: it would end your own sessions and your password.
    let mine = format!("/staff/accounts/{}/password-sign-in", boss.id);
    let r = client
        .post_form(&mine, &[("password_sign_in", "off")])
        .await;
    assert_eq!(r.status, 403);
    assert_admin_headers(&r);
    let html = client
        .get(&format!("/staff/accounts/{}", boss.id))
        .await
        .text();
    assert!(!html.contains("Turn password sign-in off"), "{html}");
    let still = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    assert_eq!(still.session_epoch, boss.session_epoch);
    db.drop().await;
}

/// The account's page lists its local identities; staff retire one of that
/// account's (never another's, never their own), and its sessions end.
#[tokio::test]
async fn the_admin_lists_and_retires_local_identities() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(admin_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let arrive = |key: &'static str, subject: &'static str, name: &'static str| {
        let pool = db.pool.clone();
        async move {
            identities::arrive_as(&pool, key, subject, Some(name))
                .await
                .unwrap()
                .account()
                .unwrap()
                .clone()
        }
    };
    let desk = arrive("kiosk", "desk-1", "desk").await;
    let other = arrive("kiosk", "desk-2", "other").await;
    let at = format!("/staff/accounts/{}", desk.id);
    let forget = format!("{at}/local-identities/forget");

    let html = client.get(&at).await.text();
    assert!(
        html.contains("<h3>Local identities</h3>")
            && html.contains("<td>kiosk</td><td>desk-1</td>")
            && html.contains(&format!(r#"action="{forget}""#))
            && !html.contains("desk-2"),
        "{html}"
    );
    let html = client
        .get(&format!("/staff/accounts/{}", boss.id))
        .await
        .text();
    assert!(!html.contains("Local identities"), "{html}");

    // Another account's pair, through this account's URL: nothing happens.
    let r = client
        .post_form(&forget, &[("key", "kiosk"), ("subject", "desk-2")])
        .await;
    assert_eq!(r.status, 404);
    assert_admin_headers(&r);
    let known = identities::arrive_as(&db.pool, "kiosk", "desk-2", None)
        .await
        .unwrap();
    assert_eq!(known.account().map(|a| a.id), Some(other.id));

    let r = client
        .post_form(&forget, &[("key", "kiosk"), ("subject", "desk-1")])
        .await;
    assert_eq!(r.status, 303);
    assert_admin_headers(&r);
    let html = client.get(r.location().unwrap()).await.text();
    assert!(
        html.contains("Local identity retired") && !html.contains("Local identities"),
        "{html}"
    );
    let gone = identities::arrive_as(&db.pool, "kiosk", "desk-1", None)
        .await
        .unwrap();
    assert!(gone.account().is_none());
    let now = store::by_id(&db.pool, desk.id).await.unwrap().unwrap();
    assert!(now.session_epoch > desk.session_epoch);

    let mine = format!("/staff/accounts/{}/local-identities/forget", boss.id);
    let r = client
        .post_form(&mine, &[("key", "kiosk"), ("subject", "desk-2")])
        .await;
    assert_eq!(r.status, 403);
    assert_admin_headers(&r);
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
            "<title>{}</title><p>me: {}</p><p>at: {}</p>{}",
            escaped(page.title),
            escaped(&page.me.username),
            escaped(&page.request.uri.to_string()),
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

/// Every admin response is kept out of caches and out of frames, whatever it
/// answers: the nest's layers put both headers on it, and a route moved out of the
/// nest would lose them silently.
fn assert_admin_headers(r: &owt_test::Response) {
    assert_eq!(r.header("cache-control"), Some("no-store"), "{}", r.status);
    assert_eq!(r.header("x-frame-options"), Some("DENY"), "{}", r.status);
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
    let cy = legacy_account(&db.pool, "cy_50%").await;
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

/// The app's own search adds its matches to the username and email ones, once each,
/// under the same filters; a failure leaves the built-in matches and says so.
#[tokio::test]
async fn the_admin_also_finds_accounts_by_the_apps_own_columns() {
    let db = db!();
    let sessions = sessions();
    let ada = store::create(&db.pool, new("ada", "ada@example.com", None))
        .await
        .unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    let cy = store::create(&db.pool, new("cy", "", None)).await.unwrap();
    sqlx::query("CREATE TABLE profiles (account_id bigint NOT NULL, nickname text NOT NULL)")
        .execute(&db.pool)
        .await
        .unwrap();
    // Ada's nickname also matches her username; one row has no account.
    sqlx::query("INSERT INTO profiles VALUES ($1, 'Wizard'), ($2, 'ada fan'), (999999, 'wizard')")
        .bind(cy.id)
        .bind(ada.id)
        .execute(&db.pool)
        .await
        .unwrap();
    let pool = db.pool.clone();
    let admin = admin(&db).search("nickname", move |term| {
        let pool = pool.clone();
        async move {
            anyhow::ensure!(term != "boss", "the profiles are down");
            Ok(sqlx::query_scalar(
                "SELECT account_id FROM profiles WHERE strpos(lower(nickname), lower($1)) > 0",
            )
            .bind(term)
            .fetch_all(&pool)
            .await?)
        }
    });
    let client = owt_test::Client::new(app(&db, &sessions, admin.routes()));
    client.set_cookie("s", &cookie_for(&sessions, &boss));

    let list = |q: &str| {
        let client = &client;
        let q = q.to_owned();
        async move {
            let r = client.get(&format!("/staff/accounts?{q}")).await;
            assert_eq!(r.status, 200);
            r.text()
        }
    };
    let found = |html: &str| {
        ["ada", "boss", "cy"]
            .into_iter()
            .filter(|u| html.contains(&format!(">{u}</a>")))
            .collect::<Vec<_>>()
    };
    let html = list("q=").await;
    assert!(
        html.contains(r#"placeholder="Username, email or nickname""#),
        "{html}"
    );
    assert_eq!(found(&html), ["ada", "boss", "cy"]);
    let html = list("q=wiz").await;
    assert_eq!(found(&html), ["cy"], "{html}");
    assert!(
        html.contains("1 account<"),
        "the id with no account: {html}"
    );
    // Found by username and by nickname, listed once.
    let html = list("q=ada").await;
    assert_eq!(found(&html), ["ada"]);
    assert!(html.contains("1 account<"), "{html}");
    let html = list("q=a").await;
    assert_eq!(found(&html), ["ada", "cy"], "{html}");
    // The filters hold for the app's matches too.
    assert_eq!(found(&list("q=wiz&role=staff").await), Vec::<&str>::new());

    let html = list("q=boss").await;
    assert_eq!(found(&html), ["boss"]);
    assert!(
        html.contains(
            "Searching by nickname failed, so these are username and email matches only."
        ),
        "{html}"
    );
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
#[expect(clippy::too_many_lines, reason = "every way in and out, in order")]
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
    // The notice speaks to staff about this account, never as to its owner, and
    // the refusal's own sentence (shown to both) names the account, not "yours".
    let html = client.get(r.location().unwrap()).await.text();
    assert!(
        html.contains("That is this account&#x27;s only way in")
            || html.contains("That is this account&#39;s only way in"),
        "{html}"
    );
    assert!(!html.contains("Your account"), "{html}");
    assert!(
        !owt_accounts::Refused::LastWayIn
            .to_string()
            .contains("Your account")
    );

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
        format!("{at}/password-sign-in"),
        format!("{at}/local-identities/forget"),
    ];
    let fields = [
        ("username", "x"),
        ("email", ""),
        ("active", "on"),
        ("staff", "on"),
        ("password_sign_in", "off"),
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
    // Today's rules refuse it; an older row may have it.
    assert!(
        store::create(&db.pool, new("</title><svg/onload=alert(1)>", "", None))
            .await
            .is_err()
    );
    let evil = legacy_account(&db.pool, "</title><svg/onload=alert(1)>").await;
    for path in [
        "/staff/accounts".to_owned(),
        format!("/staff/accounts/{}", evil.id),
    ] {
        let html = client.get(&path).await.text();
        assert!(!html.contains("<svg"), "{path}: {html}");
    }
    db.drop().await;
}

/// An app's own markup for the admin, from the view models: a design system with
/// none of the `owt-*` classes.
mod plain {
    use askama::Template;
    use axum::http::request::Parts;
    use owt_accounts::admin::{AccountView, Body, ListView, NewView, Views};
    use owt_web::ui::Kind;

    #[derive(Template)]
    #[template(
        source = r#"<ul class="pf-list" data-total="{{ v.total }}" data-filter="{{ v.filter }}">
{% for r in v.rows %}<li data-pw="{{ r.password_sign_in }}"><a href="{{ r.href }}">{{ r.username }}</a>{% for b in r.badges %} [{{ b.text }}]{% endfor %}</li>
{% endfor %}</ul>{% for i in v.pagination.items() %}{% match i.kind %}
{% when Kind::Previous %}<a class="pf-prev" href="{{ i.href }}">Previous</a>
{% when Kind::Next %}<a class="pf-next" href="{{ i.href }}">Next</a>
{% when Kind::Current %}<b class="pf-current">{{ i.label }}</b>
{% when Kind::Gap %}…
{% when _ %}<a class="pf-page" href="{{ i.href }}">{{ i.label }}</a>
{% endmatch %}{% endfor %}
<a href="{{ v.new_account }}">add</a>"#,
        ext = "html"
    )]
    struct List<'a, 'b> {
        v: &'a ListView<'b>,
    }

    #[derive(Template)]
    #[template(
        source = r#"<form class="pf-form" action="{{ v.action }}" method="post">{% if let Some(e) = v.error %}<p class="pf-error">{{ e }}</p>{% endif %}<input name="username" value="{{ v.username }}"></form>"#,
        ext = "html"
    )]
    struct New<'a, 'b> {
        v: &'a NewView<'b>,
    }

    #[derive(Template)]
    #[template(
        source = r#"<h1 class="pf-title">{{ v.account.username }}</h1>{% if let Some(n) = v.notice %}<p class="pf-notice" data-error="{{ n.is_error() }}">{{ n.text }}</p>{% endif %}{% if let Some(s) = v.secret %}<output class="pf-secret">{{ s.value }}</output>{% endif %}
<form action="{{ v.save }}" method="post"></form><form action="{{ v.set_password }}" method="post"></form>{% if let Some(l) = v.issue_link %}<form action="{{ l }}" method="post">{{ v.link_lifetime }}</form>{% endif %}<form action="{{ v.sign_out }}" method="post"></form>
{% for c in v.connections %}<form action="{{ c.unlink }}" method="post">{{ c.provider }}</form>{% endfor %}
<p class="pf-pw" data-on="{{ v.password_sign_in }}"></p>{% if v.password_sign_in %}<form action="{{ v.set_password_sign_in }}" method="post"><input name="password_sign_in" value="off"></form>{% endif %}
{% for l in v.local_identities %}<form class="pf-local" action="{{ l.forget }}" method="post"><input name="key" value="{{ l.key }}"><input name="subject" value="{{ l.subject }}"></form>{% endfor %}"#,
        ext = "html"
    )]
    struct Account<'a, 'b> {
        v: &'a AccountView<'b>,
    }

    pub struct Plain;

    impl Views for Plain {
        fn list(&self, _: &Parts, view: &ListView<'_>) -> owt_web::Result<Body> {
            Body::render(&List { v: view })
        }
        fn new_account(&self, _: &Parts, view: &NewView<'_>) -> owt_web::Result<Body> {
            Body::render(&New { v: view })
        }
        fn account(&self, _: &Parts, view: &AccountView<'_>) -> owt_web::Result<Body> {
            Body::render(&Account { v: view })
        }
    }

    /// An app whose account page always fails.
    pub struct Broken;

    impl Views for Broken {
        fn account(&self, _: &Parts, _: &AccountView<'_>) -> owt_web::Result<Body> {
            Err(owt_web::Error::Internal(anyhow::anyhow!(
                "the template broke"
            )))
        }
    }
}

/// The test app with the admin drawn by `views`.
fn plain_app_with(
    db: &Db,
    sessions: &Sessions<Data>,
    views: impl owt_accounts::admin::Views,
) -> Router {
    let admin = admin(db)
        .views(views)
        .sign_in_links(Duration::from_secs(3_600), |token| {
            format!("https://app.example/login/link/{token}")
        });
    app(db, sessions, admin.routes())
}

/// The test app with the admin drawn by [`plain::Plain`].
fn plain_app(db: &Db, sessions: &Sessions<Data>) -> Router {
    plain_app_with(db, sessions, plain::Plain)
}

/// An app's list pages with the view model's pager: each kind of item drawn its
/// own way, the filter kept.
#[tokio::test]
async fn an_apps_templates_page_the_list() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(plain_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    sqlx::query(
        "WITH made AS (
            INSERT INTO accounts (username, username_skeleton)
            SELECT 'ed' || lpad(n::text, 3, '0'), 'ed' || lpad(n::text, 3, '0')
            FROM generate_series(1, 55) n
            RETURNING id)
         INSERT INTO account_roles (account_id, role) SELECT id, 'editor' FROM made",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let first = client.get("/staff/accounts?role=editor").await.text();
    assert!(
        first.contains(r#"data-total="55""#)
            && first.contains(r#"<b class="pf-current">1</b>"#)
            && first.contains(
                r#"<a class="pf-page" href="/staff/accounts?role=editor&#38;page=2">2</a>"#
            )
            && first.contains(
                r#"<a class="pf-next" href="/staff/accounts?role=editor&#38;page=2">Next</a>"#
            )
            && !first.contains("pf-prev")
            && !first.contains(r#"href="""#),
        "{first}"
    );
    let second = client
        .get("/staff/accounts?role=editor&page=2")
        .await
        .text();
    assert!(
        second.contains(r#"<a class="pf-prev" href="/staff/accounts?role=editor">Previous</a>"#)
            && second.contains(r#"<b class="pf-current">2</b>"#)
            && second.contains(">ed055</a>")
            && !second.contains("pf-next"),
        "{second}"
    );
    db.drop().await;
}

/// A password or link is made before its page is drawn: when the app's page fails,
/// the admin's own shows it rather than lose it to a 500.
#[tokio::test]
async fn a_secret_survives_the_apps_page_failing() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(plain_app_with(&db, &sessions, plain::Broken));
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let at = format!("/staff/accounts/{}", ada.id);
    assert_eq!(client.get(&at).await.status, 500);

    for action in ["password", "link"] {
        let r = client.post_form(&format!("{at}/{action}"), &[]).await;
        assert_eq!(r.status, 200, "{action}");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.header("x-frame-options"), Some("DENY"));
        let value = secret(&r.text());
        if action == "password" {
            assert!(
                store::authenticate(&db.pool, "ada", &value)
                    .await
                    .unwrap()
                    .is_some()
            );
        } else {
            assert!(
                value.starts_with("https://app.example/login/link/"),
                "{value}"
            );
        }
    }
    db.drop().await;
}

/// An app draws every admin page from the view models with its own templates.
#[tokio::test]
async fn an_app_draws_the_admin_with_its_own_templates() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(plain_app(&db, &sessions));
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    owt_accounts::roles::grant(&db.pool, ada.id, &EDITOR, None)
        .await
        .unwrap();
    let linked = identities::link(
        &db.pool,
        ada.id,
        &owt_auth::oauth::google(),
        &identity("g1", None, false),
    )
    .await
    .unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));

    let r = client.get("/staff/accounts?role=editor").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    let html = r.text();
    assert!(!html.contains("owt-"), "{html}");
    assert!(
        html.contains(r#"data-total="1" data-filter="editor""#)
            && html.contains(&format!(
                r#"<a href="/staff/accounts/{}">ada</a> [Editor]"#,
                ada.id
            ))
            && html.contains(r#"<a href="/staff/accounts/new">add</a>"#),
        "{html}"
    );

    let html = client.get("/staff/accounts/new").await.text();
    assert!(
        html.contains(r#"<form class="pf-form" action="/staff/accounts" method="post">"#),
        "{html}"
    );
    let r = client
        .post_form("/staff/accounts", &[("username", "ada"), ("email", "")])
        .await;
    assert_eq!(r.status, 422);
    let html = r.text();
    assert!(
        html.contains(r#"<p class="pf-error">There is already an account named"#)
            && html.contains(r#"value="ada""#)
            && !html.contains("owt-"),
        "{html}"
    );

    let at = format!("/staff/accounts/{}", ada.id);
    let html = client.get(&at).await.text();
    for action in [
        at.clone(),
        format!("{at}/password"),
        format!("{at}/link"),
        format!("{at}/sign-out"),
        format!("{at}/identities/{}/unlink", linked.id),
    ] {
        assert!(
            html.contains(&format!(r#"action="{action}""#)),
            "{action}: {html}"
        );
    }
    assert!(html.contains(">1 hour</form>"), "{html}");

    let r = client.post_form(&format!("{at}/password"), &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    let html = r.text();
    assert!(!html.contains("owt-"), "{html}");
    let password = html
        .split(r#"<output class="pf-secret">"#)
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .expect("the password, once");
    assert!(
        store::authenticate(&db.pool, "ada", password)
            .await
            .unwrap()
            .is_some()
    );
    db.drop().await;
}

/// An app's templates get password sign-in and the local identities from the view
/// models, with the URLs to change them, and their forms work.
#[tokio::test]
async fn an_apps_templates_show_password_sign_in_and_local_identities() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(plain_app(&db, &sessions));
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let arrival = identities::arrive_as(&db.pool, "kiosk", "desk-1", Some("desk"))
        .await
        .unwrap();
    let desk = arrival.account().unwrap().clone();
    let at = format!("/staff/accounts/{}", desk.id);

    let html = client.get("/staff/accounts").await.text();
    assert!(
        html.contains(&format!(
            r#"<li data-pw="false"><a href="{at}">desk</a> [User] [Password sign-in off]</li>"#
        )) && html.contains(r#"<li data-pw="true"><a href"#),
        "{html}"
    );
    let html = client.get(&at).await.text();
    assert!(
        html.contains(r#"<p class="pf-pw" data-on="false">"#)
            && html.contains(&format!(
                r#"<form class="pf-local" action="{at}/local-identities/forget" method="post"><input name="key" value="kiosk"><input name="subject" value="desk-1"></form>"#
            ))
            && !html.contains("owt-"),
        "{html}"
    );
    let r = client
        .post_form(
            &format!("{at}/local-identities/forget"),
            &[("key", "kiosk"), ("subject", "desk-1")],
        )
        .await;
    assert_eq!(r.status, 303);
    let html = client.get(&at).await.text();
    assert!(!html.contains("pf-local"), "{html}");
    db.drop().await;
}

/// The app's markup is not what guards: under its own templates the admin is still
/// for staff alone, a staff member's own access cannot be posted away, and another
/// site cannot post at all.
#[tokio::test]
async fn the_admin_checks_hold_under_an_apps_templates() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(plain_app(&db, &sessions));
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let boss = store::create(&db.pool, new("boss", "", None))
        .await
        .unwrap();
    store::set_staff(&db.pool, boss.id, true).await.unwrap();
    let boss = store::by_id(&db.pool, boss.id).await.unwrap().unwrap();
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    assert_eq!(client.get("/staff/accounts").await.status, 403);

    client.set_cookie("s", &cookie_for(&sessions, &boss));
    let at = format!("/staff/accounts/{}", ada.id);
    let mine = format!("/staff/accounts/{}", boss.id);
    let r = client
        .post_form(&mine, &[("email", ""), ("active", "on")])
        .await;
    assert_eq!(r.status, 403);
    assert!(r.text().contains(r#"data-error="true""#));
    let r = client
        .send(
            axum::http::Request::post(format!("{at}/sign-out"))
                .header("sec-fetch-site", "same-site")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 403);
    assert!(
        store::by_id(&db.pool, boss.id)
            .await
            .unwrap()
            .unwrap()
            .is_staff
    );
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
            INSERT INTO accounts (username, username_skeleton)
            SELECT 'ed' || lpad(n::text, 3, '0'), 'ed' || lpad(n::text, 3, '0')
            FROM generate_series(1, 55) n
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

/// A provider on this machine: a token endpoint and a user-info endpoint that
/// answers with whatever subject the test sets.
async fn fake_provider(sub: Arc<std::sync::Mutex<String>>) -> String {
    let fake = Router::new()
        .route(
            "/token",
            post(|| async { serde_json::json!({"access_token": "t"}).to_string() }),
        )
        .route(
            "/userinfo",
            get(move || {
                let sub = sub.lock().unwrap().clone();
                async move {
                    serde_json::json!({
                        "sub": sub, "name": "Ada Lovelace",
                        "email": "ada@example.com", "email_verified": true
                    })
                    .to_string()
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, fake).await });
    base
}

fn social_sessions() -> Sessions<owt_accounts::social::Data> {
    let key = owt_web::session::key_from_base64(&base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        (64..128u8).collect::<Vec<_>>(),
    ))
    .unwrap();
    Sessions::new(key, "s", Duration::from_secs(3600), false)
}

fn social_app(
    db: &Db,
    sessions: &Sessions<owt_accounts::social::Data>,
    social: &owt_accounts::social::SocialSignIn,
) -> Router {
    async fn whoami(Maybe(account): Maybe) -> String {
        account.map_or_else(|| "anonymous".to_owned(), |a| a.username)
    }
    let accounts = Accounts::new(db.pool.clone(), "/login");
    Router::new()
        .merge(social.routes::<owt_accounts::social::Data, ()>())
        .route("/whoami", get(whoami))
        .layer(from_fn_with_state(
            accounts,
            Accounts::load::<owt_accounts::social::Data>,
        ))
        .layer(axum::middleware::from_fn_with_state(
            sessions.clone(),
            Sessions::layer,
        ))
}

/// The `state` a start redirect sent to the provider.
fn sent_state(location: &str) -> String {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}

/// Sign-in with Google pointed at a fake provider answering with subject `sub`.
async fn social_fixture(
    db: &Db,
    sub: Arc<std::sync::Mutex<String>>,
    welcome: identities::Welcome,
) -> (owt_accounts::social::SocialSignIn, owt_test::Client) {
    social_fixture_with(db, sub, welcome, |social| social).await
}

/// [`social_fixture`], configured further by `more` before its routes are made.
async fn social_fixture_with(
    db: &Db,
    sub: Arc<std::sync::Mutex<String>>,
    welcome: identities::Welcome,
    more: impl FnOnce(owt_accounts::social::SocialSignIn) -> owt_accounts::social::SocialSignIn,
) -> (owt_accounts::social::SocialSignIn, owt_test::Client) {
    use owt_accounts::social::{self, Providers, SocialSignIn};
    use owt_auth::oauth;
    let base = fake_provider(sub).await;
    let providers = Providers::new("http://localhost:8000", social::DEFAULT_CALLBACK)
        .unwrap()
        .with(
            oauth::Provider {
                token_url: format!("{base}/token"),
                userinfo_url: format!("{base}/userinfo"),
                ..oauth::google()
            },
            "cid",
            "secret",
        )
        .unwrap();
    assert_eq!(
        providers.get("google").unwrap().redirect_uri,
        "http://localhost:8000/auth/google/callback"
    );
    let social = SocialSignIn::new(
        db.pool.clone(),
        oauth::http_client().unwrap(),
        providers,
        welcome,
    )
    .after_sign_in("/home");
    let social = more(social);
    let client = owt_test::Client::new(social_app(db, &social_sessions(), &social));
    (social, client)
}

/// A second provider (Discord) on the same fake, for mix-up tests.
async fn two_provider_fixture(db: &Db, sub: Arc<std::sync::Mutex<String>>) -> owt_test::Client {
    use owt_accounts::social::{self, Providers, SocialSignIn};
    use owt_auth::oauth;
    let base = fake_provider(sub).await;
    let at = |p: oauth::Provider| oauth::Provider {
        token_url: format!("{base}/token"),
        userinfo_url: format!("{base}/userinfo"),
        ..p
    };
    let providers = Providers::new("http://localhost:8000", social::DEFAULT_CALLBACK)
        .unwrap()
        .with(at(oauth::google()), "cid", "secret")
        .unwrap()
        .with(at(oauth::discord()), "did", "secret")
        .unwrap();
    let social = SocialSignIn::new(
        db.pool.clone(),
        oauth::http_client().unwrap(),
        providers,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    );
    owt_test::Client::new(social_app(db, &social_sessions(), &social))
}

/// Start at the provider and come back with the state it was sent.
async fn round_trip(client: &owt_test::Client, fields: &[(&str, &str)]) -> owt_test::Response {
    let r = client.post_form("/auth/google/start", fields).await;
    assert_eq!(r.status, 303);
    let state = sent_state(r.location().unwrap());
    client
        .get(&format!("/auth/google/callback?state={state}&code=abc"))
        .await
}

#[tokio::test]
async fn the_app_hears_of_each_arrival_before_it_signs_in() {
    use owt_accounts::social::{Arrived, Social};
    /// Who arrived, whether created, with which provider and access token.
    type Heard = Arc<std::sync::Mutex<Vec<(String, bool, String, String)>>>;
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let heard: Heard = Arc::default();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (log, no) = (heard.clone(), refuse.clone());
    let (_, client) = social_fixture_with(
        &db,
        sub.clone(),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
        move |social| {
            social.on_arrival(move |arrived: Arrived| {
                let (log, no) = (log.clone(), no.clone());
                async move {
                    log.lock().unwrap().push((
                        arrived.account.username,
                        arrived.created,
                        arrived.provider,
                        arrived.tokens.access,
                    ));
                    if no.load(std::sync::atomic::Ordering::SeqCst) {
                        anyhow::bail!("the app's set-up failed");
                    }
                    Ok(())
                }
            })
        },
    )
    .await;

    // A first sign-in creates the account; the next finds it.
    assert_eq!(round_trip(&client, &[]).await.location(), Some("/home"));
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");
    round_trip(&client, &[]).await;
    assert_eq!(
        *heard.lock().unwrap(),
        [
            ("adalovelace".into(), true, "google".into(), "t".into()),
            ("adalovelace".into(), false, "google".into(), "t".into()),
        ]
    );

    // An error signs nobody in, and lands with a message rather than a 500, so the
    // pending sign-in it took stays used up.
    refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    client.clear_cookies();
    let r = round_trip(&client, &[]).await;
    assert_eq!(r.location(), Some("/login?social=failed"));
    let (_, data) = social_sessions()
        .unseal(&client.cookie("s").expect("a session cookie"))
        .expect("it opens");
    assert!(data.started().is_none(), "the pending sign-in survived");
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    assert_eq!(heard.lock().unwrap().len(), 3);
}

/// A connect hands the app the provider's tokens; the app's error lands on the
/// connections page and leaves the identity linked.
#[tokio::test]
async fn the_app_hears_of_each_connect_with_its_tokens() {
    use owt_accounts::social::Connected;
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let heard: Arc<std::sync::Mutex<Vec<(String, String, String)>>> = Arc::default();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (log, no) = (heard.clone(), refuse.clone());
    let (_, client) = social_fixture_with(
        &db,
        sub.clone(),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
        move |social| {
            social.on_connect(move |connected: Connected| {
                let (log, no) = (log.clone(), no.clone());
                async move {
                    log.lock().unwrap().push((
                        connected.account.username,
                        connected.provider,
                        connected.tokens.access,
                    ));
                    if no.load(std::sync::atomic::Ordering::SeqCst) {
                        anyhow::bail!("the app could not keep the tokens");
                    }
                    Ok(())
                }
            })
        },
    )
    .await;
    // A sign-in is not a connect.
    round_trip(&client, &[]).await;
    assert!(heard.lock().unwrap().is_empty());

    *sub.lock().unwrap() = "g2".into();
    let r = round_trip(&client, &[("connect", "1")]).await;
    assert_eq!(r.location(), Some("/account/connections?social=connected"));
    assert_eq!(
        *heard.lock().unwrap(),
        [("adalovelace".into(), "google".into(), "t".into())]
    );

    refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    *sub.lock().unwrap() = "g3".into();
    let r = round_trip(&client, &[("connect", "1")]).await;
    assert_eq!(r.location(), Some("/account/connections?social=failed"));
    let ada = store::by_username(&db.pool, "adalovelace")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 3);
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");
    db.drop().await;
}

/// A database failure after the callback took the pending sign-in lands with a
/// message rather than a 500: a 5xx seals no session change, and the pending sign-in
/// would survive it.
#[tokio::test]
async fn a_database_failure_in_the_callback_still_uses_up_the_pending_sign_in() {
    use owt_accounts::social::Social;
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (_, client) = social_fixture(
        &db,
        sub.clone(),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;
    round_trip(&client, &[]).await;
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");
    // From here every write of an identity fails, as a database that went away would.
    sqlx::raw_sql(
        "CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'the database is unavailable'; END $$;
         CREATE TRIGGER refuse BEFORE INSERT OR UPDATE ON account_identities
            FOR EACH ROW EXECUTE FUNCTION refuse();",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let pending = |client: &owt_test::Client| {
        let (_, data) = social_sessions()
            .unseal(&client.cookie("s").expect("a session cookie"))
            .expect("it opens");
        data.started().is_some()
    };

    // A connect lands on the connections page, still signed in as before.
    *sub.lock().unwrap() = "g2".into();
    let r = round_trip(&client, &[("connect", "1")]).await;
    assert_eq!(r.location(), Some("/account/connections?social=failed"));
    assert!(!pending(&client), "the pending connect survived");
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");

    // A sign-in signs nobody in.
    *sub.lock().unwrap() = "g1".into();
    client.clear_cookies();
    let r = round_trip(&client, &[]).await;
    assert_eq!(r.location(), Some("/login?social=failed"));
    assert!(!pending(&client), "the pending sign-in survived");
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    db.drop().await;
}

#[tokio::test]
async fn a_provider_sign_in_round_trips_through_the_routes() {
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (social, client) = social_fixture(
        &db,
        sub,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;

    // The sign-in page's buttons.
    let buttons = social.buttons("/games").to_string();
    assert!(
        buttons.contains(r#"action="/auth/google/start""#) && buttons.contains(r#"value="/games""#),
        "{buttons}"
    );

    // Start, then the provider sends the browser back with the state and a code.
    let r = client
        .post_form("/auth/google/start", &[("next", "/games")])
        .await;
    let location = r.location().unwrap().to_owned();
    assert!(
        location.starts_with("https://accounts.google.com/"),
        "{location}"
    );
    let callback = format!(
        "/auth/google/callback?state={}&code=abc",
        sent_state(&location)
    );
    let r = client.get(&callback).await;
    assert_eq!(r.location(), Some("/games"), "{}", r.text());
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");

    // The pending sign-in was used up: a replay is refused.
    let r = client.get(&callback).await;
    assert_eq!(r.location(), Some("/login?social=expired"));

    // A state that is not the one sent, a cancellation, a `next` off this site.
    client.post_form("/auth/google/start", &[]).await;
    let r = client
        .get("/auth/google/callback?state=forged&code=abc")
        .await;
    assert_eq!(r.location(), Some("/login?social=expired"));
    client.post_form("/auth/google/start", &[]).await;
    let r = client
        .get("/auth/google/callback?error=access_denied")
        .await;
    assert_eq!(r.location(), Some("/login?social=cancelled"));
    let r = round_trip(&client, &[("next", "https://evil.example/")]).await;
    assert_eq!(r.location(), Some("/home"));

    // Unknown providers are not routes.
    assert_eq!(client.post_form("/auth/nope/start", &[]).await.status, 404);
    assert_eq!(
        client
            .get("/auth/nope/callback?state=x&code=y")
            .await
            .status,
        404
    );
    db.drop().await;
}

/// The session cookie with its pending sign-in rewritten by `edit` (the id too).
fn with_pending(
    client: &owt_test::Client,
    edit: impl FnOnce(&mut String, &mut owt_accounts::social::Started),
) {
    let sessions = social_sessions();
    let (mut id, mut data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    edit(&mut id, data.started.as_mut().unwrap());
    client.set_cookie("s", &sessions.seal(&id, &data));
}

/// A pending sign-in is good for `PENDING_FOR`, and only in the session it began in:
/// a copy of the cookie kept past it, or a sign-in begun before someone else signed
/// in on the same browser, finishes nothing.
#[tokio::test]
async fn a_pending_sign_in_lapses_and_stays_in_its_session() {
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (_, client) = social_fixture(
        &db,
        sub,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;
    let begin = || async {
        let r = client.post_form("/auth/google/start", &[]).await;
        sent_state(r.location().unwrap())
    };
    let finish = |state: String| {
        let client = &client;
        async move {
            client
                .get(&format!("/auth/google/callback?state={state}&code=abc"))
                .await
        }
    };
    let state = begin().await;
    with_pending(&client, |_, started| {
        started.at -= owt_accounts::social::PENDING_FOR.as_secs() + 1;
    });
    assert_eq!(
        finish(state).await.location(),
        Some("/login?social=expired")
    );

    // Begun, then the session was replaced (a password sign-in cycles the id).
    let state = begin().await;
    with_pending(&client, |id, _| *id = "another-session-id".into());
    assert_eq!(
        finish(state).await.location(),
        Some("/login?social=expired")
    );

    // A start time from the future (past the minute of skew allowed), and a pending
    // sign-in bound to no session, finish nothing either.
    let state = begin().await;
    with_pending(&client, |_, started| started.at += 3600);
    assert_eq!(
        finish(state).await.location(),
        Some("/login?social=expired")
    );
    let state = begin().await;
    with_pending(&client, |_, started| started.session.clear());
    assert_eq!(
        finish(state).await.location(),
        Some("/login?social=expired")
    );

    // Untouched, it still works.
    let state = begin().await;
    assert_eq!(finish(state).await.location(), Some("/home"));
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");
    db.drop().await;
}

/// A connect needs a recent sign-in when it comes back, not only when it starts.
#[tokio::test]
async fn a_connect_needs_a_recent_sign_in_at_the_callback_too() {
    use owt_accounts::social::{self, Providers, SocialSignIn};
    use owt_auth::oauth;
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let base = fake_provider(sub.clone()).await;
    let providers = Providers::new("http://localhost:8000", social::DEFAULT_CALLBACK)
        .unwrap()
        .with(
            oauth::Provider {
                token_url: format!("{base}/token"),
                userinfo_url: format!("{base}/userinfo"),
                ..oauth::google()
            },
            "cid",
            "secret",
        )
        .unwrap();
    let social = SocialSignIn::new(
        db.pool.clone(),
        oauth::http_client().unwrap(),
        providers,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .connect_within(Duration::from_secs(1));
    let client = owt_test::Client::new(social_app(&db, &social_sessions(), &social));
    round_trip(&client, &[]).await;
    *sub.lock().unwrap() = "g2".into();
    let r = client
        .post_form("/auth/google/start", &[("connect", "1")])
        .await;
    let state = sent_state(r.location().unwrap());
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let r = client
        .get(&format!("/auth/google/callback?state={state}&code=abc"))
        .await;
    assert_eq!(r.location(), Some("/login?social=sign-in-again"));
    let ada = store::by_username(&db.pool, "adalovelace")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn a_provider_is_connected_and_removed_from_settings() {
    use owt_auth::oauth;
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (social, client) = social_fixture(
        &db,
        sub.clone(),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;
    round_trip(&client, &[]).await;
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");

    // Connecting while signed in adds a second identity of the same provider.
    *sub.lock().unwrap() = "g2".into();
    let r = round_trip(&client, &[("connect", "1")]).await;
    assert_eq!(r.location(), Some("/account/connections?social=connected"));
    let ada = store::by_username(&db.pool, "adalovelace")
        .await
        .unwrap()
        .unwrap();
    let linked = identities::list(&db.pool, ada.id).await.unwrap();
    assert_eq!(linked.len(), 2);
    let page = social.connections(ada.id).await.unwrap().to_string();
    assert!(
        page.contains("<td>Google</td>") && page.contains("/auth/connections/"),
        "{page}"
    );

    // Removing one goes; removing the last way in does not.
    let remove = |id: i64| format!("/auth/connections/{id}/remove");
    let r = client.post_form(&remove(linked[1].id), &[]).await;
    assert_eq!(r.location(), Some("/account/connections?social=removed"));
    let r = client.post_form(&remove(linked[0].id), &[]).await;
    assert_eq!(
        r.location(),
        Some("/account/connections?social=last-way-in")
    );
    // Someone else's connection is not found.
    let other = store::create(&db.pool, new("other", "", None))
        .await
        .unwrap();
    let theirs = identities::link(
        &db.pool,
        other.id,
        &oauth::discord(),
        &identity("d1", None, false),
    )
    .await
    .unwrap();
    assert_eq!(client.post_form(&remove(theirs.id), &[]).await.status, 404);

    // Anonymous: connecting needs a sign-in first, and Remove is walled.
    client.clear_cookies();
    let r = client
        .post_form("/auth/google/start", &[("connect", "1")])
        .await;
    assert_eq!(r.location(), Some("/login?social=sign-in-first"));
    assert_eq!(
        client.post_form(&remove(linked[0].id), &[]).await.status,
        303
    );
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 1);
    db.drop().await;
}

/// With self-signup off, a provider identity linked to nothing signs nobody in,
/// even with a verified email an account here has.
#[tokio::test]
async fn without_self_signup_an_unknown_identity_is_turned_away() {
    let db = db!();
    store::create(&db.pool, new("ada", "ada@example.com", None))
        .await
        .unwrap();
    let sub = Arc::new(std::sync::Mutex::new("g9".to_owned()));
    let (_, client) = social_fixture(&db, sub, identities::Welcome::default()).await;
    let r = round_trip(&client, &[]).await;
    assert_eq!(r.location(), Some("/login?social=unknown"));
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    db.drop().await;
}

/// The session id changes at a provider sign-in (no fixation); a failed callback
/// uses the pending sign-in up too; a callback at another provider's route is
/// refused; an overlong `next` is dropped rather than losing the sign-in.
#[tokio::test]
async fn a_provider_sign_in_survives_nothing_it_should_not() {
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let client = two_provider_fixture(&db, sub).await;
    let sessions = social_sessions();
    let id_of = |client: &owt_test::Client| {
        sessions
            .unseal(&client.cookie("s").expect("a session cookie"))
            .expect("it opens")
            .0
    };

    // Fixation: the anonymous session's id is not the signed-in one's.
    let r = client.post_form("/auth/google/start", &[]).await;
    let before = id_of(&client);
    let state = sent_state(r.location().unwrap());
    client
        .get(&format!("/auth/google/callback?state={state}&code=abc"))
        .await;
    assert_eq!(client.get("/whoami").await.text(), "adalovelace");
    assert_ne!(id_of(&client), before);

    // A forged state uses the pending sign-in up: the real one cannot follow.
    client.clear_cookies();
    let r = client.post_form("/auth/google/start", &[]).await;
    let state = sent_state(r.location().unwrap());
    let r = client
        .get("/auth/google/callback?state=forged&code=abc")
        .await;
    assert_eq!(r.location(), Some("/login?social=expired"));
    let r = client
        .get(&format!("/auth/google/callback?state={state}&code=abc"))
        .await;
    assert_eq!(r.location(), Some("/login?social=expired"));
    assert_eq!(client.get("/whoami").await.text(), "anonymous");

    // Mix-up: begun with Google, returned at Discord's callback with its state.
    let r = client.post_form("/auth/google/start", &[]).await;
    let state = sent_state(r.location().unwrap());
    let r = client
        .get(&format!("/auth/discord/callback?state={state}&code=abc"))
        .await;
    assert_eq!(r.location(), Some("/login?social=expired"));
    assert_eq!(client.get("/whoami").await.text(), "anonymous");

    // `next`: kept when short and local, dropped when long or elsewhere.
    for (next, lands) in [
        ("/games?x=1".to_owned(), "/games?x=1"),
        (format!("/{}", "a".repeat(2000)), "/"),
        ("//evil.example/".to_owned(), "/"),
        ("/\\evil.example/".to_owned(), "/"),
        ("https://evil.example/".to_owned(), "/"),
    ] {
        client.clear_cookies();
        let r = client
            .post_form("/auth/google/start", &[("next", &next)])
            .await;
        assert!(
            client.cookie("s").unwrap().len() < 3000,
            "the cookie grew with next"
        );
        let state = sent_state(r.location().unwrap());
        let r = client
            .get(&format!("/auth/google/callback?state={state}&code=abc"))
            .await;
        assert_eq!(r.location(), Some(lands), "{next}");
    }
    db.drop().await;
}

/// A connect: for the account that began it only, after a recent sign-in, back on
/// the connections page whatever happens.
#[tokio::test]
async fn a_connect_belongs_to_the_account_that_began_it() {
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (_, client) = social_fixture(
        &db,
        sub.clone(),
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;
    let sessions = social_sessions();
    round_trip(&client, &[]).await;
    let ada = store::by_username(&db.pool, "adalovelace")
        .await
        .unwrap()
        .unwrap();

    // Someone else signs in on this browser before the consent comes back.
    *sub.lock().unwrap() = "g2".into();
    let r = client
        .post_form("/auth/google/start", &[("connect", "1")])
        .await;
    let state = sent_state(r.location().unwrap());
    let bob = store::create(&db.pool, new("bob", "", None)).await.unwrap();
    let (id, mut data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    owt_accounts::session::Signed::set_signature(
        &mut data,
        Some(owt_accounts::session::Signature {
            account: bob.id,
            epoch: bob.session_epoch,
        }),
    );
    client.set_cookie("s", &sessions.seal(&id, &data));
    let r = client
        .get(&format!("/auth/google/callback?state={state}&code=abc"))
        .await;
    assert_eq!(r.location(), Some("/login?social=sign-in-first"));
    assert_eq!(identities::list(&db.pool, bob.id).await.unwrap().len(), 0);
    assert_eq!(identities::list(&db.pool, ada.id).await.unwrap().len(), 1);

    // Cancelled at the provider: back to the connections page.
    client.set_cookie(
        "s",
        &sessions.seal(&id, &{
            let mut d = data.clone();
            d.started = None;
            owt_accounts::session::Signed::set_signature(
                &mut d,
                Some(owt_accounts::session::Signature {
                    account: ada.id,
                    epoch: ada.session_epoch,
                }),
            );
            d
        }),
    );
    client
        .post_form("/auth/google/start", &[("connect", "1")])
        .await;
    let r = client
        .get("/auth/google/callback?error=access_denied")
        .await;
    assert_eq!(r.location(), Some("/account/connections?social=cancelled"));

    // Another account's identity: taken.
    *sub.lock().unwrap() = "g-bob".into();
    identities::link(
        &db.pool,
        bob.id,
        &owt_auth::oauth::google(),
        &identity("g-bob", None, false),
    )
    .await
    .unwrap();
    let r = round_trip(&client, &[("connect", "1")]).await;
    assert_eq!(r.location(), Some("/account/connections?social=taken"));

    // A session that began long ago must sign in again first.
    let old = {
        let mut d = owt_accounts::social::Data::default();
        owt_accounts::session::Signed::set_signature(
            &mut d,
            Some(owt_accounts::session::Signature {
                account: ada.id,
                epoch: ada.session_epoch,
            }),
        );
        d
    };
    let demanding = owt_accounts::social::SocialSignIn::new(
        db.pool.clone(),
        owt_auth::oauth::http_client().unwrap(),
        owt_accounts::social::Providers::new("http://localhost:8000", "/auth/{provider}/callback")
            .unwrap()
            .with(owt_auth::oauth::google(), "cid", "secret")
            .unwrap(),
        identities::Welcome::default(),
    )
    .connect_within(Duration::ZERO);
    let strict = owt_test::Client::new(social_app(&db, &sessions, &demanding));
    strict.set_cookie("s", &sessions.seal(&owt_web::session::new_id(), &old));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = strict
        .post_form("/auth/google/start", &[("connect", "1")])
        .await;
    assert_eq!(r.location(), Some("/login?social=sign-in-again"));
    db.drop().await;
}

/// An identity linked to a deactivated account signs nobody in and creates nothing.
#[tokio::test]
async fn a_deactivated_accounts_identity_signs_nobody_in() {
    let db = db!();
    let sub = Arc::new(std::sync::Mutex::new("g1".to_owned()));
    let (_, client) = social_fixture(
        &db,
        sub,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await;
    round_trip(&client, &[]).await;
    let ada = store::by_username(&db.pool, "adalovelace")
        .await
        .unwrap()
        .unwrap();
    store::set_active(&db.pool, ada.id, false).await.unwrap();
    client.clear_cookies();
    let r = round_trip(&client, &[]).await;
    assert_eq!(r.location(), Some("/login?social=unknown"));
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(total, 1);
    db.drop().await;
}

/// A builder setting made after `routes()` reaches later routes, not earlier ones,
/// and is never silently dropped.
#[tokio::test]
async fn the_builder_never_drops_a_setting() {
    use owt_accounts::social::{self, Providers, SocialSignIn};
    let db = db!();
    let s = SocialSignIn::new(
        db.pool.clone(),
        owt_auth::oauth::http_client().unwrap(),
        Providers::new("http://localhost:8000", social::DEFAULT_CALLBACK)
            .unwrap()
            .with(owt_auth::oauth::google(), "cid", "secret")
            .unwrap(),
        identities::Welcome::default(),
    );
    let _early = s.routes::<social::Data, ()>();
    let s = s.sign_in_page("/signin");
    let client = owt_test::Client::new(social_app(&db, &social_sessions(), &s));
    let r = client.get("/auth/google/callback?state=x&code=y").await;
    assert_eq!(r.location(), Some("/signin?social=expired"));
    db.drop().await;
}

/// A sign-in with the old password, still checking it when the password changes
/// (the owner's reset, staff answering a compromise), does not stand: it would
/// otherwise get the new session epoch and outlive the change.
#[tokio::test]
async fn a_sign_in_in_flight_does_not_outlive_a_password_change() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let replacement = owt_auth::password::hash("a different passphrase")
        .await
        .unwrap();
    let pool = db.pool.clone();
    let signing_in =
        tokio::spawn(
            async move { store::authenticate(&pool, "ada", "correct horse battery").await },
        );
    // The check is under way (Argon2 takes far longer than this); change the
    // password and sign out everywhere in one statement, as set_password does.
    tokio::time::sleep(Duration::from_millis(15)).await;
    sqlx::query(
        "UPDATE accounts SET password_hash = $1, session_epoch = session_epoch + 1 WHERE id = $2",
    )
    .bind(&replacement)
    .bind(ada.id)
    .execute(&db.pool)
    .await
    .unwrap();
    assert_eq!(signing_in.await.unwrap().unwrap(), None);
    let now = store::by_id(&db.pool, ada.id).await.unwrap().unwrap();
    assert!(
        store::authenticate(&db.pool, "ada", "a different passphrase")
            .await
            .unwrap()
            .is_some_and(|a| a.session_epoch == now.session_epoch)
    );
    db.drop().await;
}

/// The account's own change needs its current password; a legacy hash is no
/// password at all (it opens nothing, so it is not a way in).
#[tokio::test]
async fn changing_a_password_needs_the_current_one() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let err = store::change_password(&db.pool, &ada, "wrong guess", "a different passphrase")
        .await
        .unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::CurrentPassword));
    assert!(
        store::change_password(
            &db.pool,
            &ada,
            "correct horse battery",
            "a different passphrase"
        )
        .await
        .unwrap()
    );
    assert!(
        store::authenticate(&db.pool, "ada", "a different passphrase")
            .await
            .unwrap()
            .is_some()
    );
    db.drop().await;
}

/// The token never reaches a log through `Debug`.
#[test]
fn a_minted_link_keeps_its_token_out_of_debug() {
    let minted = links::Minted {
        token: "secret-token-value".into(),
    };
    assert!(!format!("{minted:?}").contains("secret"));
}

/// An account whose username the library would refuse, inserted around it (a
/// console session, a script): the table's constraints let the shape through, and the
/// pages must still treat it as text.
async fn legacy_account(pool: &PgPool, username: &str) -> store::Account {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (username, username_skeleton) VALUES ($1, $1) RETURNING id",
    )
    .bind(username)
    .fetch_one(pool)
    .await
    .unwrap();
    store::by_id(pool, id).await.unwrap().unwrap()
}

/// The account's own change, still checking the current password when staff reset
/// it, is refused: the reset stands.
#[tokio::test]
async fn a_reset_by_staff_beats_a_change_in_flight() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let (pool, a) = (db.pool.clone(), ada.clone());
    let changing = async move {
        store::change_password(&pool, &a, "correct horse battery", "the attackers choice").await
    };
    let changing = tokio::spawn(changing);
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(
        store::set_password(&db.pool, &ada, "staff reset passphrase")
            .await
            .unwrap()
    );
    let err = changing.await.unwrap().unwrap_err();
    assert_eq!(err.refused(), Some(&owt_accounts::Refused::CurrentPassword));
    for (password, opens) in [
        ("staff reset passphrase", true),
        ("the attackers choice", false),
    ] {
        assert_eq!(
            store::authenticate(&db.pool, "ada", password)
                .await
                .unwrap()
                .is_some(),
            opens,
            "{password}"
        );
    }
    db.drop().await;
}

/// However many people share a non-Latin name, a first sign-in gets an account.
#[tokio::test]
async fn a_common_name_in_any_script_always_gets_an_account() {
    let db = db!();
    let open = identities::Welcome {
        create: true,
        ..Default::default()
    };
    for n in 0..23 {
        let mut who = identity(&format!("ivan-{n}"), None, false);
        who.display_name = Some("Иван".into());
        let arrival = identities::arrive(&db.pool, &oauth::google(), &who, open)
            .await
            .unwrap();
        let name = &arrival.account().unwrap().username;
        assert!(name.starts_with("иван"), "{name}");
    }
    db.drop().await;
}

/// A name a reader could not tell from an existing one is refused, by the table.
#[tokio::test]
async fn a_lookalike_of_an_existing_username_is_refused() {
    let db = db!();
    for (first, second) in [
        ("paypal", "paypa1"),
        // All Cyrillic: one script, so only the skeleton tells it from `coco`.
        ("coco", "\u{441}\u{43e}\u{441}\u{43e}"),
        ("modern", "modem"),
        ("code", "c0de"),
    ] {
        store::create(&db.pool, new(first, "", None)).await.unwrap();
        let err = store::create(&db.pool, new(second, "", None))
            .await
            .unwrap_err();
        assert_eq!(
            err.refused(),
            Some(&owt_accounts::Refused::UsernameLookalike(second.into())),
            "{first} / {second}"
        );
    }
    // A provider sign-up moves on to another name rather than failing.
    let mut who = identity("lookalike", None, false);
    who.display_name = Some("paypa1".into());
    let arrival = identities::arrive(
        &db.pool,
        &oauth::google(),
        &who,
        identities::Welcome {
            create: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(arrival.account().is_some());
    db.drop().await;
}

/// The table refuses what the library would never write: a hash that opens nothing,
/// a name not in stored form, a link that outlives the limit, an empty subject.
#[tokio::test]
async fn the_schema_refuses_rows_the_library_would_misread() {
    let db = db!();
    let ada = store::create(&db.pool, new("ada", "", None)).await.unwrap();
    let refused = |sql: &'static str| {
        let pool = db.pool.clone();
        async move {
            let err = sqlx::query(sql)
                .bind(ada.id)
                .execute(&pool)
                .await
                .expect_err(sql);
            assert!(
                err.as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_check_violation),
                "{sql}: {err}"
            );
        }
    };
    refused("UPDATE accounts SET password_hash = 'pbkdf2_sha256$600000$s$h' WHERE id = $1").await;
    refused("UPDATE accounts SET username = 'ＡＤＡ' WHERE id = $1").await;
    refused("UPDATE accounts SET username = 'Ada' WHERE id = $1").await;
    refused("UPDATE accounts SET email = 'Ada@Example.com' WHERE id = $1").await;
    refused("UPDATE accounts SET email = '@example.com' WHERE id = $1").await;
    refused(
        "INSERT INTO sign_in_links (token_sha256, account_id, expires_at)
         VALUES (sha256('x'), $1, now() + interval '31 days')",
    )
    .await;
    refused(
        "INSERT INTO account_identities (account_id, provider, subject) VALUES ($1, 'google', '')",
    )
    .await;
    refused(
        "INSERT INTO account_local_identities (account_id, key, subject) VALUES ($1, 'kiosk', '')",
    )
    .await;
    refused(
        "UPDATE accounts SET password_sign_in = false, password_hash = '$argon2id$v=19$x'
         WHERE id = $1",
    )
    .await;
    // And what the library writes, it takes.
    links::mint(&db.pool, ada.id, links::MAX_TTL, "longest")
        .await
        .unwrap();
    db.drop().await;
}

/// A database that ran 0001 and 0002 for a while, holding rows those admit (some
/// written around the library), comes through 0003 and `complete` in the state a
/// new one starts in: every constraint validated for every row, no one who could
/// sign in locked out, and the renames reported.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one upgrade, seeded and checked")]
async fn existing_rows_come_through_the_constraints_migration() {
    use owt_accounts::migrations::{ALL, Renamed, complete};
    let Some((pool, drop_schema)) = schema_after(&ALL[..2]).await else {
        return;
    };
    let argon = owt_auth::password::hash("correct horse battery")
        .await
        .unwrap();
    // A PHC string without its version field: the verifier takes it.
    let unversioned = argon.replacen("$v=19", "", 1);
    // Its parameters in another order (the verifier takes any), and a salt with no
    // hash (which opens nothing).
    let (params, rest) = {
        let mut parts = argon.splitn(5, '$');
        let (_, alg, v, params, rest) = (
            parts.next(),
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut p: Vec<&str> = params.split(',').collect();
        p.reverse();
        (format!("${alg}${v}${}", p.join(",")), rest.to_owned())
    };
    let reordered = format!("{params}${rest}");
    let saltless = format!("{params}${}", rest.split('$').next().unwrap());
    sqlx::query(
        "INSERT INTO accounts (id, username, email, password_hash, session_epoch)
         OVERRIDING SYSTEM VALUE VALUES
            (1, 'admin', 'ADA@EXAMPLE.COM', $1, 0),
            (2, 'admin-3', '', '', 0),
            (3, 'ａdmin', '', 'pbkdf2_sha256$600000$s$h', 0),
            (4, '´bob', '', '', 0),
            (5, 'x𝚺', '', '', 0),
            (6, 'ｃｏｃｏ', '@nowhere', '', 0),
            (7, 'paypal', '', '', 0),
            (8, 'pаypal', '', '', 0),
            (9, 'carol', '', $2, 0),
            (10, 'dave', 'Ａda@example.com', '', 0),
            (11, 'erin', '', '', -5),
            (12, 'frank', '', $3, 0),
            (13, 'gina', '', $4, 0)",
    )
    .bind(&argon)
    .bind(&unversioned)
    .bind(&reordered)
    .bind(&saltless)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("SELECT setval(pg_get_serial_sequence('accounts', 'id'), 100)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sign_in_links (token_sha256, account_id, expires_at) VALUES
            (sha256('t'), 1, now() + interval '100 years'),
            ('\\x010203', 1, now() + interval '1 day')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO account_identities (account_id, provider, subject)
         VALUES (1, 'google', ''), (1, 'google', 'g1')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // As sqlx runs each migration: in a transaction. The later ones too, which the
    // library reads.
    for migration in &ALL[2..] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(migration.sql))
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let done = complete(&pool).await.unwrap();
    let renamed = |id, from: &str, to: &str| Renamed {
        id,
        from: from.into(),
        to: to.into(),
    };
    assert_eq!(
        done.renamed,
        [
            renamed(3, "ａdmin", "admin-3-2"),
            renamed(4, "´bob", &store::normalize("´bob")),
            renamed(5, "x𝚺", "xς"),
            renamed(6, "ｃｏｃｏ", "coco"),
        ]
    );
    assert_eq!(done.emails_cleared, [6, 10]);
    assert_eq!(done.passwords_cleared, [3, 13]);
    assert_eq!(done.keyed, 13);
    assert!(done.failed.is_empty() && done.validated, "{done:?}");
    let again = complete(&pool).await.unwrap();
    assert!(again.keyed == 0 && again.renamed.is_empty() && again.validated);
    let unvalidated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint WHERE NOT convalidated
         AND conrelid::regclass::text IN ('accounts', 'account_identities', 'sign_in_links')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unvalidated, 0);

    // Ways in that worked still do, typed as their owners type them.
    for (login, password) in [
        ("Ada@Example.com", "correct horse battery"),
        ("carol", "correct horse battery"),
        ("frank", "correct horse battery"),
    ] {
        assert!(
            store::authenticate(&pool, login, password)
                .await
                .unwrap()
                .is_some(),
            "{login}"
        );
    }
    assert_eq!(
        store::by_username(&pool, "x𝚺").await.unwrap().map(|a| a.id),
        Some(5)
    );
    let skeleton: Option<String> =
        sqlx::query_scalar("SELECT username_skeleton FROM accounts WHERE id = 8")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        skeleton.as_deref(),
        Some("paypal@8"),
        "the later lookalike's own key"
    );
    let epoch: i32 = sqlx::query_scalar("SELECT session_epoch FROM accounts WHERE id = 11")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(epoch, 0);
    assert_eq!(identities::list(&pool, 1).await.unwrap().len(), 1);
    let links: Vec<bool> = sqlx::query_scalar(
        "SELECT expires_at <= created_at + interval '30 days' FROM sign_in_links",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        links,
        [true],
        "the century link cut, the digest-less one gone"
    );

    // New names are held to the lookalike rule against the old ones, and against a
    // row an older replica wrote after the migration, before complete reached it.
    let err = store::create(&pool, new("c0co", "", None))
        .await
        .unwrap_err();
    assert_eq!(
        err.refused(),
        Some(&owt_accounts::Refused::UsernameLookalike("c0co".into()))
    );
    sqlx::query("INSERT INTO accounts (username) VALUES ('mike')")
        .execute(&pool)
        .await
        .unwrap();
    let err = store::create(&pool, new("rnike", "", None))
        .await
        .unwrap_err();
    assert_eq!(
        err.refused(),
        Some(&owt_accounts::Refused::UsernameLookalike("rnike".into()))
    );
    pool.close().await;
    drop_schema.await;
}

/// A database at 0004 comes through 0005: every account keeps password sign-in, and
/// `complete` validates the constraint it adds.
#[tokio::test]
async fn existing_accounts_keep_password_sign_in_through_the_local_migration() {
    use owt_accounts::migrations::{ALL, complete};
    let Some((pool, drop_schema)) = schema_after(&ALL[..4]).await else {
        return;
    };
    complete(&pool).await.unwrap();
    let ada = store::create(&pool, new("ada", "", Some("correct horse battery")))
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(ALL[4].sql))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let done = complete(&pool).await.unwrap();
    assert!(done.validated, "{done:?}");
    let opened = store::authenticate(&pool, "ada", "correct horse battery")
        .await
        .unwrap();
    assert_eq!(opened.map(|a| a.id), Some(ada.id));
    let unvalidated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE NOT convalidated AND connamespace = current_schema()::regnamespace",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unvalidated, 0);
    pool.close().await;
    drop_schema.await;
}

/// A schema of its own with these migrations applied, as a database that stopped at
/// them; and the future that drops it.
async fn schema_after(
    migrations: &[owt_accounts::migrations::Migration],
) -> Option<(PgPool, impl Future<Output = ()>)> {
    let url = owt_runtime::env::var("DATABASE_URL")?;
    let schema = format!(
        "owt_upgrade_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let admin = PgPool::connect(&url).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let opts: PgConnectOptions = url.parse().unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    for m in migrations {
        sqlx::raw_sql(sqlx::AssertSqlSafe(m.sql))
            .execute(&pool)
            .await
            .unwrap();
    }
    let drop_schema = async move {
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
    };
    Some((pool, drop_schema))
}

#[tokio::test]
async fn nothing_conflicts_where_the_migrations_are_installed() {
    let db = db!();
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    assert!(found.is_empty(), "{found:?}");
    db.drop().await;
}

#[tokio::test]
async fn every_name_the_migrations_take_is_checked() {
    // Every relation and function the migrations create, read back from an installed
    // schema, then held by something of an app's in an empty one: conflicts names
    // each, so its list cannot fall behind a new migration.
    let installed = db!();
    let relations: Vec<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_class
         WHERE relnamespace = current_schema()::regnamespace
           AND relname NOT IN ('_sqlx_migrations', '_sqlx_migrations_pkey')
         ORDER BY 1",
    )
    .fetch_all(&installed.pool)
    .await
    .unwrap();
    let functions: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc
         WHERE pronamespace = current_schema()::regnamespace ORDER BY 1",
    )
    .fetch_all(&installed.pool)
    .await
    .unwrap();
    installed.drop().await;

    let Some(db) = Db::empty().await else { return };
    for name in &relations {
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE TABLE \"{name}\" ()")))
            .execute(&db.pool)
            .await
            .unwrap();
    }
    for name in &functions {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION \"{name}\"() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )))
        .execute(&db.pool)
        .await
        .unwrap();
    }
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    let held = |by: &str| {
        let mut named: Vec<String> = found
            .iter()
            .filter(|c| c.held_by == by)
            .map(|c| c.name.to_owned())
            .collect();
        named.sort();
        named
    };
    assert_eq!(held("table"), relations);
    assert_eq!(held("function"), functions);
    db.drop().await;
}

/// A column or constraint a pending migration adds to `accounts`, which the app
/// added first under the same name, is named too.
#[tokio::test]
async fn a_column_the_migrations_add_is_named_when_held() {
    let db = db!();
    // As a database that stopped before 0005, whose app then added a column of the
    // name 0005 takes, and a constraint.
    sqlx::raw_sql(
        "DROP TABLE account_local_identities;
         ALTER TABLE accounts DROP COLUMN password_sign_in;
         DELETE FROM _sqlx_migrations WHERE version = 5;
         ALTER TABLE accounts ADD COLUMN password_sign_in text,
             ADD CONSTRAINT accounts_password_sign_in_hash CHECK (true);",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    let named: Vec<(&str, &str, &str)> = found
        .iter()
        .map(|c| (c.migration, c.name, c.held_by))
        .collect();
    assert_eq!(
        named,
        [
            ("owt_accounts_local", "accounts.password_sign_in", "column"),
            (
                "owt_accounts_local",
                "accounts.accounts_password_sign_in_hash",
                "constraint"
            ),
        ]
    );
    db.drop().await;
}

#[tokio::test]
async fn an_apps_own_accounts_table_is_named_until_renamed() {
    let Some(db) = Db::empty().await else { return };
    // An app's `accounts`, unrelated to sign-in, with a key of its own: renaming the
    // table alone leaves its key's index and sequence under their old names.
    sqlx::raw_sql(
        "CREATE TABLE accounts (id serial PRIMARY KEY, username text UNIQUE, goods int);
         CREATE TYPE account_roles AS ENUM ('buyer', 'seller');",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    let named: Vec<(&str, &str, &str)> = found
        .iter()
        .map(|c| (c.migration, c.name, c.held_by))
        .collect();
    assert_eq!(
        named,
        [
            ("owt_accounts", "accounts", "table"),
            ("owt_accounts", "accounts_pkey", "index"),
            ("owt_accounts", "accounts_id_seq", "sequence"),
            ("owt_accounts", "accounts_username_key", "index"),
            ("owt_accounts_roles", "account_roles", "type"),
        ]
    );
    assert_eq!(found[0].schema, db.schema);
    let said = found[0].to_string();
    assert!(
        said.contains("accounts is already a table") && said.contains("before owt-accounts"),
        "{said}"
    );
    // As an app migrates: a bare `MIGRATOR.run` that fails returns before releasing
    // sqlx's advisory lock (one per database, so every test's), and its pooled
    // connection would hold it; migrate_locked closes that connection.
    let lock_id = i64::from(rand::random::<u32>());
    assert!(
        owt_runtime::db::migrate_locked(&db.pool, &MIGRATOR, lock_id)
            .await
            .is_err()
    );

    // The rename an app writes before owt-accounts' files: the table and what was
    // named after it.
    sqlx::raw_sql(
        "ALTER TABLE accounts RENAME TO holdings;
         ALTER INDEX accounts_pkey RENAME TO holdings_pkey;
         ALTER SEQUENCE accounts_id_seq RENAME TO holdings_id_seq;
         ALTER INDEX accounts_username_key RENAME TO holdings_username_key;
         ALTER TYPE account_roles RENAME TO trade_roles;",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    assert!(found.is_empty(), "{found:?}");
    MIGRATOR.run(&db.pool).await.unwrap();
    let found = owt_accounts::migrations::conflicts(&db.pool).await.unwrap();
    assert!(found.is_empty(), "{found:?}");
    db.drop().await;
}
