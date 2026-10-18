//! Site policies against a real Postgres (`DATABASE_URL`); skipped without it. Each
//! test takes a schema of its own, as in `accounts.rs`.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use owt_accounts::policies::{self, Draft, PRIVACY, Page, Policies, TERMS};
use owt_accounts::session::{self, Data};
use owt_accounts::{Accounts, Maybe, New, store};
use owt_web::session::{Session, Sessions};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

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
            "owt_policies_{}_{}",
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

fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The policies over the test schema, re-read on every page so a version published
/// with the functions is asked for at once.
fn policies(db: &Db) -> Policies {
    let chrome = |page: Page<'_>| -> owt_web::Result<axum::response::Response> {
        Ok(axum::response::Html(format!(
            "<title>{}</title><p>at: {}</p>{}",
            escaped(page.title),
            escaped(&page.request.uri.to_string()),
            page.body
        ))
        .into_response())
    };
    Policies::new(db.pool.clone(), chrome, &[TERMS, PRIVACY])
        .admin("/staff/policies")
        .agreement("I agree, and I am at least 13.")
        .exempt(&["/static/"])
        .refresh(Duration::ZERO)
}

/// The test app: the policies' routes and gate inside the accounts layer.
fn app(db: &Db, sessions: &Sessions<Data>) -> Router {
    app_with(db, sessions, policies(db))
}

/// The test app, with `policies` configured by the test.
fn app_with(db: &Db, sessions: &Sessions<Data>, policies: Policies) -> Router {
    async fn whoami(Maybe(account): Maybe) -> String {
        account.map_or_else(|| "anonymous".to_owned(), |a| a.username)
    }
    async fn sign_out(session: Session<Data>) -> &'static str {
        session::sign_out(&session);
        "out"
    }
    let accounts = Accounts::new(db.pool.clone(), "/login");
    Router::new()
        .merge(policies.routes())
        .route("/whoami", get(whoami))
        .route("/static/app.css", get(|| async { "css" }))
        .route("/out", post(sign_out))
        .layer(from_fn_with_state(policies, Policies::gate))
        .layer(from_fn_with_state(accounts, Accounts::load::<Data>))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer))
}

fn sessions() -> Sessions<Data> {
    let key = owt_web::session::key_from_base64(&base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        (0..64u8).collect::<Vec<_>>(),
    ))
    .unwrap();
    Sessions::new(key, "s", Duration::from_secs(3600), false)
}

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

async fn account(db: &Db, username: &str, staff: bool) -> store::Account {
    let a = store::create(
        &db.pool,
        New {
            username,
            email: "",
            password: None,
            is_staff: staff,
        },
    )
    .await
    .unwrap();
    store::by_id(&db.pool, a.id).await.unwrap().unwrap()
}

/// A published version of `kind`.
async fn published(
    db: &Db,
    kind: &str,
    title: &str,
    body: &str,
    summary: &str,
) -> policies::Version {
    let draft = policies::draft(
        &db.pool,
        kind,
        Draft {
            title,
            effective_date: "2026-10-01",
            summary,
            body_markdown: body,
        },
        None,
    )
    .await
    .unwrap();
    policies::publish(&db.pool, draft.id)
        .await
        .unwrap()
        .unwrap()
}

/// The `version` inputs of the page that asks.
fn shown_versions(html: &str) -> Vec<String> {
    html.split("name=\"version\" value=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap().to_owned())
        .collect()
}

async fn count(db: &Db, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `GET uri` as a browser navigates to a page: it says so, and asks for HTML. The
/// client's plain `get` sends neither, as a non-browser client (or a fetch) does,
/// and the gate leaves those alone.
async fn navigate(client: &owt_test::Client, uri: &str) -> owt_test::Response {
    client
        .send(
            Request::get(uri)
                .header("sec-fetch-dest", "document")
                .header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
}

/// The test app, and a client signed in as `ada`, who has agreed to nothing.
async fn signed_in(db: &Db) -> (owt_test::Client, store::Account, Sessions<Data>) {
    let sessions = sessions();
    let client = owt_test::Client::new(app(db, &sessions));
    let ada = account(db, "ada", false).await;
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    (client, ada, sessions)
}

#[tokio::test]
async fn the_gate_sends_signed_in_page_loads_to_the_page_that_asks() {
    let db = db!();
    let (client, _, sessions) = signed_in(&db).await;
    // Nothing published: nobody is asked, and the documents are not there.
    assert_eq!(client.get("/whoami").await.text(), "ada");
    assert_eq!(client.get("/terms").await.status, 404);

    published(
        &db,
        "terms",
        "Terms of Service",
        "## Use\n\nBe <b>kind</b>.",
        "",
    )
    .await;
    published(&db, "privacy", "Privacy Notice", "We keep little.", "").await;

    // Anonymous visitors read the documents and are never asked.
    let anonymous = owt_test::Client::new(app(&db, &sessions));
    let page = anonymous.get("/terms").await;
    assert_eq!(page.status, 200);
    let html = page.text();
    assert!(
        html.contains("<title>Terms of Service</title>") && html.contains("<h2>Use</h2>"),
        "{html}"
    );
    assert!(
        html.contains("&lt;b&gt;kind&lt;/b&gt;") && !html.contains("<b>"),
        "{html}"
    );
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert_eq!(anonymous.get("/whoami").await.text(), "anonymous");
    assert_eq!(
        anonymous.get("/agree").await.location(),
        Some("/login?next=%2Fagree")
    );

    // Signed in: every document load goes to the page that asks first, as a
    // browser asks for one (naming the destination, or just text/html)...
    let r = navigate(&client, "/whoami?x=1").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/agree?next=%2Fwhoami%3Fx%3D1"));
    // An older browser names no destination but asks for HTML.
    let old = Request::get("/whoami?x=1")
        .header("accept", "text/html,*/*;q=0.8")
        .body(Body::empty())
        .unwrap();
    assert_eq!(client.send(old).await.status, 303);
    // ...but not what a page loads for itself (an image, a script, a fetch), nor a
    // fragment, a non-page request, a document, an exemption, or a POST.
    let image = Request::get("/static/app.css")
        .header("sec-fetch-dest", "image")
        .header("accept", "image/avif,image/webp,*/*")
        .body(Body::empty())
        .unwrap();
    assert_eq!(client.send(image).await.status, 200);
    let fetch = Request::get("/whoami")
        .header("sec-fetch-dest", "empty")
        .header("accept", "*/*")
        .body(Body::empty())
        .unwrap();
    assert_eq!(client.send(fetch).await.status, 200);
    assert_eq!(
        client.get("/whoami").await.status,
        200,
        "no Accept: not a browser's page"
    );
    assert_eq!(client.get_htmx("/whoami").await.status, 200);
    // A boosted navigation is a page: htmx follows the 303 and swaps the whole page.
    let boosted = Request::get("/whoami?x=1")
        .header("hx-request", "true")
        .header("hx-boosted", "true")
        .header("accept", "*/*")
        .body(Body::empty())
        .unwrap();
    assert_eq!(client.send(boosted).await.status, 303);
    let json = client
        .send(
            Request::get("/whoami")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(json.status, 200);
    assert_eq!(client.get("/privacy").await.status, 200);
    assert_eq!(client.get("/static/app.css").await.status, 200);
    assert_eq!(client.post_form("/out", &[]).await.status, 200);
    db.drop().await;
}

#[tokio::test]
async fn agreeing_records_the_versions_shown_and_nothing_else() {
    let db = db!();
    let (client, _, _) = signed_in(&db).await;
    let terms = published(
        &db,
        "terms",
        "Terms of Service",
        "## Use\n\nBe <b>kind</b>.",
        "",
    )
    .await;
    let privacy = published(&db, "privacy", "Privacy Notice", "We keep little.", "").await;

    let html = client.get("/agree?next=%2Fwhoami").await.text();
    assert!(
        html.contains("Before you continue") && html.contains("I agree, and I am at least 13."),
        "{html}"
    );
    assert!(
        html.contains("href=\"/terms\"") && html.contains("href=\"/privacy\""),
        "{html}"
    );
    let shown = shown_versions(&html);
    assert_eq!(shown, [terms.id.to_string(), privacy.id.to_string()]);

    // Unticked, or versions other than those asked: asked again, nothing recorded.
    let unticked = [
        ("next", "/whoami"),
        ("version", &shown[0]),
        ("version", &shown[1]),
    ];
    let r = client.post_form("/agree", &unticked).await;
    assert_eq!(r.status, 422);
    assert!(r.text().contains("Tick the box"));
    let partial = [
        ("agree", "yes"),
        ("next", "/whoami"),
        ("version", shown[0].as_str()),
    ];
    assert_eq!(client.post_form("/agree", &partial).await.status, 409);
    assert_eq!(count(&db, "policy_acceptances").await, 0);

    let form = format!(
        "agree=yes&next=%2Fwhoami&version={}&version={}",
        shown[0], shown[1]
    );
    let r = client
        .send(
            Request::post("/agree")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("user-agent", "TestBrowser/1.0")
                .body(Body::from(form))
                .unwrap(),
        )
        .await;
    assert_eq!((r.status.as_u16(), r.location()), (303, Some("/whoami")));
    let events: Vec<(String, i32, String, Option<String>)> = sqlx::query_as(
        "SELECT kind, version, content_sha256, user_agent FROM policy_acceptance_events ORDER BY kind",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    let hash = |text: &str| hex(&Sha256::digest(text.as_bytes()));
    let browser = Some("TestBrowser/1.0".to_owned());
    assert_eq!(
        events,
        [
            (
                "privacy".into(),
                1,
                hash("We keep little."),
                browser.clone()
            ),
            (
                "terms".into(),
                1,
                hash("## Use\n\nBe <b>kind</b>."),
                browser
            ),
        ]
    );
    assert_eq!(client.get("/whoami").await.text(), "ada");

    // Nothing left to ask: the page sends on, to a local path only.
    let r = client.get("/agree?next=%2F%2Fevil.example").await;
    assert_eq!((r.status.as_u16(), r.location()), (303, Some("/")));
    let r = client
        .post_form("/agree", &[("agree", "yes"), ("next", "/whoami")])
        .await;
    assert_eq!(r.location(), Some("/whoami"));
    assert_eq!(count(&db, "policy_acceptance_events").await, 2);
    let html = client.get("/terms").await.text();
    assert!(html.contains("You agreed to version 1 on"), "{html}");
    db.drop().await;
}

#[tokio::test]
async fn a_new_version_asks_again_and_old_ones_stay_while_held() {
    let db = db!();
    let (client, ada, _) = signed_in(&db).await;
    let bob = account(&db, "bob", false).await;
    let v1 = published(&db, "terms", "Terms", "First.", "").await;
    let privacy = published(&db, "privacy", "Privacy", "Little.", "").await;
    for who in [ada.id, bob.id] {
        let n = policies::accept(&db.pool, who, &[v1.id, privacy.id], None, Some("seed"))
            .await
            .unwrap();
        assert_eq!(n, 2);
    }
    assert_eq!(client.get("/whoami").await.text(), "ada");

    let v2 = published(&db, "terms", "Terms", "Second.", "Clearer wording.").await;
    assert_eq!(v2.version, Some(2));
    assert_eq!(navigate(&client, "/whoami").await.status, 303);
    assert_eq!(
        client.get("/whoami").await.status,
        200,
        "a fetch is let through"
    );
    let html = client.get("/agree").await.text();
    assert!(html.contains("We have updated our policies"), "{html}");
    assert!(
        html.contains("You last agreed to") && html.contains("href=\"/terms/v/1\""),
        "{html}"
    );
    assert!(html.contains("Clearer wording."), "{html}");
    assert_eq!(
        shown_versions(&html),
        [v2.id.to_string()],
        "privacy is not asked again"
    );

    // Both versions are on record while somebody holds the first.
    let old = client.get("/terms/v/1").await.text();
    assert!(
        old.contains("Not the current version") && old.contains("First."),
        "{old}"
    );
    let none: Vec<(String, i32)> = Vec::new();
    assert_eq!(policies::prune(&db.pool).await.unwrap(), none);
    policies::accept(&db.pool, bob.id, &[v2.id], None, None)
        .await
        .unwrap();
    assert_eq!(
        policies::prune(&db.pool).await.unwrap(),
        none,
        "ada holds it"
    );
    policies::accept(&db.pool, ada.id, &[v2.id], None, None)
        .await
        .unwrap();
    assert_eq!(
        policies::prune(&db.pool).await.unwrap(),
        [("terms".to_owned(), 1)]
    );
    assert_eq!(client.get("/terms/v/1").await.status, 404);
    assert_eq!(client.get("/terms/v/2").await.status, 200);
    assert_eq!(client.get("/whoami").await.text(), "ada");
    // The record of each acceptance outlives the version.
    assert_eq!(count(&db, "policy_acceptance_events").await, 6);

    // A published version never changes, and the current one is never deleted.
    let edit = sqlx::query("UPDATE policy_versions SET title = 'x' WHERE id = $1")
        .bind(v2.id)
        .execute(&db.pool)
        .await;
    assert!(edit.is_err());
    sqlx::query("DELETE FROM policy_acceptances")
        .execute(&db.pool)
        .await
        .unwrap();
    let delete = sqlx::query("DELETE FROM policy_versions WHERE id = $1")
        .bind(v2.id)
        .execute(&db.pool)
        .await;
    assert!(delete.is_err());
    let draft = Draft {
        title: "x",
        effective_date: "2026-01-01",
        summary: "",
        body_markdown: "x",
    };
    assert_eq!(policies::save(&db.pool, v2.id, draft).await.unwrap(), None);
    db.drop().await;
}

/// The test app's client, signed in as a member of staff.
async fn staff(db: &Db) -> (owt_test::Client, store::Account) {
    let sessions = sessions();
    let client = owt_test::Client::new(app(db, &sessions));
    let boss = account(db, "boss", true).await;
    client.set_cookie("s", &cookie_for(&sessions, &boss));
    (client, boss)
}

#[tokio::test]
async fn only_staff_reach_the_staff_pages() {
    let db = db!();
    let sessions = sessions();
    let client = owt_test::Client::new(app(&db, &sessions));
    let r = client.get("/staff/policies").await;
    assert_eq!(r.location(), Some("/login?next=%2Fstaff%2Fpolicies"));
    let ada = account(&db, "ada", false).await;
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    assert_eq!(client.get("/staff/policies").await.status, 403);
    assert_eq!(
        client
            .post_form("/staff/policies/new/terms", &[])
            .await
            .status,
        403
    );

    let (client, _) = staff(&db).await;
    let list = client.get("/staff/policies").await;
    assert_eq!(list.status, 200);
    assert_eq!(list.header("x-frame-options"), Some("DENY"));
    assert!(list.text().contains("No versions yet"), "{}", list.text());
    // The chrome sees the page's own URI, not the nested router's stripped one.
    assert!(
        list.text().contains("<p>at: /staff/policies</p>"),
        "{}",
        list.text()
    );
    assert_eq!(
        client
            .post_form("/staff/policies/new/cookies", &[])
            .await
            .status,
        404
    );
    db.drop().await;
}

#[tokio::test]
async fn a_draft_is_private_checked_and_fixed_once_published() {
    let db = db!();
    let (client, _) = staff(&db).await;
    let r = client.post_form("/staff/policies/new/terms", &[]).await;
    assert_eq!(r.status, 303);
    let at = r.location().unwrap().to_owned();
    assert!(at.starts_with("/staff/policies/"), "{at}");
    let page = client.get(&at).await.text();
    assert!(
        page.contains("Terms of Service: draft") && page.contains("value=\"Terms of Service\""),
        "{page}"
    );
    assert_eq!(client.get("/terms").await.status, 404);
    let r = client.post_form(&format!("{at}/publish"), &[]).await;
    assert_eq!(r.location(), Some(format!("{at}?notice=empty").as_str()));

    let bad_date = [
        ("title", "Terms"),
        ("effective_date", "2026-02-30"),
        ("body_markdown", "x"),
    ];
    let r = client.post_form(&at, &bad_date).await;
    assert_eq!(r.status, 422);
    assert!(r.text().contains("YYYY-MM-DD"));
    let good = [
        ("title", " Terms "),
        ("effective_date", "2026-10-01"),
        ("summary", ""),
        ("body_markdown", "One.\r\nTwo."),
    ];
    let r = client.post_form(&at, &good).await;
    assert_eq!(r.location(), Some(format!("{at}?notice=saved").as_str()));
    let r = client.post_form(&format!("{at}/publish"), &[]).await;
    assert_eq!(r.location(), Some("/staff/policies?notice=published"));
    let v1 = policies::current(&db.pool, "terms").await.unwrap().unwrap();
    assert_eq!(
        (v1.title.as_str(), v1.body_markdown.as_str()),
        ("Terms", "One.\nTwo.")
    );
    let digest = hex(&Sha256::digest(b"One.\nTwo."));
    assert_eq!(v1.content_sha256.as_deref(), Some(digest.as_str()));
    assert!(client.get(&at).await.text().contains(&digest));

    // Published: fixed.
    let r = client.post_form(&at, &good).await;
    assert_eq!(
        r.location(),
        Some(format!("{at}?notice=not-draft").as_str())
    );
    let r = client.post_form(&format!("{at}/delete"), &[]).await;
    assert_eq!(
        r.location(),
        Some(format!("{at}?notice=not-draft").as_str())
    );

    // Staff are asked too, though not on the staff pages.
    assert_eq!(navigate(&client, "/whoami").await.status, 303);
    assert_eq!(client.get("/staff/policies").await.status, 200);
    db.drop().await;
}

#[tokio::test]
async fn a_new_version_says_what_changed_and_staff_prune_what_nobody_holds() {
    let db = db!();
    let (client, boss) = staff(&db).await;
    let v1 = published(&db, "terms", "Terms", "One.\nTwo.", "").await;
    policies::accept(&db.pool, boss.id, &[v1.id], None, None)
        .await
        .unwrap();

    // A second version starts from the first's text, and says what changed.
    let new = client.post_form("/staff/policies/new/terms", &[]).await;
    let at = new.location().unwrap().to_owned();
    assert!(client.get(&at).await.text().contains("One.\nTwo."));
    let r = client.post_form(&format!("{at}/publish"), &[]).await;
    assert_eq!(r.location(), Some(format!("{at}?notice=summary").as_str()));
    let fields = [
        ("title", "Terms"),
        ("effective_date", "2026-10-02"),
        ("summary", "Shorter."),
        ("body_markdown", "One."),
    ];
    client.post_form(&at, &fields).await;
    client.post_form(&format!("{at}/publish"), &[]).await;
    let v2 = policies::current(&db.pool, "terms").await.unwrap().unwrap();
    assert_eq!((v2.version, v2.summary.as_str()), (Some(2), "Shorter."));

    // A discarded draft goes; the version boss holds stays until they move on.
    let discarded = client.post_form("/staff/policies/new/terms", &[]).await;
    let at = discarded.location().unwrap().to_owned();
    let r = client.post_form(&format!("{at}/delete"), &[]).await;
    assert_eq!(r.location(), Some("/staff/policies?notice=deleted"));
    assert_eq!(client.get(&at).await.status, 404);
    let r = client.post_form("/staff/policies/prune", &[]).await;
    assert!(r.text().contains("Nothing to remove"), "{}", r.text());
    policies::accept(&db.pool, boss.id, &[v2.id], None, None)
        .await
        .unwrap();
    let r = client.post_form("/staff/policies/prune", &[]).await;
    assert!(
        r.text().contains("Removed Terms of Service version 1."),
        "{}",
        r.text()
    );
    let list = client.get("/staff/policies").await.text();
    assert!(
        list.contains("Version 2") && !list.contains("Version 1<"),
        "{list}"
    );
    db.drop().await;
}

/// A design of the app's own for a document's page; the others stay Tailwind's.
struct Plain;

impl policies::Views for Plain {
    fn document(
        &self,
        _: &axum::http::request::Parts,
        view: &policies::DocumentView<'_>,
    ) -> owt_web::Result<owt_accounts::admin::Body> {
        #[derive(askama::Template)]
        #[template(
            source = "<p>plain {{ v.version.title }}, {{ v.date }}, current at {{ v.current_href }}</p>",
            ext = "html"
        )]
        struct Html<'a, 'b> {
            v: &'a policies::DocumentView<'b>,
        }
        owt_accounts::admin::Body::render(&Html { v: view })
    }
}

#[tokio::test]
async fn an_app_draws_the_pages_at_its_paths_in_its_words() {
    let db = db!();
    let sessions = sessions();
    let mine = policies(&db)
        .views(Plain)
        .documents_at("/legal/")
        .sign_out("/out")
        .dates(|d: &str| d.replace('-', "/"))
        .words(policies::Words {
            agree: "Agree, then",
            ..policies::Words::ENGLISH
        });
    let client = owt_test::Client::new(app_with(&db, &sessions, mine));
    let ada = account(&db, "ada", false).await;
    client.set_cookie("s", &cookie_for(&sessions, &ada));
    published(&db, "terms", "Terms <1>", "First.", "").await;

    // The app's own page, at the prefix; nothing at the root.
    let r = navigate(&client, "/legal/terms").await;
    assert_eq!(r.status, 200, "a document is never gated");
    assert!(
        r.text()
            .contains("<p>plain Terms &#60;1&#62;, 2026/10/01, current at /legal/terms</p>"),
        "{}",
        r.text()
    );
    assert_eq!(client.get("/terms").await.status, 404);
    assert_eq!(client.get("/legal/terms/v/1").await.status, 200);

    // The page that asks stays Tailwind's, with the paths, the dates and the words.
    let r = navigate(&client, "/whoami").await;
    assert_eq!(r.location(), Some("/agree?next=%2Fwhoami"));
    let html = client.get("/agree").await.text();
    assert!(
        html.contains("href=\"/legal/terms\"")
            && html.contains("last updated 2026/10/01")
            && html.contains("Agree, then")
            && html.contains("<form method=\"post\" action=\"/out\">")
            && html.contains("Sign out instead"),
        "{html}"
    );
    let r = client.post_form("/out", &[]).await;
    assert_eq!(r.text(), "out");
    assert_eq!(client.get("/whoami").await.text(), "anonymous");
    db.drop().await;
}
