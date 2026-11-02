//! The mounted second-factor pages (`owt_accounts::mfa::pages`), over HTTP: enrolling,
//! the sign-in challenge, step-up with `?next=`, recovery codes, the throttle and the
//! audit events.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::extract::{Form, State};
use axum::middleware::from_fn_with_state;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use owt_accounts::mfa::pages::{MfaPages, Page, Recorder};
use owt_accounts::mfa::{Event, Mfa, RecentMfa};
use owt_accounts::session::Data;
use owt_accounts::{Accounts, Signed, store};
use owt_auth::throttle::{Budgets, Throttle};
use owt_auth::totp::{self, Secret};
use owt_web::client_ip::ClientIp;
use owt_web::session::{Session, Sessions};
use serde::Deserialize;
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
        let schema = format!("owt_mfap_{}_{}", std::process::id(), rand::random::<u32>());
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
        owt_accounts::migrations::run(&pool).await.unwrap();
        owt_accounts::migrations::complete(&pool).await.unwrap();
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

const PASSWORD: &str = "correct horse battery";

async fn account(db: &Db, name: &str) -> store::Account {
    store::create(
        &db.pool,
        store::New {
            username: name,
            email: &format!("{name}@example.com"),
            password: Some(PASSWORD),
            is_staff: false,
        },
    )
    .await
    .unwrap()
}

fn throttle(per_account: u32) -> Throttle {
    Throttle::new(Budgets {
        attempts_per_address: 1000,
        sign_ins_per_address: 1000,
        sign_ins_per_account: per_account,
        ..Budgets::default()
    })
}

/// Few codes: each costs an Argon2 hash, which is slow unoptimized.
fn mfa() -> Mfa {
    Mfa::new("Acme Health").recovery_codes(3)
}

fn step_now() -> u64 {
    totp::step_at(SystemTime::now()).unwrap()
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    mfa: Mfa,
    throttle: Arc<Throttle>,
}

#[derive(Deserialize)]
struct Login {
    login: String,
    password: String,
}

/// The app's own sign-in page: it sends a challenge to the pages' challenge.
async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session<Data>,
    Form(f): Form<Login>,
) -> String {
    match st
        .mfa
        .password_sign_in(&st.pool, &*st.throttle, &session, ip, &f.login, &f.password)
        .await
    {
        Ok(next) => format!("{next:?}"),
        Err(e) => format!("refused: {e}"),
    }
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Recorder for Log {
    fn record<'a>(
        &'a self,
        _: &'a axum::http::request::Parts,
        event: &'a Event,
    ) -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        self.0.lock().unwrap().push(event.name().to_owned());
        Box::pin(std::future::ready(Ok(())))
    }
}

impl Log {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct App {
    client: owt_test::Client,
    sessions: Sessions<Data>,
    log: Log,
}

fn app(db: &Db, per_account: u32) -> App {
    let mfa = mfa();
    let throttle = Arc::new(throttle(per_account));
    let st = AppState {
        pool: db.pool.clone(),
        mfa: mfa.clone(),
        throttle: Arc::clone(&throttle),
    };
    let log = Log::default();
    let chrome = |page: Page<'_>| -> owt_web::Result<axum::response::Response> {
        let who = page.account.map_or("nobody", |a| a.username.as_str());
        Ok(Html(format!(
            "<title>{}</title><p>who: {who}</p>{}",
            page.title, page.body
        ))
        .into_response())
    };
    let pages = MfaPages::new(db.pool.clone(), mfa.clone(), Arc::clone(&throttle), chrome)
        .audit(log.clone());
    let accounts = Accounts::new(db.pool.clone(), "/login").require_mfa::<Data>(mfa);
    let sessions = Sessions::new(
        owt_test::accounts::test_key(),
        "s",
        Duration::from_secs(3600),
        false,
    );
    let router = Router::new()
        .route("/login", post(login))
        .route(
            "/private",
            get(|Signed(a): Signed| async move { format!("private for {}", a.username) }),
        )
        .route(
            "/factors",
            get(|_: RecentMfa<900>, Signed(a): Signed| async move {
                format!("factors of {}", a.username)
            }),
        )
        .with_state(st)
        .merge(pages.routes())
        .layer(from_fn_with_state(accounts, Accounts::load::<Data>))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer));
    App {
        client: owt_test::Client::new(router),
        sessions,
        log,
    }
}

/// The text of every `<code class="owt-secret-value">` on the page.
fn secrets(html: &str) -> Vec<String> {
    html.split("<code class=\"owt-secret-value\">")
        .skip(1)
        .map(|s| s.split("</code>").next().unwrap().to_owned())
        .collect()
}

/// Make the session's proofs `secs` older.
fn age(app: &App, secs: u64) {
    let (id, mut data) = app
        .sessions
        .unseal(&app.client.cookie("s").unwrap())
        .unwrap();
    let auth = data.mfa.auth.as_mut().unwrap();
    auth.at -= secs;
    auth.mfa_at = auth.mfa_at.map(|t| t - secs);
    app.client.set_cookie("s", &app.sessions.seal(&id, &data));
}

/// Sign in with the password, enroll through the pages, and answer the codes and the
/// secret.
async fn enroll(app: &App) -> (Secret, Vec<String>) {
    let r = app
        .client
        .post_form("/login", &[("login", "ada"), ("password", PASSWORD)])
        .await;
    assert_eq!(r.text(), "Done");
    let r = app.client.get("/mfa/enroll").await;
    assert_eq!(r.status, 200);
    assert!(r.header("cache-control").unwrap().contains("no-store"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    let html = r.text();
    assert!(
        html.contains("<svg") && html.contains("<p>who: ada</p>"),
        "{html}"
    );
    let secret = Secret::from_base32(&secrets(&html)[0]).unwrap();
    // A refresh shows the same secret: the one scanned stays good.
    assert_eq!(
        secrets(&app.client.get("/mfa/enroll").await.text()),
        secrets(&html)
    );

    // A wrong code shows the same secret again, with the reason.
    let r = app
        .client
        .post_form("/mfa/enroll", &[("code", "000000")])
        .await;
    assert_eq!(r.status, 422);
    let html = r.text();
    assert!(html.contains("That code is not right"), "{html}");
    assert_eq!(
        Secret::from_base32(&secrets(&html)[0])
            .unwrap()
            .to_base32()
            .as_str(),
        secret.to_base32().as_str()
    );

    let code = totp::code(&secret, step_now());
    let r = app
        .client
        .post_form("/mfa/enroll", &[("code", &code)])
        .await;
    assert_eq!(r.status, 200);
    assert!(r.header("cache-control").unwrap().contains("no-store"));
    let codes = secrets(&r.text());
    assert_eq!(codes.len(), 3);
    assert_eq!(
        app.log.take(),
        ["mfa.totp.enrolled", "mfa.recovery_codes.issued"]
    );
    (secret, codes)
}

/// Sign out by dropping the cookie, then sign in with the password: a challenge.
async fn sign_in_again(app: &App) {
    app.client.set_cookie("s", "");
    let r = app
        .client
        .post_form("/login", &[("login", "ada"), ("password", PASSWORD)])
        .await;
    assert_eq!(r.text(), "Challenge");
}

#[tokio::test]
async fn enroll_then_the_challenge_signs_in_and_returns_to_next() {
    let db = db!();
    account(&db, "ada").await;
    let app = app(&db, 1000);
    let (secret, _) = enroll(&app).await;
    let r = app.client.get("/mfa").await;
    assert!(
        r.text().contains("<dd>Set up") && r.text().contains("<dd>3</dd>"),
        "{}",
        r.text()
    );

    sign_in_again(&app).await;
    assert_eq!(app.client.get("/private").await.status, 303);
    let r = app.client.get("/mfa/challenge?next=%2Fprivate").await;
    assert_eq!(r.status, 200);
    let html = r.text();
    assert!(html.contains("<p>who: nobody</p>"), "{html}");
    assert!(html.contains("name=\"next\" value=\"/private\""), "{html}");

    let r = app
        .client
        .post_form(
            "/mfa/challenge",
            &[("code", "000000"), ("next", "/private")],
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(app.client.get("/private").await.status, 303);

    let code = totp::code(&secret, step_now() + 1);
    let r = app
        .client
        .post_form("/mfa/challenge", &[("code", &code), ("next", "/private")])
        .await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/private"));
    assert_eq!(app.client.get("/private").await.text(), "private for ada");
    assert_eq!(app.log.take(), ["mfa.challenge.passed"]);
    db.drop().await;
}

#[tokio::test]
async fn the_challenge_without_a_pending_sign_in_goes_to_the_sign_in_page() {
    let db = db!();
    let app = app(&db, 1000);
    let r = app.client.get("/mfa/challenge?next=%2Fprivate").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/login?next=%2Fprivate"));
    db.drop().await;
}

#[tokio::test]
async fn reauth_returns_to_next_and_refuses_another_site() {
    let db = db!();
    account(&db, "ada").await;
    let app = app(&db, 1000);
    let (secret, _) = enroll(&app).await;
    assert_eq!(app.client.get("/factors").await.text(), "factors of ada");

    age(&app, 1000);
    let r = app.client.get("/factors").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/reauth?next=%2Ffactors"));
    let html = app.client.get("/reauth?next=%2Ffactors").await.text();
    assert!(
        html.contains("name=\"password\"") && html.contains("name=\"code\""),
        "{html}"
    );
    assert!(html.contains("name=\"next\" value=\"/factors\""), "{html}");
    // Another site in `next` is dropped from the form...
    for evil in [
        "https%3A%2F%2Fevil.example%2F",
        "%2F%2Fevil.example",
        "%2F%5Cevil.example",
    ] {
        let html = app.client.get(&format!("/reauth?next={evil}")).await.text();
        assert!(html.contains("name=\"next\" value=\"/\""), "{evil}: {html}");
    }

    // A wrong password with a right code proves nothing.
    let code = totp::code(&secret, step_now() + 1);
    let r = app
        .client
        .post_form(
            "/reauth",
            &[("password", "wrong"), ("code", &code), ("next", "/factors")],
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(app.client.get("/factors").await.status, 303);

    // ...and from what is posted: the right answers go home, not there.
    let r = app
        .client
        .post_form(
            "/reauth",
            &[
                ("password", PASSWORD),
                ("code", &code),
                ("next", "https://evil.example/"),
            ],
        )
        .await;
    assert_eq!(r.status, 303);
    assert_eq!(r.location(), Some("/"));
    assert_eq!(app.client.get("/factors").await.text(), "factors of ada");
    assert_eq!(app.log.take(), ["mfa.challenge.passed"]);

    age(&app, 1000);
    sqlx::query("UPDATE account_totp SET last_step = last_step - 3")
        .execute(&db.pool)
        .await
        .unwrap();
    let code = totp::code(&secret, step_now() + 1);
    let r = app
        .client
        .post_form(
            "/reauth",
            &[
                ("password", PASSWORD),
                ("code", &code),
                ("next", "/factors"),
            ],
        )
        .await;
    assert_eq!(r.location(), Some("/factors"));
    db.drop().await;
}

#[tokio::test]
async fn a_recovery_code_works_once() {
    let db = db!();
    account(&db, "ada").await;
    let app = app(&db, 1000);
    let (_, codes) = enroll(&app).await;

    sign_in_again(&app).await;
    let r = app
        .client
        .post_form("/mfa/challenge", &[("recovery_code", &codes[0])])
        .await;
    assert_eq!(r.status, 303);
    assert_eq!(app.client.get("/private").await.text(), "private for ada");
    assert_eq!(
        app.log.take(),
        ["mfa.recovery_code.used", "mfa.challenge.passed"]
    );

    sign_in_again(&app).await;
    let r = app
        .client
        .post_form("/mfa/challenge", &[("recovery_code", &codes[0])])
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(app.client.get("/private").await.status, 303);
    let r = app
        .client
        .post_form("/mfa/challenge", &[("recovery_code", &codes[1])])
        .await;
    assert_eq!(r.status, 303);
    db.drop().await;
}

#[tokio::test]
async fn code_attempts_are_throttled() {
    let db = db!();
    account(&db, "ada").await;
    // Login and second-factor answers are counted under separate keys.
    let app = app(&db, 4);
    let (secret, _) = enroll(&app).await;
    sign_in_again(&app).await;
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let r = app
            .client
            .post_form("/mfa/challenge", &[("code", "000000")])
            .await;
        statuses.push(r.status.as_u16());
    }
    assert_eq!(statuses.last(), Some(&429), "{statuses:?}");
    // The right code is not checked while the budget is spent.
    let code = totp::code(&secret, step_now() + 1);
    let r = app
        .client
        .post_form("/mfa/challenge", &[("code", &code)])
        .await;
    assert_eq!(r.status, 429);
    assert!(r.text().contains("Too many attempts"), "{}", r.text());
    assert_eq!(app.client.get("/private").await.status, 303);
    db.drop().await;
}

#[tokio::test]
async fn changing_a_factor_needs_step_up_and_reenrolling_replaces_it() {
    let db = db!();
    account(&db, "ada").await;
    let app = app(&db, 1000);
    let (secret, _) = enroll(&app).await;

    age(&app, 1000);
    for action in ["/mfa/remove", "/mfa/reenroll", "/mfa/recovery-codes"] {
        let r = app.client.post_form(action, &[]).await;
        assert_eq!(r.status, 303, "{action}");
        assert_eq!(r.location(), Some("/reauth?next=%2Fmfa"), "{action}");
    }
    let code = totp::code(&secret, step_now() + 1);
    app.client
        .post_form("/reauth", &[("password", PASSWORD), ("code", &code)])
        .await;
    app.log.take();

    let r = app.client.post_form("/mfa/recovery-codes", &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(secrets(&r.text()).len(), 3);
    assert_eq!(app.log.take(), ["mfa.recovery_codes.issued"]);

    let r = app.client.post_form("/mfa/reenroll", &[]).await;
    assert_eq!(r.location(), Some("/mfa/enroll?next=%2Fmfa"));
    assert_eq!(app.log.take(), ["mfa.totp.removed"]);
    let html = app.client.get("/mfa/enroll?next=%2Fmfa").await.text();
    let fresh = Secret::from_base32(&secrets(&html)[0]).unwrap();
    assert_ne!(fresh.to_base32().as_str(), secret.to_base32().as_str());

    // Remove: none left, and the page offers to set one up.
    let r = app
        .client
        .post_form(
            "/mfa/enroll",
            &[("code", &totp::code(&fresh, step_now())), ("next", "/mfa")],
        )
        .await;
    assert_eq!(r.status, 200);
    let r = app.client.post_form("/mfa/remove", &[]).await;
    assert_eq!(r.location(), Some("/mfa?notice=removed"));
    let html = app.client.get("/mfa?notice=removed").await.text();
    assert!(
        html.contains("Not set up") && html.contains("was removed"),
        "{html}"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_cross_origin_post_is_refused() {
    let db = db!();
    account(&db, "ada").await;
    let app = app(&db, 1000);
    app.client
        .post_form("/login", &[("login", "ada"), ("password", PASSWORD)])
        .await;
    let r = app
        .client
        .send(
            axum::http::Request::post("/mfa/remove")
                .header("sec-fetch-site", "cross-site")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 403);
    db.drop().await;
}
