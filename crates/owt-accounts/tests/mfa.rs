//! Second factors against a real Postgres (`DATABASE_URL`); skipped without it. Each
//! test takes a schema of its own, so they run in parallel and leave nothing.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::extract::{Form, State};
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use owt_accounts::mfa::{
    Answer, EventKind, Factor, Mfa, MfaError, MfaPolicy, Next, Recent, RecentMfa, SecretSealer,
    StepUp, require_recent, require_recent_mfa,
};
use owt_accounts::session::{Data, SignInRefused, Signed as _};
use owt_accounts::{Accounts, Signed, store};
use owt_auth::throttle::{Budgets, Throttle};
use owt_auth::totp::{self, Secret};
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
        let schema = format!("owt_mfa_{}_{}", std::process::id(), rand::random::<u32>());
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
const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

async fn account(db: &Db, name: &str, staff: bool) -> store::Account {
    store::create(
        &db.pool,
        store::New {
            username: name,
            email: &format!("{name}@example.com"),
            password: Some(PASSWORD),
            is_staff: staff,
        },
    )
    .await
    .unwrap()
}

fn throttle() -> Throttle {
    Throttle::new(Budgets {
        attempts_per_address: 1000,
        sign_ins_per_address: 1000,
        sign_ins_per_account: 1000,
        ..Budgets::default()
    })
}

fn step_now() -> u64 {
    totp::step_at(SystemTime::now()).unwrap()
}

/// Few codes: each costs an Argon2 hash, which is slow unoptimized.
fn mfa() -> Mfa {
    Mfa::new("Acme Health").recovery_codes(3)
}

/// Enroll an authenticator for a signed-in `account`: its secret, the recovery codes
/// and the time step the confirmation used.
async fn enroll(
    db: &Db,
    mfa: &Mfa,
    account: &store::Account,
) -> (Secret, Vec<owt_auth::recovery::Recovery>, u64) {
    let session = Session::<Data>::default();
    owt_accounts::session::sign_in(&session, account);
    let begun = mfa.begin_totp(&db.pool, account).await.unwrap();
    let secret = Secret::from_base32(&begun.secret).unwrap();
    assert!(begun.uri.starts_with("otpauth://totp/"), "{}", *begun.uri);
    assert!(begun.qr_svg.starts_with("<?xml") || begun.qr_svg.contains("<svg"));
    let step = step_now();
    let confirmed = mfa
        .confirm_totp(&db.pool, &session, account, &totp::code(&secret, step))
        .await
        .unwrap();
    assert_eq!(confirmed.next, Next::Done);
    assert!(!confirmed.recovery_codes.is_empty());
    let names: Vec<_> = confirmed
        .events
        .iter()
        .map(owt_accounts::mfa::Event::name)
        .collect();
    assert_eq!(names, ["mfa.totp.enrolled", "mfa.recovery_codes.issued"]);
    (secret, confirmed.recovery_codes, step)
}

#[tokio::test]
async fn enroll_confirm_sign_in_and_a_replayed_code_is_refused() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let mfa = mfa();
    let (secret, _, confirmed_step) = enroll(&db, &mfa, &ada).await;
    let factors = mfa.factors(&db.pool, ada.id).await.unwrap();
    assert!(factors.any() && factors.recovery_codes_left == 3);
    // Begun again once confirmed: refused.
    assert!(matches!(
        mfa.begin_totp(&db.pool, &ada).await,
        Err(MfaError::AlreadyEnrolled)
    ));

    let throttle = throttle();
    let session = Session::<Data>::default();
    // The password alone: a challenge, and nothing is signed in.
    let next = mfa
        .password_sign_in(&db.pool, &throttle, &session, IP, "ada", PASSWORD)
        .await
        .unwrap();
    assert_eq!(next, Next::Challenge);
    assert_eq!(session.read(Data::signature), None);

    // The code the confirmation used (or any earlier step) is a replay.
    let used = totp::code(&secret, confirmed_step);
    let r = mfa
        .challenge(&db.pool, &throttle, &session, IP, Answer::Totp(&used))
        .await;
    assert!(matches!(r, Err(MfaError::Invalid)), "{r:?}");
    assert_eq!(session.read(Data::signature), None);
    // The next step's code passes (the window takes one step ahead).
    let code = totp::code(&secret, step_now() + 1);
    let (who, events) = mfa
        .challenge(&db.pool, &throttle, &session, IP, Answer::Totp(&code))
        .await
        .unwrap();
    assert_eq!(who.id, ada.id);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::ChallengePassed(Factor::Totp));
    assert_eq!(
        session.read(Data::signature).map(|s| s.account),
        Some(ada.id)
    );
    assert!(session.read(|d| d.mfa.pending).is_none());

    // The same code again, on a new sign-in: refused.
    let again = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &throttle, &again, IP, "ada", PASSWORD)
        .await
        .unwrap();
    let r = mfa
        .challenge(&db.pool, &throttle, &again, IP, Answer::Totp(&code))
        .await;
    assert!(matches!(r, Err(MfaError::Invalid)), "{r:?}");
    assert_eq!(again.read(Data::signature), None);

    // A wrong password never reaches the second factor.
    let r = mfa
        .password_sign_in(
            &db.pool,
            &throttle,
            &Session::<Data>::default(),
            IP,
            "ada",
            "no",
        )
        .await;
    assert!(matches!(r, Err(SignInRefused::Mismatch)));
    db.drop().await;
}

#[tokio::test]
async fn a_recovery_code_works_once() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let mfa = mfa().recovery_codes(7);
    let (_, codes, _) = enroll(&db, &mfa, &ada).await;
    let throttle = throttle();

    let session = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &throttle, &session, IP, "ada", PASSWORD)
        .await
        .unwrap();
    // As typed: lower case, spaces for the hyphen.
    let typed = codes[3].code.to_lowercase().replace('-', " ");
    let (_, events) = mfa
        .challenge(&db.pool, &throttle, &session, IP, Answer::Recovery(&typed))
        .await
        .unwrap();
    assert_eq!(events[0].kind, EventKind::RecoveryCodeUsed { remaining: 6 });
    assert_eq!(events[0].name(), "mfa.recovery_code.used");
    assert!(session.read(Data::signature).is_some());
    assert_eq!(
        mfa.factors(&db.pool, ada.id)
            .await
            .unwrap()
            .recovery_codes_left,
        6
    );

    // The same code on another sign-in: refused. Another code: fine.
    let again = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &throttle, &again, IP, "ada", PASSWORD)
        .await
        .unwrap();
    let r = mfa
        .challenge(
            &db.pool,
            &throttle,
            &again,
            IP,
            Answer::Recovery(&codes[3].code),
        )
        .await;
    assert!(matches!(r, Err(MfaError::Invalid)), "{r:?}");
    assert!(
        mfa.challenge(
            &db.pool,
            &throttle,
            &again,
            IP,
            Answer::Recovery(&codes[4].code)
        )
        .await
        .is_ok()
    );

    // Two requests racing with one code: exactly one passes.
    let (a, b) = (Session::<Data>::default(), Session::<Data>::default());
    for s in [&a, &b] {
        mfa.password_sign_in(&db.pool, &throttle, s, IP, "ada", PASSWORD)
            .await
            .unwrap();
    }
    let (ra, rb) = tokio::join!(
        mfa.challenge(
            &db.pool,
            &throttle,
            &a,
            IP,
            Answer::Recovery(&codes[5].code)
        ),
        mfa.challenge(
            &db.pool,
            &throttle,
            &b,
            IP,
            Answer::Recovery(&codes[5].code)
        ),
    );
    assert_eq!(
        usize::from(ra.is_ok()) + usize::from(rb.is_ok()),
        1,
        "{ra:?} {rb:?}"
    );

    // New codes replace the rest.
    let (fresh, event) = mfa.regenerate_recovery_codes(&db.pool, &ada).await.unwrap();
    assert_eq!(fresh.len(), 7);
    assert_eq!(event.name(), "mfa.recovery_codes.issued");
    let session = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &throttle, &session, IP, "ada", PASSWORD)
        .await
        .unwrap();
    let r = mfa
        .challenge(
            &db.pool,
            &throttle,
            &session,
            IP,
            Answer::Recovery(&codes[6].code),
        )
        .await;
    assert!(matches!(r, Err(MfaError::Invalid)), "an old code is gone");
    db.drop().await;
}

#[tokio::test]
async fn attempts_are_throttled_and_the_right_code_is_not_checked_once_spent() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let mfa = mfa();
    let (secret, _, _) = enroll(&db, &mfa, &ada).await;
    let throttle = Throttle::new(Budgets {
        attempts_per_address: 1000,
        sign_ins_per_address: 1000,
        sign_ins_per_account: 3,
        ..Budgets::default()
    });
    let session = Session::<Data>::default();
    // Sign-in spends "ada"'s budget; the second factor has a budget of its own.
    mfa.password_sign_in(&db.pool, &throttle, &session, IP, "ada", PASSWORD)
        .await
        .unwrap();
    for _ in 0..3 {
        let r = mfa
            .challenge(&db.pool, &throttle, &session, IP, Answer::Totp("000000"))
            .await;
        assert!(matches!(r, Err(MfaError::Invalid)));
    }
    let right = totp::code(&secret, step_now() + 1);
    let r = mfa
        .challenge(&db.pool, &throttle, &session, IP, Answer::Totp(&right))
        .await;
    assert!(matches!(r, Err(MfaError::Throttled)), "{r:?}");
    assert_eq!(r.unwrap_err().status(), 429);
    assert_eq!(session.read(Data::signature), None);
    db.drop().await;
}

#[tokio::test]
async fn a_required_policy_sends_an_account_without_a_factor_to_enrollment_and_no_further() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let boss = account(&db, "boss", true).await;
    let mfa = mfa().policy(MfaPolicy::when(|a| a.is_staff));
    let throttle = throttle();

    // Ada is not staff: optional for her, signed in at once, with the time recorded.
    let s = Session::<Data>::default();
    let next = mfa
        .password_sign_in(&db.pool, &throttle, &s, IP, "ada", PASSWORD)
        .await
        .unwrap();
    assert_eq!(next, Next::Done);
    assert!(require_recent(&s, Duration::from_secs(60)).is_ok());
    assert_eq!(
        require_recent_mfa(&s, Duration::from_secs(60)),
        Err(StepUp::SecondFactor)
    );
    let _ = ada;

    // The boss must enroll: pending, not signed in.
    let s = Session::<Data>::default();
    let next = mfa
        .password_sign_in(&db.pool, &throttle, &s, IP, "boss", PASSWORD)
        .await
        .unwrap();
    assert_eq!(next, Next::Enroll);
    assert_eq!(s.read(Data::signature), None);
    let (who, kind) = mfa.pending_account(&db.pool, &s).await.unwrap().unwrap();
    assert_eq!((who.id, kind), (boss.id, owt_accounts::mfa::Kind::Enroll));
    // A challenge is not an enrollment.
    let r = mfa
        .challenge(&db.pool, &throttle, &s, IP, Answer::Totp("123456"))
        .await;
    assert!(matches!(r, Err(MfaError::NoChallenge)), "{r:?}");

    let begun = mfa.begin_totp(&db.pool, &who).await.unwrap();
    let secret = Secret::from_base32(&begun.secret).unwrap();
    // A wrong first code leaves it pending.
    let r = mfa.confirm_totp(&db.pool, &s, &who, "000000").await;
    assert!(matches!(r, Err(MfaError::Invalid)), "{r:?}");
    assert_eq!(s.read(Data::signature), None);
    let done = mfa
        .confirm_totp(&db.pool, &s, &who, &totp::code(&secret, step_now()))
        .await
        .unwrap();
    assert_eq!(done.next, Next::Done);
    assert_eq!(s.read(Data::signature).map(|x| x.account), Some(boss.id));
    assert!(s.read(|d| d.mfa.pending).is_none());
    assert!(require_recent_mfa(&s, Duration::from_secs(60)).is_ok());

    // Someone else's session cannot confirm an account that is not theirs.
    let stranger = Session::<Data>::default();
    let r = mfa.confirm_totp(&db.pool, &stranger, &boss, "123456").await;
    assert!(matches!(r, Err(MfaError::NoChallenge)), "{r:?}");
    db.drop().await;
}

#[tokio::test]
async fn a_pending_enrollment_expires() {
    let db = db!();
    account(&db, "boss", true).await;
    let mfa = mfa()
        .policy(MfaPolicy::Required)
        .pending_ttl(Duration::from_secs(60));
    let s = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &throttle(), &s, IP, "boss", PASSWORD)
        .await
        .unwrap();
    // Age the pending sign-in past its lifetime.
    s.update(|d| d.mfa.pending.as_mut().unwrap().at -= 120);
    assert!(mfa.pending_account(&db.pool, &s).await.unwrap().is_none());
    db.drop().await;
}

#[tokio::test]
async fn the_last_factor_cannot_be_removed_when_the_policy_requires_one() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let staff = account(&db, "staff", true).await;
    let mfa = mfa().policy(MfaPolicy::when(|a| a.is_staff));
    for a in [&ada, &staff] {
        enroll(&db, &mfa, a).await;
    }
    let r = mfa.remove_totp(&db.pool, &staff).await;
    assert!(matches!(r, Err(MfaError::LastFactor)), "{r:?}");
    assert!(mfa.factors(&db.pool, staff.id).await.unwrap().any());

    // Ada may: the event names it, her codes go with it, and no session is touched.
    let event = mfa.remove_totp(&db.pool, &ada).await.unwrap();
    assert_eq!(event.name(), "mfa.totp.removed");
    assert_eq!(event.kind, EventKind::Removed(Factor::Totp));
    let f = mfa.factors(&db.pool, ada.id).await.unwrap();
    assert!(!f.any() && f.recovery_codes_left == 0);
    let epoch = store::by_id(&db.pool, ada.id)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    assert_eq!(epoch, ada.session_epoch);
    assert!(matches!(
        mfa.remove_totp(&db.pool, &ada).await,
        Err(MfaError::NotEnrolled)
    ));
    // Signing in is back to a password.
    let s = Session::<Data>::default();
    assert_eq!(
        mfa.password_sign_in(&db.pool, &throttle(), &s, IP, "ada", PASSWORD)
            .await
            .unwrap(),
        Next::Done
    );
    db.drop().await;
}

/// A sealer that is not the identity: the stored bytes are not the secret.
struct Masked;

impl SecretSealer for Masked {
    fn seal(&self, plaintext: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = plaintext.to_vec();
        out.extend_from_slice(context);
        Ok(out.iter().map(|b| b ^ 0x5a).collect())
    }

    fn open(&self, sealed: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>> {
        let plain: Vec<u8> = sealed.iter().map(|b| b ^ 0x5a).collect();
        let n = plain
            .len()
            .checked_sub(context.len())
            .ok_or_else(|| anyhow::anyhow!("short"))?;
        anyhow::ensure!(plain[n..] == *context, "sealed for another row");
        Ok(plain[..n].to_vec())
    }
}

#[tokio::test]
async fn the_secret_is_stored_as_the_sealer_returns_it() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let bob = account(&db, "bob", false).await;
    let mfa = mfa().sealer(Masked);
    let (secret, _, _) = enroll(&db, &mfa, &ada).await;
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT secret FROM account_totp WHERE account_id = $1")
            .bind(ada.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_ne!(stored, secret.as_bytes());
    assert!(!stored.windows(20).any(|w| w == secret.as_bytes()));
    // It signs in, so it opens.
    let s = Session::<Data>::default();
    let t = throttle();
    mfa.password_sign_in(&db.pool, &t, &s, IP, "ada", PASSWORD)
        .await
        .unwrap();
    mfa.challenge(
        &db.pool,
        &t,
        &s,
        IP,
        Answer::Totp(&totp::code(&secret, step_now() + 1)),
    )
    .await
    .unwrap();
    // Pasted into another account's row, it does not open.
    enroll(&db, &mfa, &bob).await;
    sqlx::query(
        "UPDATE account_totp SET secret = (SELECT secret FROM account_totp WHERE account_id = $1)
         WHERE account_id = $2",
    )
    .bind(ada.id)
    .bind(bob.id)
    .execute(&db.pool)
    .await
    .unwrap();
    let s = Session::<Data>::default();
    mfa.password_sign_in(&db.pool, &t, &s, IP, "bob", PASSWORD)
        .await
        .unwrap();
    let r = mfa
        .challenge(
            &db.pool,
            &t,
            &s,
            IP,
            Answer::Totp(&totp::code(&secret, step_now())),
        )
        .await;
    assert!(matches!(r, Err(MfaError::Fault(_))), "{r:?}");
    db.drop().await;
}

// --- Over HTTP: the pending state grants nothing, and step-up redirects.

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

#[derive(Deserialize)]
struct Code {
    totp: Option<String>,
    recovery: Option<String>,
}

async fn login(State(st): State<AppState>, session: Session<Data>, Form(f): Form<Login>) -> String {
    match st
        .mfa
        .password_sign_in(&st.pool, &*st.throttle, &session, IP, &f.login, &f.password)
        .await
    {
        Ok(next) => format!("{next:?}"),
        Err(e) => format!("refused: {e}"),
    }
}

async fn challenge(
    State(st): State<AppState>,
    session: Session<Data>,
    Form(f): Form<Code>,
) -> String {
    let answer = match (&f.totp, &f.recovery) {
        (Some(c), _) => Answer::Totp(c),
        (_, Some(c)) => Answer::Recovery(c),
        _ => return "nothing".into(),
    };
    match st
        .mfa
        .challenge(&st.pool, &*st.throttle, &session, IP, answer)
        .await
    {
        Ok((a, _)) => format!("signed in as {}", a.username),
        Err(e) => format!("refused: {e}"),
    }
}

async fn reauth(
    State(st): State<AppState>,
    session: Session<Data>,
    Signed(me): Signed,
    Form(f): Form<Login>,
) -> String {
    match st
        .mfa
        .begin_reauth(
            &st.pool,
            &*st.throttle,
            &session,
            IP,
            &me,
            Some(&f.password),
        )
        .await
    {
        Ok(next) => format!("{next:?}"),
        Err(e) => format!("refused: {e}"),
    }
}

fn http_app(db: &Db, sessions: &Sessions<Data>, mfa: Mfa) -> Router {
    let st = AppState {
        pool: db.pool.clone(),
        mfa,
        throttle: Arc::new(throttle()),
    };
    let accounts = Accounts::new(db.pool.clone(), "/login").reauth_at("/reauth");
    Router::new()
        .route("/login", post(login))
        .route("/challenge", post(challenge))
        .route("/reauth", post(reauth))
        .route("/private", get(|Signed(a): Signed| async move { format!("private for {}", a.username) }))
        .route("/export", get(|_: Recent<60>, Signed(a): Signed| async move { format!("export for {}", a.username) }))
        .route("/factors", get(|_: RecentMfa<60>, Signed(a): Signed| async move { format!("factors of {}", a.username) }))
        .with_state(st)
        .layer(from_fn_with_state(accounts, Accounts::load::<Data>))
        .layer(from_fn_with_state(sessions.clone(), Sessions::layer))
}

fn sessions() -> Sessions<Data> {
    Sessions::new(
        owt_test::accounts::test_key(),
        "s",
        Duration::from_secs(3600),
        false,
    )
}

#[tokio::test]
async fn the_pending_sign_in_is_not_a_session_the_extractors_accept() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let mfa = mfa();
    let (secret, _, _) = enroll(&db, &mfa, &ada).await;
    let sessions = sessions();
    let client = owt_test::Client::new(http_app(&db, &sessions, mfa));

    let r = client
        .post_form("/login", &[("login", "ada"), ("password", PASSWORD)])
        .await;
    assert_eq!(r.text(), "Challenge");
    // The cookie holds the pending sign-in, and no signature.
    let (_, data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    assert!(data.mfa.pending.is_some() && data.signature().is_none());
    for path in ["/private", "/export", "/factors"] {
        let r = client.get(path).await;
        assert_eq!(r.status, 303, "{path}");
        assert!(r.location().unwrap().starts_with("/login?next="), "{path}");
    }
    // A wrong code leaves it so.
    let r = client.post_form("/challenge", &[("totp", "000000")]).await;
    assert!(r.text().starts_with("refused"), "{}", r.text());
    assert_eq!(client.get("/private").await.status, 303);

    let r = client
        .post_form(
            "/challenge",
            &[("totp", &totp::code(&secret, step_now() + 1))],
        )
        .await;
    assert_eq!(r.text(), "signed in as ada");
    assert_eq!(client.get("/private").await.text(), "private for ada");
    // The session id changed at sign-in.
    let (_, after) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
    assert!(after.mfa.pending.is_none());
    db.drop().await;
}

#[tokio::test]
async fn step_up_expires_and_a_reauthentication_renews_it() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let mfa = mfa();
    let (secret, _, _) = enroll(&db, &mfa, &ada).await;
    let sessions = sessions();
    let client = owt_test::Client::new(http_app(&db, &sessions, mfa));

    client
        .post_form("/login", &[("login", "ada"), ("password", PASSWORD)])
        .await;
    let step = step_now() + 1;
    let r = client
        .post_form("/challenge", &[("totp", &totp::code(&secret, step))])
        .await;
    assert_eq!(r.text(), "signed in as ada");
    assert_eq!(client.get("/export").await.text(), "export for ada");
    assert_eq!(client.get("/factors").await.text(), "factors of ada");

    // Two minutes on: signed in still, but the proof is stale.
    let age = |secs: u64| {
        let (id, mut data) = sessions.unseal(&client.cookie("s").unwrap()).unwrap();
        let auth = data.mfa.auth.as_mut().unwrap();
        auth.at -= secs;
        auth.mfa_at = auth.mfa_at.map(|t| t - secs);
        client.set_cookie("s", &sessions.seal(&id, &data));
    };
    age(120);
    assert_eq!(client.get("/private").await.text(), "private for ada");
    for path in ["/export", "/factors"] {
        let r = client.get(path).await;
        assert_eq!(r.status, 303, "{path}");
        assert_eq!(
            r.location().unwrap(),
            format!("/reauth?next=%2F{}", &path[1..])
        );
    }

    // Password, then the second factor.
    let r = client
        .post_form("/reauth", &[("login", ""), ("password", "wrong")])
        .await;
    assert!(r.text().starts_with("refused"), "{}", r.text());
    assert_eq!(client.get("/export").await.status, 303);
    let r = client
        .post_form("/reauth", &[("login", ""), ("password", PASSWORD)])
        .await;
    assert_eq!(r.text(), "Challenge");
    assert_eq!(
        client.get("/export").await.status,
        303,
        "pending proves nothing"
    );
    // Half a minute has passed for the person: the code for the next step is new.
    sqlx::query("UPDATE account_totp SET last_step = last_step - 3")
        .execute(&db.pool)
        .await
        .unwrap();
    let r = client
        .post_form(
            "/challenge",
            &[("totp", &totp::code(&secret, step_now() + 1))],
        )
        .await;
    assert_eq!(r.text(), "signed in as ada");
    assert_eq!(client.get("/export").await.text(), "export for ada");
    assert_eq!(client.get("/factors").await.text(), "factors of ada");
    db.drop().await;
}

#[tokio::test]
async fn step_up_needs_a_record_for_this_signature() {
    let db = db!();
    let ada = account(&db, "ada", false).await;
    let session = Session::<Data>::default();
    let max = Duration::from_secs(300);
    assert_eq!(require_recent(&session, max), Err(StepUp::NotSignedIn));
    // A sign-in that records nothing (a link, a provider) is Unrecorded until stamped.
    owt_accounts::session::sign_in(&session, &ada);
    assert_eq!(require_recent(&session, max), Err(StepUp::Unrecorded));
    owt_accounts::mfa::mark_authenticated(&session, &ada);
    assert!(require_recent(&session, max).is_ok());
    // A record for another account counts for nothing.
    let bob = account(&db, "bob", false).await;
    owt_accounts::session::sign_in(&session, &bob);
    assert_eq!(require_recent(&session, max), Err(StepUp::Unrecorded));
    // A later moment, and a time in the future, are both stale.
    owt_accounts::mfa::mark_authenticated(&session, &bob);
    let later = SystemTime::now() + Duration::from_secs(301);
    assert!(matches!(
        owt_accounts::mfa::require_recent_at(&session, max, later),
        Err(StepUp::Stale { max_age: 300, .. })
    ));
    let before = SystemTime::now() - Duration::from_secs(3600);
    assert!(owt_accounts::mfa::require_recent_at(&session, max, before).is_err());
    db.drop().await;
}
