# owt-stack

An opinionated stack used as a base for One Way Tek projects:
Rust, Axum, SQLx on Postgres, Redis, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; flash messages; the request as page chrome reads it; htmx fragments at their own URLs; fingerprinted static URLs; `Cache-Control` as a typed policy; security headers and a nonce-based content security policy; a response deadline and body cap; safe `?next=` redirects; the client's address behind proxies; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers; shared page components (alerts, form fields, pagination, an error body) styled by semantic tokens |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); a Redis read-through cache that never fails a request (feature `redis`); background jobs on every replica, on one at a time or on a Redis lease's holder (feature `redis`); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | sign-in throttling by address and account; Argon2id hashing off the runtime with bounded concurrency and a decoy check for unknown accounts; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-accounts` | the `accounts` table and its migration; create and authenticate (decoy check, rehash, username or email); sessions revoked by epoch (sign out everywhere, password change, deactivation); the `Signed`, `Staff` and `Maybe` extractors over one load per request; provider identities linked to accounts; one-time sign-in links |
| `owt-change` | change requests from a site's own pages: a floating "Request a change" button for signed-in admins, and the endpoint that forwards what they ask, with who asked, to a work tracker under the site's key |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar; the router on an ephemeral port; golden-page snapshots; page/fragment agreement; the browser fetches nothing from another origin, and vendored files match their pins |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow on ARC: the app's `just check`, or built-in fmt, audit, sqlx metadata, clippy and tests; the stylesheet build |
| `.github/workflows/release-please.yml`, `conventional-commits.yml` | this repository's releases: Conventional Commits checked on every pull request, versions and the changelog by release-please |
| `.github/workflows/release.yml` | reusable releases from conventional commits: stable on `main`, prereleases on `rc`, optional version write-back and changelog |
| `.github/workflows/image.yml` | reusable image build for a released tag, pushed to ghcr with the channel's floating tags |
| `.github/workflows/promote-rc.yml` | reusable rc channel: merge a PR (or `main`) into `rc` and start its prerelease |
| `templates/justfile`, `templates/compose.yaml` | the commands every app answers to (`just check`, `just db`, `just dev`), and Postgres and Redis for them |
| `templates/vendor-js` | downloads the vendored browser files `vendor.pins` lists, refusing any hash mismatch |
| `templates/Dockerfile` | cargo-chef, an npm Tailwind stage, distroless non-root runtime (with `templates/dockerignore`) |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger, Service, Route, CNPG Postgres over verified TLS with nightly volume-snapshot backups and their pruning, NetworkPolicies |
| `templates/openshift/restore-drill.sh` | proves a backup restores, on throwaway clusters |
| `templates/openshift/monitoring.yaml` | Prometheus scraping for the app's metrics and its Postgres (needs `monitoring-edit`) |
| `tailwind/owt.css` | font stacks, htmx state variants (`htmx-request:opacity-50`), and the `owt-*` classes the shared components and the change-request button use |

Every Rust example below is compiled by `cargo test` (the `readme` crate includes this
file as its docs), so an API change that breaks these instructions fails CI.

## Adding it to an app

<!-- x-release-please-start-version -->
```toml
[dependencies]
owt-web = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
owt-runtime = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
# As needed:
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
owt-bus = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
owt-accounts = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
owt-change = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }

# The app's own: static files, request logs, compression.
tower-http = { version = "0.7", features = ["fs", "trace", "compression-gzip", "compression-br"] }

[dev-dependencies]
owt-test = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.4.1" }
```
<!-- x-release-please-end -->

`owt-runtime`'s features: `metrics` (default) for Prometheus, `otel` for trace export,
`redis` for leases and leased jobs.

A shared crate is only shared while the majors agree: an app that names `axum`, `sqlx`,
`askama` or `redis` directly must use the major in this workspace's `Cargo.toml`.

An app that names `sqlx` uses its `tls-rustls-aws-lc-rs` feature, not `tls-rustls`
(which means ring). With both rustls backends compiled in (or none), rustls cannot pick
one, and the first `rediss://` connection would panic; `Bus::redis` installs aws-lc-rs
as the process's provider if none is set, and an app that connects to a `rediss://`
Redis before or without the bus (a lease's `ConnectionManager`, say) calls
`owt_bus::ensure_crypto_provider()` first.

**Developing against a local checkout:** patch the git source in the app's
`.cargo/config.toml` (not committed) instead of editing `Cargo.toml`:

```toml
[patch."https://github.com/onewaytek/owt-stack"]
owt-web = { path = "../owt-stack/crates/owt-web" }
owt-runtime = { path = "../owt-stack/crates/owt-runtime" }
```

**The repository is public:** `cargo fetch` needs no token in CI, in image builds or
on a workstation, and an app that still passes an `OWT_STACK_TOKEN` secret to the
reusable workflows can drop it. The crates are not on crates.io; the tagged git
source above is the way to depend on them, and the lockfile pins the commit.

## Wiring an app

`main` reads its configuration, starts logging, connects and migrates, and serves until
SIGTERM. A variable that is set but malformed stops startup with its name.

```rust,no_run
use owt_runtime::{db::PoolConfig, env, logging, serve};

// In the app: `sqlx::migrate!()`.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator::DEFAULT;
# fn router(_: sqlx::PgPool) -> axum::Router { axum::Router::new() }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _logging = logging::init(&logging::Options {
        service: "myapp",
        default_filter: "myapp=info,tower_http=info".into(),
        json: !env::flag("DEBUG", false)?,
        otel_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT"),
    });
    let pool = PoolConfig { max: env::parse_or("DB_POOL_MAX", 10)?, ..PoolConfig::default() }
        .connect(&env::required("DATABASE_URL")?)
        .await?;
    // Replicas starting together migrate once; the rest wait on the lock.
    owt_runtime::db::migrate_locked(&pool, &MIGRATOR, 8_531_207).await?;
    let bind = env::var("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8000".into());
    serve::serve(&bind, router(pool), serve::shutdown_signal()).await
}
```

The router composes the layers. Order matters: a layer added later wraps the ones
before it, so cross-origin refusal runs before the session is opened, and the outer
headers see every response.

```rust
use axum::{Router, middleware::{from_fn, from_fn_with_state}, routing::get};
use owt_web::{assets::Assets, csrf::CrossOrigin, headers::{self, Csp}, limits::Limits};
use owt_web::session::{Presented, Sessions, Verdict};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SessionData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
    /// The account's epoch at sign-in; bumping the account's signs it out everywhere.
    #[serde(default)]
    pub epoch: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<owt_web::flash::Flash>,
}

/// One indexed read: `SELECT epoch FROM account WHERE id = $1`. `None`: no such
/// account any more.
async fn account_epoch(pool: &sqlx::PgPool, user_id: i64) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT epoch FROM account WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub fn router(key: cookie::Key, assets: Assets, trusted: &[String], pool: sqlx::PgPool) -> Router {
    // `__Host-`: browsers refuse a copy set over plain HTTP or by a sibling subdomain.
    let sessions = Sessions::<SessionData>::new(key, "__Host-session", Duration::from_secs(14 * 86_400), true)
        .validate_with(move |s: Presented<SessionData>| {
            let pool = pool.clone();
            async move {
                let Some(user_id) = s.data.user_id else { return Verdict::Valid };
                match account_epoch(&pool, user_id).await {
                    // Valid, or Revoked: signed out everywhere, or the account is gone.
                    Ok(epoch) => (epoch == Some(s.data.epoch)).into(),
                    // An outage must neither admit a revoked session nor sign everyone out.
                    Err(_) => Verdict::Unknown,
                }
            }
        });
    // Enforce once the browser console is quiet.
    let csp = Csp::new().report_only(true);
    let routes = Router::new().route("/healthz", get(owt_web::healthz));
    // ... the app's routes ...
    let pages = Limits::default()
        .apply(routes)
        .layer(from_fn_with_state(sessions, Sessions::<SessionData>::layer))
        .layer(from_fn_with_state(CrossOrigin::new().trust(trusted), CrossOrigin::layer));
    Router::new()
        .nest(
            "/static",
            Router::new()
                .fallback_service(tower_http::services::ServeDir::new(assets.dir()))
                .layer(from_fn_with_state(assets.clone(), Assets::cache_policy)),
        )
        .merge(pages)
        .layer(from_fn_with_state(csp, Csp::layer))
        .layer(from_fn(headers::private_by_default))
        .layer(from_fn(headers::security))
}
```

Templates put the request's nonce on inline scripts: take `owt_web::headers::Nonce` in
the handler and write `<script nonce="{{ nonce }}">`.

- **Session key:** `owt_web::session::key_from_base64(&env::required("SESSION_SECRET")?)`,
  at least 64 random bytes. Changing it signs everyone out.
- **Static URLs:** `Assets::new("static", "/static").watch(cfg!(debug_assertions))`;
  templates call a function that returns `assets.url("css/app.css")`, which carries
  the content hash and is served `immutable`.
- **Metrics:** `owt_runtime::metrics::install(&[], describe)` once, the
  `metrics::http` layer with an `HttpTimer("myapp_http_request_seconds")` on the routed
  router, and `metrics::serve` on its own listener (port 9464 in the OpenShift
  template), never through the Route.

### Handlers, errors and pages

Handlers return `owt_web::Result`. `NotFound` and internal errors carry a marker that
the `error::error_pages` middleware swaps for the app's own pages; database errors are
logged and never shown. `Error::unavailable(..)` is the 503 for a request the app
could not answer *for now* (a dependency down), distinct from a 500 fault in its code;
it is marked for the app's page too and carries `Retry-After`.
An app may keep its own error enum in its domain's words and convert it with
`impl From<AppError> for owt_web::Error`.

A page's context carries the request (`RequestInfo`) and the flash messages, and
derefs to the request, so templates write `layout.path` and `layout.url_with(..)` (a
link to this page with one query parameter changed, the rest kept).

```rust
use askama::Template;
use axum::response::Html;
use owt_web::{flash::{Flash, HasFlashes, Level}, request::RequestInfo, session::Session};
# #[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
# pub struct SessionData { messages: Vec<Flash> }

impl HasFlashes for SessionData {
    fn flashes(&self) -> &[Flash] { &self.messages }
    fn flashes_mut(&mut self) -> &mut Vec<Flash> { &mut self.messages }
}

pub struct Layout {
    pub request: RequestInfo,
    pub messages: Vec<Flash>,
}

impl std::ops::Deref for Layout {
    type Target = RequestInfo;
    fn deref(&self) -> &RequestInfo { &self.request }
}

#[derive(Template)]
#[template(ext = "html", source = r#"
{%- for m in layout.messages %}<p class="{{ m.level().as_str() }}">{{ m.text() }}</p>{% endfor -%}
<a href="{{ layout.url_with("page", Some("2")) }}">Next</a>"#)]
struct Games { layout: Layout }

async fn games(request: RequestInfo, session: Session<SessionData>) -> owt_web::Result<Html<String>> {
    owt_web::render(&Games { layout: Layout { request, messages: session.take_flashes() } })
}

async fn save(session: Session<SessionData>) -> axum::response::Redirect {
    session.flash(Level::Success, "Saved.");
    axum::response::Redirect::to("/games/")
}
```

### htmx fragments

A fragment lives at a URL of its own, never the page's URL negotiated on
`HX-Request`: a CDN that ignores `Vary` (Cloudflare) would serve one variant for the
other. Render both from one loader, and have the page `{% include %}` the fragment's
partial. The fragment handler re-paths its request to the page once
(`request.for_page("/map")`) and renders from that: the links the loader builds
(pagination, `url_with`), navigation's "you are here" and the URL pushed to history
then all name the page, never the bare fragment, and `Fragment::page` takes that
re-pathed request so there is no second copy of the page's URL to keep in step.

```rust
use askama::Template;
use axum::{http::HeaderValue, response::{IntoResponse, Response}};
use owt_web::{fragment::{Fragment, reselect}, request::RequestInfo};

#[derive(Template)]
#[template(ext = "html", source = r#"<section id="viewport">{{ x }},{{ y }}</section>"#)]
struct Viewport { x: i64, y: i64 }

/// The one loader: `request` is the page's, whichever URL asked.
fn viewport(request: &RequestInfo) -> Viewport {
    let at = |k| request.query_value(k).and_then(|v| v.parse().ok()).unwrap_or(0);
    Viewport { x: at("x"), y: at("y") }
}

/// `GET /map?x=..&y=..`: the whole page.
async fn page(request: RequestInfo) -> owt_web::Result<Response> {
    let body = owt_web::render(&viewport(&request))?;
    // A stale client that htmx-requests this URL swaps only #viewport out of it.
    Ok(([reselect("#viewport")], body).into_response())
}

/// `GET /map/view?x=..&y=..`: the fragment, recorded in history as `/map?x=..&y=..`.
async fn view(request: RequestInfo) -> owt_web::Result<Fragment> {
    let request = request.for_page("/map");
    Fragment::render(&viewport(&request), HeaderValue::from_static("no-store"))?.page(&request)
}
```

`Fragment::page` pushes a history entry, for a step a person would want Back to undo.
A fragment fetched while someone types or adjusts a filter uses `Fragment::replace`
with the same re-pathed request, so the address bar follows the typing while Back
leaves the page rather than retracing every request. htmx reads these headers before
the element's `hx-push-url` and `hx-replace-url`, so the choice is the handler's.

The fragment's cache policy is a required argument; use `no-store` for anything that
differs per person. A response that sets the session cookie is `no-store` whatever it
asked for, so a public fragment never hands one person's session to a cache. Test that page and fragment agree with `owt_test::fragment`
(below).

### Caching

Every response falls in one cache class, chosen with `CachePolicy` rather than written
as a string. A public policy never goes on per-person content or on a response that
sets a cookie: the edge would serve it to everyone.

```rust,no_run
use std::time::{Duration, SystemTime};
use axum::response::{Html, IntoResponse, Response};
use owt_runtime::cache::{Cache, Expiry, Options};
use owt_web::cache::CachePolicy;

# fn render(_: &[u8]) -> String { String::new() }
# fn compute() -> Vec<u8> { Vec::new() }
/// A world map that changes only when the simulation ticks.
async fn map(cache: Cache, next_tick: SystemTime) -> Response {
    let key = "map:v3:world-7";
    let bytes = match cache.get(key).await {
        Some(hit) => hit,
        None => {
            let fresh = compute();
            // Never awaited: the response isn't held up by the cache write.
            cache.set_detached(vec![(key.into(), fresh.clone())], Expiry::At(next_tick));
            fresh
        }
    };
    let until = next_tick.duration_since(SystemTime::now()).unwrap_or_default();
    // The edge keeps it to the tick; browsers a minute at most.
    (CachePolicy::public_until(until, Duration::from_secs(60)), Html(render(&bytes))).into_response()
}

# async fn demo() -> anyhow::Result<()> {
// At startup: connects in the background; unset REDIS_URL means no cache at all.
let cache = match owt_runtime::env::var("REDIS_URL") {
    Some(url) => Cache::connect(&url, "myapp", Options::default())?,
    None => Cache::disabled(),
};
# let _ = cache; Ok(()) }
```

- **Policies:** `immutable()` for fingerprinted bytes, `public(d)` with `.edge(s_maxage)`
  and `.stale_while_revalidate(w)`, `public_until(remaining, browser_cap)`, and
  `no_store()`. A policy is a response part, and `Fragment::new` takes one through
  `.into()`.
- **Keys never need deleting:** a key carries what produced the value (a fingerprint,
  a format version: `Expiry::Lru`) or expires when the value stops being true
  (`Expiry::At`); `Expiry::For` is for values that may merely be a little stale. A
  Redis that is absent, slow (over 100 ms) or failing is a miss.

### Authentication

```rust,no_run
# async fn demo(
#     headers: axum::http::HeaderMap, peer: std::net::IpAddr, account: &str, given: &str,
#     stored_hash: Option<&str>, next: Option<&str>,
#     pending: owt_auth::oauth::Pending, state: &str, code: &str,
# ) -> anyhow::Result<()> {
use owt_auth::{jwt, oauth, password, throttle::Throttle};
use owt_web::{client_ip::Source, redirect};

// Passwords. Throttle first: a sign-in over budget checks no password. The address
// is the client's as the proxies in front of the app report it (one: the router).
let throttle = Throttle::default(); // in the app's state, behind an Arc
let ip = Source::ForwardedFor { proxies: 1 }.client_ip(&headers, peer);
if !throttle.sign_in(ip, account) {
    return Ok(()); // answer 429
}
// Argon2id on the blocking pool, a bounded number at once. An unknown account
// (`None`) costs a real check too, so timing does not tell which accounts exist.
if password::verify_or_decoy(given, stored_hash).await {
    // A hash made with weaker parameters than today's: store a fresh one.
    if stored_hash.is_some_and(password::needs_rehash) {
        let _new_hash = password::hash(given).await?;
    }
    // Then `session.cycle_id()` before storing who signed in: a session id fixed
    // on this browser by someone else must not become a signed-in one.
    let _to = redirect::local_or(next, "/"); // `?next=` never leaves this site
}

// Sign-in with a provider: redirect to `url` and keep `pending` in the session; on
// the callback, `complete` checks the state and the provider, then trades the code.
let google = oauth::Client {
    provider: oauth::google(),
    client_id: "id".into(),
    client_secret: "secret".into(),
    redirect_uri: "https://app.example/auth/google/callback".into(),
};
let (_url, _pending) = google.begin()?;
let http = oauth::http_client()?; // timeouts, no redirects followed
let who = google.complete(&http, &pending, state, code).await?;
println!("{} <{:?}>", who.uid, who.email);

// Machine clients with an IdP's token: signature, algorithm, issuer, audience,
// expiry and not-before.
let verifier = jwt::Verifier::discover(http, "https://sso.example/realms/x", "myapp").await?;
let claims: jwt::Claims = verifier.verify("eyJ...").await?;
# let _ = claims; Ok(()) }
```

### Accounts

`owt-accounts` is the sign-in every app wrote over the pieces above: an `accounts`
table with a session epoch, `authenticate` with the decoy check and rehash, a
walled extractor, sign-out everywhere. The app keeps its pages (the sign-in form is
its template), its extra columns (`ALTER TABLE accounts ADD COLUMN …` in a migration
of its own) and the choice of flows (self-signup or not, which providers, whether
links are minted).

**Tables:** write `owt_accounts::migrations::ALL[0].sql` to
`migrations/0001_owt_accounts.sql`, first, since the app's tables reference
`accounts(id)`; a test calls `owt_accounts::migrations::assert_installed("migrations")`
so an edited or missing copy fails the build. sqlx keeps one ledger per database, which
is why the library does not run a migrator of its own. A shipped migration never
changes (sqlx would refuse the re-copied file at deploy, its checksum differing from
the applied one): a later release appends a new entry to `ALL`, which the app copies
as its next file, and a test here pins each file's SHA-256.

**Logins:** a username is one token without `@`; an email always has one. So a login
is never both, and nobody can register a username equal to someone else's email to
shadow their sign-in. The table's `CHECK` enforces it on writes made around the
library.

```rust,no_run
# async fn demo(
#     pool: sqlx::PgPool, session: owt_web::session::Session<owt_accounts::session::Data>,
#     ip: std::net::IpAddr, login: &str, given: &str, who: owt_auth::oauth::Identity,
# ) -> anyhow::Result<()> {
use axum::{Router, middleware::from_fn_with_state, routing::get};
use owt_accounts::{Accounts, Maybe, New, Signed, Staff, identities, links, session, store};
use owt_auth::throttle::Throttle;

// Once per request, inside the session layer (`Sessions::layer`, above): load the
// signed-in account if its epoch still matches. The extractors read it from the
// request, so a handler and a page-chrome helper cost one query between them.
let accounts = Accounts::new(pool.clone(), "/login");
// `?next=` is the URL the client asked for, prefix included under `Router::nest`. An
// app whose pages sit under prefixes with a sign-in page each (`/en/login`,
// `/es/login`) installs the layer on each nested router with its own path.
async fn home(Maybe(me): Maybe) -> String { me.map_or("hello".into(), |a| a.username) }
async fn settings(Signed(me): Signed) -> String { me.username } // anonymous: 303 /login?next=…
async fn admin(Staff(me): Staff) -> String { me.username } // signed in, not staff: 403
// Database down: `Maybe` reads as anonymous, `Signed` and `Staff` answer 503 (the
// sign-in page could not help), and the cookie keeps its signature for when it is back.
let app: Router = Router::new()
    .route("/", get(home))
    .route("/settings", get(settings))
    .route("/admin", get(admin))
    .layer(from_fn_with_state(accounts, Accounts::load::<session::Data>));

// Sign-in: throttle, authenticate (by username or email; an unknown login costs a
// real check; an old hash is replaced), then the session: new id, account and epoch.
let throttle = Throttle::default(); // in the app's state
if throttle.sign_in(ip, login)
    && let Some(account) = store::authenticate(&pool, login, given).await?
{
    session::sign_in(&session, &account);
}
session::sign_out(&session); // this session
session::sign_out_everywhere(&pool, &session).await?; // every session: the epoch moves

// Accounts: normalized, password rules checked (`owt_accounts::password`), a taken
// username or email refused by the constraint, so two racing sign-ups cannot both win.
let ada = store::create(&pool, New {
    username: "Ada", email: "ada@example.com", password: Some("correct horse battery"), is_staff: false,
}).await?;
store::set_password(&pool, &ada, "a different passphrase").await?; // same rules; signs out everywhere
store::set_staff(&pool, ada.id, true).await?; // revoking signs out; granting does not

// A provider's identity (from `oauth::Client::complete`) becomes an account per policy:
// linked already, matched by a verified email, created, or unknown.
let welcome = identities::Welcome { match_verified_email: true, create: true };
if let Some(account) = identities::arrive(&pool, "google", &who, welcome).await?.account() {
    session::sign_in(&session, account);
}

// A one-time sign-in link, minted by an operator; only its SHA-256 is stored. The
// lifetime is capped at `links::MAX_TTL`.
let minted = links::mint(&pool, ada.id, std::time::Duration::from_secs(900), "new account").await?;
let _url = format!("https://app.example/login/link/{}", minted.token);
let _opened = links::redeem(&pool, &minted.token, &ip.to_string()).await; // Refused::Link when spent
# let _ = app; Ok(()) }
```

A refusal (`owt_accounts::Refused`) carries the sentence the person reads; a handler
matches `Error::Refused` to re-render the form with it, and the `From` into
`owt_web::Error` answers 422 with the same text.

### Change requests

`owt-change` lets a site's signed-in admins ask for a change from the page itself. A
floating "Request a change" button lets them point at the part of the page they mean
and say what should change. The site's server forwards that, with who asked, to a
work tracker.

- **The browser never holds a credential.** It posts to the site, same origin, with
  the admin's session; the site's server forwards under its key from a Secret.
- **Who asked comes from the session.** `requested_by` is filled by the server
  (`Admin::requester`), so a browser cannot name somebody else.
- **Off unless configured.** With neither `CHANGE_REQUESTS_URL` nor
  `CHANGE_REQUESTS_KEY` set, the routes answer 404 and the button renders nothing.
  One without the other fails at start.

```rust,no_run
# fn demo(http: reqwest::Client) -> Result<(), owt_change::ConfigError> {
use askama::Template;
use axum::Router;
use owt_change::{ChangeRequests, Config};

let changes = ChangeRequests::new(Config::from_env()?, http); // in the app's state
// `POST /change-requests` and `GET /change.js`, for staff (`owt_accounts::Staff`):
// nest them inside the accounts layer and behind `CrossOrigin`.
let app: Router = Router::new().nest("/staff", changes.routes::<owt_accounts::Staff, ()>());

// In the page shell, for a staff viewer: `{{ change_button }}` is the script tag.
#[derive(Template)]
#[template(source = "<body>…{{ change_button }}</body>", ext = "html")]
struct Shell<'a> { change_button: owt_change::Button<'a> }
let viewer_is_staff = true;
let _ = Shell { change_button: changes.button("/staff", viewer_is_staff) };
# let _ = app; Ok(()) }
```

An app without `owt-accounts` implements `owt_change::Admin` on its own extractor and
names it in `routes::<MyAdmin, _>()`.

**The button** is `change.js`, served by the routes, immutable under its `?v=` hash. It
runs under the default Content-Security-Policy: no inline script, no style
attributes, its DOM built with `textContent`, styled by `owt-change-*` classes in
`tailwind/owt.css`. A press enters pick mode: the element under the pointer is
outlined, a click or tap picks it, and Esc cancels. It works on phones, where there
is no right-click. A dialog then asks for a title and the detail.

**The protocol** is `owt_change::ChangeRequest`, posted as JSON with
`Authorization: Bearer <key>`:

```json
{
  "title": "Show prices at 20px on phones",
  "description": "They are hard to read on my phone.",
  "page_url": "https://myapp.example/menu",
  "element": { "selector": "main > h1", "text": "Opening hours" },
  "selection": "",
  "viewport": "390x844",
  "user_agent": "Mozilla/5.0 …",
  "requested_by": { "username": "ana", "email": "ana@myapp.example" }
}
```

The tracker answers `2xx` when it filed the request. Otherwise it answers with
`{"error": "<a sentence for the admin>"}`:

| The tracker answers | The admin sees |
|---|---|
| 422 or 503 | the tracker's sentence |
| 401 or 403 | a sentence saying the site's key was refused (the site logs a warning) |
| anything else, or no answer within 10 s | "Try again in a minute" |

### Realtime fan-out

The app names its topics and its message type; the bus moves text between replicas
and decodes each message once per replica.

```rust,no_run
use std::{fmt, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Topic { Room(i64) }

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Topic::Room(id) => write!(f, "room-{id}") }
    }
}

impl owt_bus::Topic for Topic {
    fn parse(channel: &str) -> Option<Self> {
        channel.strip_prefix("room-")?.parse().ok().map(Topic::Room)
    }
}

struct Msg(String);

impl owt_bus::Message for Msg {
    fn decode(text: String) -> Option<Self> { Some(Msg(text)) }
    fn text(&self) -> &str { &self.0 }
    // What every subscriber gets after a resubscribe, when broadcasts may be lost.
    fn resync() -> Option<Self> { Some(Msg(r#"{"type":"resync"}"#.into())) }
}

# async fn demo(redis_url: &str) -> anyhow::Result<()> {
owt_bus::ensure_crypto_provider(); // before any rediss:// connection
let publisher = redis::aio::ConnectionManager::new(redis::Client::open(redis_url)?).await?;
let options = owt_bus::Options { metrics: Some(owt_bus::MetricNames::prefixed("myapp")), ..Default::default() };
let bus: owt_bus::Bus<Topic, Msg> = owt_bus::Bus::redis(redis_url, publisher, "myapp", options)?;
let mut socket = bus.subscribe();
socket.join(Topic::Room(7));
bus.publish(Topic::Room(7), Arc::new(Msg("hello".into()))).await;
let _first = socket.recv().await;
# Ok(()) }
```

`Bus::local` is the same API in one process, for tests. Channel names are a wire
format between replicas: change them only with every replica.

### Background jobs

Every replica runs the same binary, so a periodic task runs everywhere unless it
says otherwise. `owt_runtime::jobs` gives three modes, all with jitter, a loop that
survives a failed or panicking run, and graceful shutdown:

- `every_replica`: idempotent work; the task takes its rows with `SKIP LOCKED`.
- `singleton`: at most one replica at a time, by a Postgres advisory lock that is
  tried and skipped, never waited on.
- `leased` (feature `redis`): one replica, the same one while it lives, by a Redis
  lease renewed while held; on shutdown it is released, so another replica takes over
  at once.

```rust,no_run
use std::time::Duration;
use owt_runtime::jobs::{CancellationToken, Every, JobMetrics, Jobs, lease::Leases};

# async fn demo(pool: sqlx::PgPool, redis: redis::aio::ConnectionManager) {
let shutdown = CancellationToken::new();
let jobs = Jobs::new(shutdown.clone()).metrics(JobMetrics::prefixed("myapp"));

// Each replica sweeps, taking rows with FOR UPDATE SKIP LOCKED.
let p = pool.clone();
jobs.every_replica("weekly_pass", Every::new(Duration::from_secs(60)), move || {
    let p = p.clone();
    async move { sqlx::query("SELECT 1").execute(&p).await?; Ok(()) }
});

// One replica at a time drives the bots; the others skip that tick.
jobs.singleton("bots", Every::new(Duration::from_secs(30)), pool.clone(), 7_210_001, || async { Ok(()) });

// One replica owns the clock; the TTL outlasts the period so ownership sticks.
let leases = Leases::new(redis, Leases::new_holder_id(), "myapp");
jobs.leased("clock", Every::new(Duration::from_secs(1)), leases, "clock", Duration::from_secs(5), |held| async move {
    tokio::select! {
        () = held.lost() => {}  // another replica took over mid-run: stop owner-only work
        () = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    Ok(())
});

// At SIGTERM: stop the loops (runs in progress finish), then exit.
owt_runtime::serve::shutdown_signal().await;
shutdown.cancel();
jobs.stopped().await;
# }
```

Name each advisory lock id once, in one place in the app: two jobs sharing an id
exclude each other. Record runs with `JobMetrics::prefixed("myapp")`
(`<prefix>_job_runs_total{job,outcome}`, `<prefix>_job_seconds{job}`), and call its
`describe()` inside the closure passed to `owt_runtime::metrics::install`.

A leased job keeps its lease while its replica lives as long as the TTL outlasts the
period plus jitter: the lease is renewed at each tick, during a run, and when the run
ends. A lease is a Redis key: a Redis that evicts under memory pressure (as a cache
does) can drop it, and until the holder's next renewal fails (a third of the TTL) two
replicas may run the job. Work that must never run twice gets a `noeviction` Redis,
and checks `held.is_lost()` before each owner-only step.

A run's panic, in the future or in the closure that builds it, is one failed tick;
the loop goes on.

### Front-end assets

The browser fetches nothing from another origin: whatever another origin serves runs
with the page's authority, and a page that needs public internet from the browser
breaks where there is none. Every asset is served by the app, by one of two routes:

- **From a CDN, hash-pinned:** list each file in `vendor.pins` at the repository root
  (`path url sha384-…`) and run `templates/vendor-js`, the only thing that downloads.
  It refuses any mismatch; to upgrade, change the URL and paste the hash it reports.
- **Built from npm:** `package-lock.json` is the integrity record, and the gate
  rebuilds and diffs the output.

Three tests hold it, one call each:

```rust
# fn main() {
# let d = std::env::temp_dir().join(format!("owt-readme-assets-{}", std::process::id()));
# std::fs::create_dir_all(d.join("templates")).unwrap();
# std::fs::create_dir_all(d.join("static")).unwrap();
# std::fs::write(d.join("templates/base.html"), "<script src=\"/static/htmx.min.js\"></script>").unwrap();
# std::fs::write(d.join("static/htmx.min.js"), "htmx").unwrap();
# let pin = owt_test::assets::sri(b"htmx");
# std::fs::write(d.join("vendor.pins"), format!("static/htmx.min.js https://unpkg.com/htmx.org {pin}\n")).unwrap();
# std::env::set_current_dir(&d).unwrap();
use owt_test::assets;

// No template loads a script, style, font or image from elsewhere.
assets::assert_no_remote_assets("templates");
// Every vendored file is byte-for-byte what its pin says.
assets::assert_vendored_files_match_pins("vendor.pins");
// No shipped script names a source map that isn't shipped.
assets::assert_no_dangling_source_maps("static");
# }
```

This is what makes a strict Content-Security-Policy (`headers::Csp`) enforceable:
nothing legitimate is left for it to block.

### Shared components

The pieces every page renders the same way are Askama templates compiled into
`owt-web`, embedded in a page as values: `{{ alerts }}`, `{{ field }}`. Their markup
carries only `owt-*` classes, which `tailwind/owt.css` defines over semantic tokens
(`--color-owt-ink`, `--color-owt-accent`, `--color-owt-danger`, `--radius-owt`…) with
plain defaults; an app redeclares any of them in its own `@theme` after the import and
the components take its look. Nothing to copy, and the app's stylesheet need not scan
the library (it cannot: Tailwind sees the app's templates only, which is why the
components name no utility class).

```rust
# fn main() -> askama::Result<()> {
use askama::Template;
use owt_web::flash::{Flash, Level};
use owt_web::pager::Pager;
use owt_web::request::RequestInfo;
use owt_web::ui::{Alerts, ErrorBody, Errors, Field, Pagination};

// A page names the components as fields and writes `{{ alerts }}` where they go.
#[derive(Template)]
#[template(source = r#"<form method="post">{{ alerts }}{{ errors }}{{ username }}{{ password }}</form>{{ pages }}"#, ext = "html")]
struct SignIn<'a> {
    alerts: Alerts<'a>,
    errors: Errors<'a, String>,
    username: Field<'a>,
    password: Field<'a>,
    pages: Pagination<'a>,
}

let flashes = [Flash(Level::Info, "You were signed out.".into())];
let refused = vec!["That username and password don't match an account.".to_owned()];
let request = RequestInfo::at("/people?page=2");
let page = SignIn {
    alerts: Alerts { flashes: &flashes },
    errors: Errors { errors: &refused },
    username: Field::text("username", "Username").value("ada").autocomplete("username").required().autofocus(),
    // A password field never echoes its value.
    password: Field::password("password", "Password", "current-password").required(),
    pages: Pagination::new(Pager { number: 2, pages: 7 }, &request), // links keep the rest of the query
};
let html = page.render()?;
assert!(html.contains(r#"<div class="owt-alert owt-alert-info" role="status">"#));
assert!(html.contains(r#"href="/people?page=3""#)); // root-relative: the same link in a fragment
assert!(html.contains(r#"href="/people""#)); // page 1 has one URL, not `/people?page=1`

// The body of a 404 or 500, for the app's error shell (see `error_pages`).
let body = ErrorBody::for_status(axum::http::StatusCode::NOT_FOUND).render()?;
assert!(body.contains("<h1>Page not found</h1>"));
# Ok(()) }
```

An app with a look of its own sets the tokens once. A dark theme is the same tokens
again under a media query or a class: `@theme` emits them as custom properties on
`:root`, and the components read the properties, so whatever redeclares them nearer
the element wins.

```css
@import "tailwindcss" source(none);
@import "@onewaytek/owt-stack/tailwind/owt.css";
@source "../templates";
@theme {
  --color-owt-ink: var(--color-slate-900);
  --color-owt-accent: var(--color-emerald-700);
  --color-owt-on-accent: white;
  --radius-owt: 0.75rem;
}
/* Dark: follow the system, or `:root[data-theme="dark"]` for a switch the app owns. */
@media (prefers-color-scheme: dark) {
  :root {
    --color-owt-ink: var(--color-slate-100);
    --color-owt-muted: var(--color-slate-400);
    --color-owt-surface: var(--color-slate-900);
    --color-owt-line: var(--color-slate-700);
    --color-owt-accent: var(--color-emerald-400);
    --color-owt-on-accent: var(--color-slate-950);
    --color-owt-success-soft: var(--color-green-950);
    --color-owt-info-soft: var(--color-blue-950);
    --color-owt-warning-soft: var(--color-yellow-950);
    --color-owt-danger-soft: var(--color-red-950);
  }
}
```

Two forms on one page with a field of the same name give each its own `id`
(`Field::text("email", "Email").id("invite-email")`), so labels and
`aria-describedby` stay attached to the right input. Page links drop `?page=1`, so
the first page of a list has one URL.

### Tests

```rust
use axum::{Router, routing::get};
use owt_test::{Client, fragment, golden::{Golden, Normalizer}};

# #[tokio::main(flavor = "current_thread")]
# async fn main() {
let app = Router::new().route("/", get(|| async { "<main id=\"m\"><p>Hi</p></main>" }));
let browser = Client::new(app); // carries cookies between requests
let page = browser.get("/").await;
assert_eq!(page.status, 200);

// A page and its fragment render one region alike.
fragment::assert_same_element(&page.text(), "<main id=\"m\"> <p>Hi</p></main>", "#m");

// Golden pages: compared modulo layout, with what changes per run masked.
// `UPDATE_GOLDEN=1 cargo test` rewrites the snapshots; review the diff.
let normalize = Normalizer::new().uuids("<uuid>");
# if false { // no snapshots beside the README
let mut golden = Golden::new("tests/golden/pages");
golden.take("home", normalize.normalize(&page.text()));
golden.check(); // a Golden dropped unchecked fails the test
# }
# }
```

`owt_test::Server::spawn(router)` serves on an ephemeral port for WebSocket and SSE
tests. Test requests carry no `Origin`, so cross-origin protection lets them through;
set `Sec-Fetch-Site: cross-site` on one to test the protection itself.

## Commands, CI, releases and deployment

**Day to day:** copy `templates/justfile` and `templates/compose.yaml` into the app.
Every app then answers to the same commands:

```sh
just setup        # npm ci, sqlx-cli, cargo-audit
just db           # Postgres 18 and Redis 8 (compose.yaml), then the migrations
just dev          # the app, with the stylesheet rebuilt on change
just check        # the gate: fmt, clippy, rustdoc, .sqlx freshness, audit, tests
just test --test worlds
just prepare      # regenerate .sqlx/ after changing a query
```

`just check` is the gate before every commit, and CI runs the same command, so the
two lists of checks can't drift. App-specific recipes go below the template's
`---- app recipes ----` line. The compose ports and database name come from the
app's `.env` (`POSTGRES_PORT`, `POSTGRES_DB`, ...), so two apps' stacks can run side
by side.

**CI:** call the reusable check workflow with the app's gate. It runs on ARC, with
Postgres and Redis as services, installs `just`, `sqlx-cli` and `cargo-audit`,
migrates, then runs `check-command`. Without `check-command`, it runs its own fmt,
audit, sqlx, clippy and test steps.

<!-- x-release-please-start-version -->
```yaml
jobs:
  checks:
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@v0.4.1
    with:
      check-command: just check
      database: myapp        # empty for no Postgres
      postgres-major: "18"   # match the CNPG image
      redis: true
      css-script: css:build  # empty to skip the stylesheet job
      extra-env: |           # test-only values, never real secrets
        SESSION_SECRET=...
    secrets: inherit
```
<!-- x-release-please-end -->

The checks run on the `arc-openshift-k8s` scale set unless the repository or
organization variable `RUNS_ON` names other runners, as JSON (`"ubuntu-latest"`). A
public repository should: self-hosted runners in the cluster are no place for code
anyone can propose. Off ARC the services are at their names (`postgres`, `redis`)
rather than localhost; `DATABASE_URL` and `REDIS_URL` follow, so build on those
rather than naming a host.

**Releasing an app:** this is how an *app* releases, with semantic-release through the
reusable `release.yml`. owt-stack releases itself differently, with release-please
(see "Working on owt-stack"). Conventional commits decide an app's version: `feat` is
a minor release, `fix` and `perf` are a patch, `!` or a `BREAKING CHANGE` footer is
major (from 0.x too: a breaking change in 0.4.2 releases 1.0.0), and anything else
releases nothing. `main` cuts stable releases; an `rc` branch, if the app has one, cuts
`X.Y.Z-rc.N` prereleases. Each release is a `vX.Y.Z` tag, a GitHub release with
generated notes, and an image in ghcr. An app with its own `.releaserc` must keep the
`publishCmd` that writes `version` and `channel` to `$GITHUB_OUTPUT`, or no image is
built.

<!-- x-release-please-start-version -->
```yaml
# .github/workflows/release.yml
on:
  push: {branches: [main, rc]}
  workflow_dispatch:          # promote-rc.yml starts rc releases this way
jobs:
  ci:
    uses: ./.github/workflows/ci.yml
    secrets: inherit
  release:
    needs: ci
    permissions: {contents: write, issues: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/release.yml@v0.4.1
  image:
    needs: release
    if: needs.release.outputs.version != ''
    permissions: {contents: read, packages: write}
    uses: onewaytek/owt-stack/.github/workflows/image.yml@v0.4.1
    with: {version: "${{ needs.release.outputs.version }}"}
    secrets: inherit
```

- **An app whose code reads its version** writes it into its files with the release:
  `with: {version-command: 'uv version "$VERSION" && uv lock', version-files:
  "pyproject.toml uv.lock", changelog: true, uv: true}`. The files are committed back
  as `chore(release): vX.Y.Z [skip ci]`. The command runs in bash, without the
  release's token.
- **Images** are tagged `X.Y.Z`, plus `X.Y` and `latest` (and `X` from 1.0) for a
  stable release, or `rc` for a prerelease. Rebuild an existing tag by calling
  `image.yml` from a `workflow_dispatch` with `floating-tags: false`.
- **The rc channel** (optional): on each same-repository PR into `main`, once its
  checks pass, merge the PR into `rc` and cut a prerelease. After each stable
  release, merge `main` back into `rc`.

```yaml
# in pr.yml
  promote:
    needs: ci
    if: github.event.pull_request.head.repo.full_name == github.repository && !github.event.pull_request.draft
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@v0.4.1
    with: {source: "${{ github.event.pull_request.head.ref }}", pr: "${{ github.event.pull_request.number }}"}
# in release.yml
  sync-rc:
    needs: release
    if: github.ref_name == 'main'
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@v0.4.1
    with: {source: main, dispatch-release: false}
```
<!-- x-release-please-end -->

Image builds run on GitHub-hosted runners: the ARC runners have no Docker daemon.

**Image:** copy `templates/Dockerfile` (and `templates/dockerignore` as
`.dockerignore`) and set `BIN` and `PORT`. The build fetches owt-stack like any other
git dependency; no secret is mounted. Distroless has no shell: keep a debian-slim
runtime if operations `oc exec` shell tools into the pod.

**OpenShift:**

```sh
oc process -f templates/openshift/app.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p IMAGE=ghcr.io/onewaytek/myapp -p CHANNEL=rc -p PORT=8000 | oc apply -f -
```

The ImageStream polls ghcr for the channel's tag (`rc` or `latest`), and the
Deployment's trigger rolls out each new digest. App-specific environment is a patch
on the Deployment.

**Backups come with it.** The database takes a volume snapshot nightly
(`BACKUP_SCHEDULE`, CNPG's six-field cron, seconds first) and once at first apply.
They are offline by default (`BACKUP_ONLINE=false`): Postgres stops for the seconds an
LVM snapshot takes, because an online snapshot is only consistent with a WAL archive,
which these clusters don't have. A CronJob (`PRUNE_SCHEDULE`, after the backup) prunes
snapshots older than `BACKUP_KEEP_DAYS` (14) but always keeps the newest
`BACKUP_KEEP_AT_LEAST` (3) completed ones, so backups that silently stop are not all
aged out on schedule; a prune that fails fails its Job.

These snapshots live in the same volume group, on the same node: they undo a bad
migration or a dropped table, not the loss of the disk. Off-node copies need object
storage and a WAL archive (CNPG's barman plugin), app by app.

**Restoring:** delete the broken Cluster (`oc delete cluster <name>-db`; its Backups
and their snapshots survive, since nothing owns them), then re-create it from a
Backup with the same name, so the Deployment's secrets and the NetworkPolicy still
fit:

```yaml
bootstrap:
  recovery:
    backup: {name: <name>-db-nightly-20261007020000}
    database: <name>
    owner: <name>
```

`templates/openshift/restore-drill.sh <namespace>` proves the arrangement end to end
on throwaway clusters: it backs one up, restores it into another and checks the data.
Run it (it needs a namespace admin) whenever how backups are taken changes.

An app that already has hand-written backup objects under the same names
(`<name>-db-nightly`, `<name>-backup-prune`) replaces them by applying this template.

**Monitoring** needs more than the namespace (`monitoring-edit`, and user-workload
monitoring enabled on the cluster), so it is a template of its own, for a cluster
admin to apply:

```sh
oc process -f templates/openshift/monitoring.yaml -p NAME=myapp -p NAMESPACE=myapp | oc apply -f -
```

It scrapes the app's `/metrics` and the CNPG instances' Postgres exporter, and opens
the exporter's port to Prometheus alone.

**Tailwind:** depend on the npm half and import it after Tailwind:

<!-- x-release-please-start-version -->
```json
"devDependencies": { "@onewaytek/owt-stack": "github:onewaytek/owt-stack#v0.4.1" }
```
<!-- x-release-please-end -->

```css
@import "tailwindcss" source(none);
@import "@onewaytek/owt-stack/tailwind/owt.css";
@source "../templates";
```

## Decisions

- **No CSRF tokens.** Unsafe requests are refused when the browser's fetch metadata
  (`Sec-Fetch-Site`) or, failing that, `Origin` says they came from another origin:
  Go 1.25's `CrossOriginProtection`. Forms carry no hidden field, and htmx sends no
  header. Session cookies stay `SameSite=Lax` as a second line.
- **Sessions are cookies.** Sealed with AES-GCM; no store. Revoke by epoch (a counter
  in the account, copied into the session at sign-in, bumped at sign-out) checked in
  `Sessions::validate_with`. A session ends at its absolute lifetime however often it
  is re-sealed, and a response that sets the cookie is never cacheable.
- **Fragments have their own URLs.** Nothing varies by request header, so every
  response stays cacheable behind a CDN that ignores `Vary`.
- **Library code holds no `query!` macros**, so it needs no `.sqlx/` metadata and builds
  offline anywhere.
- **Metric names belong to the app.** The library takes them as arguments, so an app's
  dashboards and load-test reports keep their names.
- **Bus channel names** (`<prefix>:<topic>`, `~changed`, `~beat`) are a wire format
  between replicas. Changing one is a rollout hazard: old and new replicas must agree.
- **OpenShift Template, not Kustomize**, for the deployment: the app's name must reach
  the image trigger annotation and the CNPG Secret's name, which Kustomize's name
  transformers do not rewrite.

## Security an app wires

The router example under "Wiring an app" composes the layers; beyond it:

- `headers::security` sends HSTS for the app's own host. An app that owns its whole
  domain adds `includeSubDomains` itself.
- Sign-in: `throttle::Throttle::sign_in` *before* `password::verify_or_decoy` (a
  refused sign-in checks no password), keyed on `client_ip::Source::client_ip`
  (configured for the proxies actually in front of the app), and
  `redirect::local_or` on `?next=` before redirecting to it (see "Authentication").
- OAuth: `oauth::http_client()` for the exchange; `Client::complete` checks the
  state and the provider itself.
- The bus's Redis is inside the trust boundary: a password or ACL user, a network
  only the app reaches, `rediss://` where the path leaves the node.
- `Limits` bounds the time to a response, not the time a client takes to send a
  request: serve behind a proxy that bounds that (the OpenShift router does).
- Start `Csp` in report-only mode and read the browser console before enforcing.
  htmx needs `htmx.config.includeIndicatorStyles = false` (or its
  `inlineStyleNonce`) and no `hx-on:*` attributes, which a nonce cannot cover.

## Upgrading from 0.1

- **Everyone signs in once more:** the sealed session gains its start time (`i`), and
  cookies sealed before it no longer open. Session data may not use the field names
  `k`, `x` or `i`.
- `Sessions::validate_with`'s closure answers a `Verdict` (a `bool` still converts).
- `oauth::Client::complete` takes the callback's `state`; drop the app's own
  `Pending::matches` check. `Pending` gains `provider`, so a sign-in in flight across
  the deploy fails once with `Error::Provider`.
- `jwt::Error` and `oauth::Error` have new variants; a `match` on them needs arms.
- `jwt::Verifier::discover` refuses a discovery document whose `issuer` is not
  exactly the configured one (trailing slash included) or whose `jwks_uri` is not
  https.
- `CrossOrigin::layer` refuses cross-origin WebSocket upgrades. A bypass prefix
  matches whole path segments: `/mcp` no longer covers `/mcp-admin`.
- The workspace's `tower-http` names only `timeout`; an app names its own features
  (`fs` for `ServeDir`; see "Adding it to an app").
- `sqlx` is built with `tls-rustls-aws-lc-rs` (above).
- The OpenShift template adds NetworkPolicies, Postgres over verified TLS, a
  read-only root filesystem and a `CNPG_NAMESPACE` parameter: process it into a
  staging namespace first.

## Working on owt-stack

`just check` is the gate (fmt, clippy over every crate and feature, the tests with the
README doctests, `cargo audit`), and CI runs the same command. The Redis tests run when
`REDIS_URL` is set, the Postgres ones (`owt-runtime`'s singleton jobs) when
`DATABASE_URL` is, and `owt-bus`'s TLS test when `REDIS_TLS_URL` is a `rediss://` URL
whose certificate the system trusts (`SSL_CERT_FILE=ca.crt` for a test CA; the test's
header says how to run such a Redis). Each is skipped otherwise; CI sets the first two.

**Tests come in four kinds**, and a change to anything that reads what a client sent
adds to the first:

- *Properties* (`crates/*/tests/properties.rs`, `owt-bus/tests/model.rs`): what must
  hold for every input, with proptest looking for the one where it does not. A
  failure writes its seed to a `.proptest-regressions` file beside the test; commit
  it, so the case is retried for ever.
- *The composed app* (`owt-web/tests/hardened_app.rs`): the layers in the README's
  order, and the sign-in story end to end (fixation, revocation, an outage, a
  replayed cookie).
- *Unit tests* beside the code, for what needs its private parts.
- *Mutation testing*, on demand: `cargo mutants -p owt-web` (or `-p owt-auth`, which
  takes an hour) lists the changes to the code no test notices. A missed mutant in
  a check that guards something is a missing test.
- *Fuzzing*, on demand (`fuzz/`, not a workspace member): coverage-guided libFuzzer
  targets over what reads client bytes (the origin check, `X-Forwarded-For`, session
  unsealing, `RequestInfo::at`, redirect targets, stored hashes), each asserting an
  invariant, not just the absence of a panic. Needs nightly and a C++ compiler:
  `cd fuzz && cargo +nightly fuzz run csrf_same_origin -- -max_total_time=300`, or
  the same inside `docker.io/rustlang/rust:nightly` with the checkout mounted. A
  finding lands in `fuzz/artifacts/`; turn it into a unit test beside the code.

**Keep this README's instructions current.** A change to a public API, a template, the
workflow's inputs or how an app adopts something updates the matching section here in
the same pull request. The Rust examples are doctests, so a stale example fails
`cargo test`; check the YAML, CSS and shell examples by eye.

**Commits and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org)**
(`feat(web): …`, `fix(auth): …`, `docs: …`), checked on every pull request. Scopes
name the crate or area: `web`, `auth`, `runtime`, `bus`, `test`, `ci`, `templates`,
`accounts`, `change`, `tailwind`, `deps`, `release` (release-please and its configuration).

**Releasing is automatic.** release-please keeps a release pull request open against
`main`, with the next version and the changelog since the last release. Merging it
tags `vX.Y.Z` and publishes the GitHub release; apps move by changing their tag. While
the version is 0.x, the bump follows Cargo's rules for 0.x:

| Commit | Release |
|---|---|
| `fix:`, `perf:`, `revert:`, `feat:`; Dependabot's `fix(deps):` | 0.2.0 → 0.2.1 |
| `feat!:`, or a `BREAKING CHANGE:` footer | 0.2.0 → 0.3.0 |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `style:`, `build:` | none on its own; listed nowhere |

A breaking change says in its footer what an app must change; that text becomes the
changelog's "Breaking changes", so the upgrade notes write themselves. The release pull
request updates every version: the workspace `Cargo.toml`, `Cargo.lock`,
`package.json`, the fuzz crate's `Cargo.toml` and `Cargo.lock` (not a workspace
member, so it tracks the release on its own) and the tags in this README (between
`x-release-please` markers). A new reference to the version needs a marker too,
outside `.github/workflows/`: GitHub lets no workflow's default token change a
workflow file, so those carry no version.

## Licence

MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`): the Rust
convention, and compatible with an app under any licence, copyleft included. A
contribution is offered under both. Security reports: `SECURITY.md`.
