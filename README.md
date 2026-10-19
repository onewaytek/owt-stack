# owt-stack

An opinionated stack used as a base for One Way Tek projects:
Rust, Axum, SQLx on Postgres, Redis, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; flash messages; the request as page chrome reads it; htmx fragments at their own URLs; fingerprinted static URLs; `Cache-Control` as a typed policy; security headers and a nonce-based content security policy; a response deadline and body cap; safe `?next=` redirects; the client's address behind proxies; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers; shared page components (alerts, form fields, pagination, an error body) styled by semantic tokens |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); a Redis read-through cache that never fails a request (feature `redis`); background jobs on every replica, on one at a time or on a Redis lease's holder (feature `redis`); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | sign-in throttling by address and account; Argon2id hashing off the runtime with bounded concurrency and a decoy check for unknown accounts; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-accounts` | the `accounts` table and its migration; create and authenticate (decoy check, rehash, username or email); sessions revoked by epoch (sign out everywhere, password change, deactivation); the `Signed`, `Staff` and `Maybe` extractors over one load per request; provider identities linked to accounts; local and system accounts an app reaches by a key of its own, with no password; one-time sign-in links; roles (user, staff, and the app's own, with the `Holds<R>` extractor); the staff accounts admin; sign-in with a provider (routes, configuration, buttons, connections) |
| `owt-change` | change requests from a site's own pages: a floating "Request a change" button for signed-in admins, and the endpoint that forwards what they ask, with who asked, to a work tracker under the site's key |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar; the router on an ephemeral port; golden-page snapshots; page/fragment agreement; the browser fetches nothing from another origin, and vendored files match their pins |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow on ARC: the app's `just check`, or built-in fmt, audit, sqlx metadata, clippy and tests; the stylesheet build |
| `.github/workflows/release-please.yml` | this repository's releases: versions and the changelog by release-please |
| `.github/workflows/conventional-commits.yml` | Conventional Commits checked on every pull request, here and, as a reusable workflow, in an app: the title and every commit, with one commitlint and one configuration |
| `.github/workflows/release.yml` | reusable releases from conventional commits: stable on `main`, prereleases on `rc`, optional version write-back and changelog |
| `.github/workflows/image.yml` | reusable image build for a released tag, daemonless on ARC (or the Dockerfile, GitHub-hosted), pushed to ghcr with the channel's floating tags |
| `.github/workflows/promote-rc.yml` | reusable rc channel: merge a PR (or `main`) into `rc` and start its prerelease, or into `rc-candidate` for checking first |
| `.github/workflows/publish-rc.yml` | reusable: move `rc` to a checked `rc-candidate` and start its prerelease |
| `.github/workflows/requeue-rc.yml` | reusable: re-run a PR's promotion that was cancelled while waiting or refused because `rc` moved |
| `templates/justfile`, `templates/compose.yaml` | the commands every app answers to (`just check`, `just db`, `just dev`), and Postgres and Redis for them |
| `templates/vendor-js` | downloads the vendored browser files `vendor.pins` lists, refusing any hash mismatch |
| `templates/dependabot.yml` | an app's `.github/dependabot.yml`: weekly `fix(deps)` pull requests for its action and workflow pins, its crates and its npm packages, minors and patches grouped |
| `templates/Dockerfile` | Red Hat Hummingbird images throughout: cargo-chef, an npm Tailwind stage, a minimal non-root glibc runtime that keeps a shell (with `templates/dockerignore`) |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger and the app's environment from a Secret, Service, Route, CNPG Postgres over verified TLS with nightly volume-snapshot backups and their pruning, NetworkPolicies |
| `templates/openshift/redis.yaml` | an optional Redis for the cache, the bus and leases: in memory, bounded, LRU-evicted, behind a password, reachable by the app alone, connecting to nothing |
| `templates/openshift/egress.yaml` | where the app's pods (or a task's) may connect: its database, its Redis, the cluster's DNS and port 443 of the internet, and nothing else |
| `templates/openshift/apply.sh` | renders every template present from the app's `params.env` (and `jobs/*.env`), `oc diff` by default, `--apply` to apply; `apply-test.sh` proves it against a stand-in `oc` |
| `templates/openshift/cronjob.yaml` | a scheduled task in the app's image, with the app's database, TLS, environment and NetworkPolicies |
| `templates/openshift/restore-drill.sh` | proves a backup restores, on throwaway clusters, and rehearses a Postgres major upgrade |
| `templates/openshift/monitoring.yaml` | Prometheus scraping for the app's metrics and its Postgres (needs `monitoring-edit`) |
| `tailwind/owt.css` | font stacks, htmx state variants (`htmx-request:opacity-50`), and the `owt-*` classes the shared components and the change-request button use |

Every Rust example below is compiled by `cargo test` (the `readme` crate includes this
file as its docs), so an API change that breaks these instructions fails CI.

## Adding it to an app

<!-- x-release-please-start-version -->
```toml
[dependencies]
owt-web = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
owt-runtime = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
# As needed:
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
owt-bus = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
owt-accounts = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
owt-change = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }

# The app's own: static files, request logs, compression.
tower-http = { version = "0.7", features = ["fs", "trace", "compression-gzip", "compression-br"] }

[dev-dependencies]
owt-test = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0" }
```
<!-- x-release-please-end -->

`owt-runtime`'s features: `metrics` (default) for Prometheus, `otel` for trace export,
`redis` for leases and leased jobs.
`owt-change`'s: `accounts` (default) for `owt_accounts::Staff` as its admin.
`owt-accounts`' `test-util` (off by default, for `[dev-dependencies]`) gives the admin's
view models an `example()` each, for an app's tests of its own templates.
`owt-auth`'s: `jwt` (default) for bearer-token verification, which brings `rsa` and an
audit ignore (see "Authentication").

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
    // Behind the OpenShift router: an idle kept-alive connection is closed after
    // `header_read_timeout` (30 s by default), and the router may reuse one for up to
    // 300 s, so keep the app's wait above the router's (see "Bounds" below).
    let mut options = serve::ServeOptions::default();
    options.header_read_timeout = std::time::Duration::from_secs(310);
    serve::serve_with(&bind, router(pool), serve::shutdown_signal(), options).await
}
```

`serve::serve` is the same with `ServeOptions::default()`: a request head must arrive
within 30 s (an idle kept-alive connection closes then too), at most 4096 connections
are open at once, and a stop drains for up to 20 s. `ServeOptions` is built from its
default and changed field by field:

```rust,no_run
# async fn run(app: axum::Router) -> anyhow::Result<()> {
use owt_runtime::serve::{self, ServeOptions};
let mut options = ServeOptions::default();
options.max_connections = 1024;
// For a listener nothing like `Limits` fronts: no connection outlives a minute.
options.max_connection_age = Some(std::time::Duration::from_secs(60));
serve::serve_with("0.0.0.0:8000", app, serve::shutdown_signal(), options).await
# }
```

The server speaks HTTP/1.1 only (the router in front speaks HTTP/2 to browsers);
`axum::serve` also answered HTTP/2 without TLS (h2c) when axum's `http2` feature was
on.

**Bounds.** What each bound counts:

- **Keep-alive.** `header_read_timeout` is the wait for each request head, the first
  on a connection and every one after, so it is also how long a kept-alive
  connection may sit idle before the app closes it. A proxy that keeps idle
  connections to the app for reuse longer than that sends, now and then, a request
  on a connection the app has just closed, and answers it with a 502. The OpenShift
  router's HAProxy waits up to 300 s by default (`timeout http-keep-alive`), so an
  app behind it sets the timeout above that, as the example above does. The router
  reads request heads itself, so the longer wait costs an idle socket, not
  protection from slow clients.
- **Connections.** `max_connections` counts every connection from its accept to its
  close: one idle between kept-alive requests, and one holding a Server-Sent Events
  stream, which is an ordinary HTTP/1.1 response that does not end. A WebSocket
  leaves the count at its upgrade. At the cap, new connections (readiness probes
  among them) wait in the kernel's accept queue, so an app with many SSE clients
  can reach it long before it runs out of CPU: raise it with `serve_with`, and the
  open-files limit with `serve::raise_open_files_limit()`.
- **Drain.** A stop closes idle connections at once and gives a response in flight
  until `drain` (20 s). An SSE stream never finishes, so every one still open is cut
  at the deadline, on each rollout: its client must reconnect (to another pod) and
  catch up. `EventSource` reconnects on its own; a page that keeps state from the
  stream asks for it again on `open`. A stop does not close a WebSocket: its
  handler ends it, or the process exiting does.

`PoolConfig::connect` warns at start when the database is not on this machine and
its TLS is not verified (`db::unverified_tls(&options)` asks the same of any
`PgConnectOptions`): give the pod `PGSSLMODE=verify-full` and `PGSSLROOTCERT`
(the OpenShift template does), since sqlx's default (`prefer`) neither requires TLS
nor checks the server.

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
    pub epoch: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<owt_web::flash::Flash>,
}

/// One indexed read of `owt-accounts`' table. `None`: no such account any more.
async fn account_epoch(pool: &sqlx::PgPool, user_id: i64) -> sqlx::Result<Option<i32>> {
    sqlx::query_scalar("SELECT session_epoch FROM accounts WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

pub fn router(key: cookie::Key, assets: Assets, cross_origin: CrossOrigin, pool: sqlx::PgPool) -> Router {
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
    // Report-only while the browser console is read for violations; enforcing
    // (drop `report_only`) is a step before launch, since report-only blocks nothing.
    let csp = Csp::new().report_only(true);
    let routes = Router::new().route("/healthz", get(owt_web::healthz));
    // ... the app's routes ...
    let pages = Limits::default()
        .apply(routes)
        .layer(from_fn_with_state(sessions, Sessions::<SessionData>::layer))
        .layer(from_fn_with_state(cross_origin, CrossOrigin::layer));
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

- **Session key:** `owt_web::session::key_for(&env::required("SESSION_SECRET")?, &purpose)`,
  from at least 64 random bytes, base64 on one line (`openssl rand 64 | base64 -w0`;
  `openssl rand -base64 64` wraps its output, and a newline inside is refused), where `purpose` names the app and its environment
  (`myapp/production`, or `myapp/` plus the pod's namespace from the downward API).
  Whoever holds the key seals a session for any account, so the secret is unique to
  each app and environment, and the purpose makes a copied secret (staging given
  production's) a different key anyway: otherwise a staging account's cookie opens
  production as the account with the same id. Changing either signs everyone out.
  The purpose is taken exactly (surrounding whitespace or a control character is an
  error, not trimmed), and a secret that is a pattern rather than random bytes (all
  zeros, a repeated word) is refused. `key_from_base64` uses the secret as the key
  directly; moving to `key_for` with `also_open_with(key_from_base64(…))` for a while
  keeps everyone signed in, but keeps a shared secret's cross-environment cookies
  opening for that while too. After a leak, rotate without `also_open_with`: the old
  key must open nothing.

  `Sessions::from_env("myapp", cookie, max_age, secure)` does the usual: the secret
  from `SESSION_SECRET` (required), the purpose `myapp/` plus `SESSION_PURPOSE`, else
  `POD_NAMESPACE`, else `local` (`session::purpose_from`); `local` is for
  development, and in a pod (`KUBERNETES_SERVICE_HOST` set) without either variable
  it is an error. An app moving onto it from
  a purpose of its own sets `SESSION_PURPOSE` to what followed its `myapp/`, or
  everyone is signed out once. `Sessions::from_vars` reads a map instead, for tests.

  ```rust,no_run
  # fn main() -> anyhow::Result<()> {
  use owt_web::session::Sessions;
  let _sessions = Sessions::<owt_accounts::session::Data>::from_env(
      "myapp",
      "__Host-session",
      std::time::Duration::from_secs(14 * 86_400),
      true,
  )?;
  # Ok(()) }
  ```

  ```rust,no_run
  # fn main() -> anyhow::Result<()> {
  use owt_web::session::{Sessions, key_for, key_from_base64};
  # #[derive(Clone, Default, serde::Serialize, serde::Deserialize)] struct SessionData;
  let secret = owt_runtime::env::required("SESSION_SECRET")?;
  let purpose = format!("myapp/{}", owt_runtime::env::required("POD_NAMESPACE")?);
  let sessions = Sessions::<SessionData>::new(
      key_for(&secret, &purpose)?,
      "__Host-session",
      std::time::Duration::from_secs(14 * 86_400),
      true,
  )
  // For one `max_age` after the move, then drop it (never after a leak).
  .also_open_with(key_from_base64(&secret)?);
  # Ok(()) }
  ```
- **Failed requests change no session:** a 5xx response (the `Limits` timeout's
  included, with `Limits` inside the session layer as above) carries no
  `Set-Cookie`, so a handler that signed someone in and then failed leaves them as
  they were. A sign-out (`flush`) stands whatever follows: a 5xx after one seals an
  empty session, dropping a sign-in made after it.
- **A slow route** (a staff action that runs a batch inline, a first request that
  builds something expensive) gets its own `Limits`, layered on the route itself
  (or with `.route_layer` on a router before `apply`). The bounds nearest the
  handler win, longer or shorter than the router's: the route's timeout moves the
  deadline the outer one waits on, still counted from when the request reached it,
  and its body limit replaces the router's. No second router is needed.

  ```rust
  use axum::{Router, routing::{get, post}};
  use owt_web::limits::Limits;
  use std::time::Duration;
  # async fn page() {}
  # async fn reindex() {}
  let slow = Limits { request_timeout: Duration::from_secs(120), ..Limits::default() };
  let routes: Router = Router::new()
      .route("/", get(page))
      .route("/staff/reindex", post(reindex).layer(slow)); // 120 s; `/` keeps 30 s
  let _pages = Limits::default().apply(routes);
  ```

  A timeout answers 503 and drops the handler's future where it stands: what it was
  awaiting is abandoned and its open transaction rolls back, but work it handed to
  `tokio::spawn` (or a job queue) runs on. The client then sees a failure for work
  that completes, and a retry does it again; such a route is idempotent, or answers
  before the long part and lets the page poll for the result.
- **Trusted origins** are `scheme://host[:port]`; anything else (`null`, a wildcard,
  a bare host, a path, or `https://` from `https://$HOST` with `HOST` blank) is
  refused at start rather than trusting every sandboxed frame or silently nothing.
  `CrossOrigin::try_trust` returns a `BadOrigin` naming the entry, so origins from the
  environment fail start-up with a config error; `trust` panics with the same
  message, for origins written in the code. Blank entries are skipped.

  ```rust
  # fn main() -> anyhow::Result<()> {
  use anyhow::Context;
  use owt_web::csrf::CrossOrigin;
  let cross_origin = CrossOrigin::new()
      .try_trust(owt_runtime::env::list("CSRF_TRUSTED_ORIGINS"))
      .context("CSRF_TRUSTED_ORIGINS")?;
  # Ok(()) }
  ```
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

`owt_accounts::session::Data` (and `social::Data`, which holds it) carries flash
messages already, as `flashes`; an app whose session holds more implements
`HasFlashes` on its own type, as below.

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
// Keys live under `myapp:c:`, apart from the leases and once-markers under `myapp:`.
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
- **One prefix per deployment:** `Cache::connect`, `Leases::new` and `Bus::redis` take
  the same one and refuse any but ASCII letters, digits, `_`, `.` and `-`. A `:` in
  it could make one prefix's cache key another's lease.

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

// The protocol underneath `owt_accounts::social`, which is what an app mounts (see
// "Sign-in with a provider"): `begin` makes the redirect and the pending login;
// `complete` checks the state and the provider, then trades the code.
let google = oauth::Client {
    provider: oauth::google(),
    client_id: "id".into(),
    client_secret: "secret".into(),
    redirect_uri: "https://app.example/auth/google/callback".into(),
};
let (_url, _pending) = google.begin()?;
let http = oauth::http_client()?; // timeouts, no redirects followed
let who = google.complete(&http, &pending, state, code).await?;
// The person is (`google.provider.key()`, `who.uid`). `who.email` is contact data:
// never look an account up by it (see "Accounts" below).
println!("{} <{:?}>", who.uid, who.email);
// Any OIDC issuer: its subjects are keyed by the issuer, not the `sso` id. The
// issuer and endpoints must be https (http only on localhost); `complete` refuses an
// ID token whose `iss`, `aud`, `azp` or `sub` is not this issuer, this client and
// the user-info subject, or whose `exp` has passed.
let _sso = oauth::oidc("sso", "SSO", "https://sso.example/realms/x",
    "https://sso.example/realms/x/protocol/openid-connect/auth",
    "https://sso.example/realms/x/protocol/openid-connect/token",
    "https://sso.example/realms/x/protocol/openid-connect/userinfo")?;
// Or from its discovery document, which must be the issuer's own; `end_session`
// is its RP-Initiated Logout endpoint, if it has one.
let found = oauth::discover(&http, "sso", "SSO", "https://sso.example/realms/x").await?;
// A provider asks for its preset's scopes; set others with a literal or a `String`
// from configuration (`offline_access` for a refresh token, at some issuers).
let mut provider = found.provider;
provider.scope = "openid profile email offline_access".into();
let sso = oauth::Client {
    provider,
    client_id: "myapp".into(),
    client_secret: "secret".into(),
    redirect_uri: "https://app.example/auth/callback".into(),
};

// An app that calls the provider's APIs as the person keeps what the token endpoint
// granted, after every check `complete` makes. Store the tokens sealed, never in
// the clear; turn the relative lifetimes into instants at once.
let (who, tokens) = sso.complete_with_tokens(&http, &pending, state, code).await?;
let _expires = std::time::SystemTime::now() + tokens.access_lifetime();
if let Some(refresh) = &tokens.refresh {
    match sso.refresh(&http, refresh, &who.uid).await {
        // No refresh token in the answer: the one held stays good.
        Ok(fresh) => { let _ = fresh.refresh.as_ref().unwrap_or(refresh); }
        // The grant is gone (`invalid_grant`: expired, revoked): forget it and sign
        // in again.
        Err(e) if e.is_rejected() => {}
        // The provider is unavailable, or the app's client is misconfigured
        // (`invalid_client`, a moved endpoint): keep the grant, try again later.
        Err(e) => return Err(e.into()),
    }
}
// A token for the app itself, with no person behind it.
let _own = sso.client_credentials(&http, Some("api")).await?;

// Machine clients with an IdP's token: the keys are refetched once they are an hour
// old (`jwt::KEYS_MAX_AGE`), so a key the IdP withdrew stops verifying within the
// hour; keys published for encryption verify nothing. Signature, algorithm, issuer, audience,
// expiry and not-before.
let verifier = jwt::Verifier::discover(http, "https://sso.example/realms/x", "myapp").await?;
let claims: jwt::Claims = verifier.verify("eyJ...").await?;
# let _ = claims; Ok(()) }
```

**The client's address** is configuration, never a guess. `Source::from_env()` reads
`CLIENT_IP` (`forwarded-for:N`, `header:NAME` or `peer`), else `TRUSTED_PROXIES` (a
count: `0` is the peer), else the peer; behind the OpenShift router alone it is
`CLIENT_IP=forwarded-for:1`. `forwarded-for:N` counts N entries from the right of
`X-Forwarded-For`, the ones the app's own proxies appended: everything to the left
is the client's to write, so a proxy at the edge appends (or replaces the header),
and the leftmost entry is never believed. `header:NAME` is for one proxy that sets
the header itself and that nothing can bypass. Add the source to every request as
an `Extension`, serve with `into_make_service_with_connect_info::<SocketAddr>()`, and
a handler takes `ClientIp`; without the peer and a header to read, it answers 500
rather than key every client alike. `Policies::client_ip` takes its own copy: pass
it the same source (`.client_ip(source.clone())`), so the two never disagree.
To confirm a setting against the real proxies, raise the filter to
`RUST_LOG=info,owt_web::client_ip=debug`: each extraction logs the source, the header
values it weighed (quoted, being the client's to forge), the peer and the address
chosen.

```rust,no_run
# async fn demo() -> anyhow::Result<()> {
use std::net::SocketAddr;
use axum::{Extension, Router, routing::post};
use owt_web::client_ip::{ClientIp, Source};

async fn sign_in(ClientIp(ip): ClientIp) -> String { ip.to_string() } // throttle on `ip`

let source = Source::from_env()?; // a typo in CLIENT_IP stops the app here
let app = Router::new().route("/login", post(sign_in)).layer(Extension(source));
let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
# Ok(()) }
```

**`jwt` is a feature** of `owt-auth`, on by default. It brings `jsonwebtoken` and,
through its RustCrypto backend, `rsa`, which carries RUSTSEC-2023-0071 (Marvin) with
no fixed release, so the app's `cargo audit` fails until it ignores that advisory.
`oauth` needs neither: it reads the ID token the token endpoint answered over TLS and
checks its claims (OIDC Core 3.1.3.7), not its signature. An app that names `owt-auth`
only for passwords, throttles or `oauth` turns the feature off:

<!-- x-release-please-start-version -->
```toml
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.8.0", default-features = false }
```
<!-- x-release-please-end -->

An app that verifies bearer tokens keeps it, and says why the advisory does not apply
in its `.cargo/audit.toml`:

```toml
[advisories]
ignore = [
    # rsa: Marvin, a timing side channel on private-key operations (decryption,
    # signing); no fixed release. It arrives through owt-auth's `jwt` feature, which
    # only verifies signatures, a public-key operation.
    "RUSTSEC-2023-0071",
]
```

### Accounts

`owt-accounts` is the sign-in every app wrote over the pieces above: an `accounts`
table with a session epoch, `authenticate` with the decoy check and rehash, a
walled extractor, sign-out everywhere. The app keeps its pages (the sign-in form is
its template), its extra columns (`ALTER TABLE accounts ADD COLUMN …` in a migration
of its own) and the choice of flows (self-signup or not, which providers, whether
links are minted).

It builds `owt-auth` without the `jwt` feature, so an app on it has neither
`jsonwebtoken` nor `rsa`, and needs no audit ignore, unless the app turns `jwt` on
itself (an `owt-auth` dependency with default features does; see above).

**Tables:** write each of `owt_accounts::migrations::ALL`, in order, to the app's
`migrations/`. A new app writes them first (`0001_owt_accounts.sql`,
`0002_owt_accounts_roles.sql`, `0003_owt_accounts_constraints.sql`,
`0004_owt_accounts_policies.sql`, `0005_owt_accounts_local.sql`), since its
tables reference `accounts(id)`. An app that has migrations of its own gives a newly
released entry its next unused version (`0007_owt_accounts_roles.sql` after its
`0006_…`), never a number already applied: sqlx refuses a file whose version it ran
with other contents. A test calls
`owt_accounts::migrations::assert_installed("migrations")`, which matches the files
by content, not name, so an edited or missing copy fails the build. sqlx keeps one
ledger per database, which is why the library does not run a migrator of its own. A
shipped migration never changes (sqlx would refuse the re-copied file at deploy, its
checksum differing from the applied one): a later release appends a new entry to
`ALL`, and a test here pins each file's SHA-256. A migration moves the rows
already there along with the schema, so a database that has run the library for years
ends in the state a new one starts in. The constraints hold what the library assumes
(names in stored form, Argon2 hashes or none, no hash where password sign-in is off,
links of 30 days at most, non-empty subjects), so a row written around it (an import, a console) cannot be one it would
misread. After the migrations run, at every start and before serving, the app awaits
`owt_accounts::migrations::complete(&pool)`: it moves rows made before a migration
to the stored form (in Rust, as sign-in normalizes) and validates the constraints
the migration added; once done it reads an index and the catalog.

```rust,no_run
# async fn start(pool: sqlx::PgPool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
owt_runtime::db::migrate_locked(&pool, migrator, 8_531_207).await?;
let done = owt_accounts::migrations::complete(&pool).await?;
for r in &done.renamed {
    eprintln!("account {} is now {:?} (was {:?}): tell its owner", r.id, r.to, r.from);
}
// ... then serve.
# Ok(()) }
```

**Names the migrations take**, in the schema they run in (the first on the
`search_path`, usually `public`):

| Migration | Tables | Indexes and sequences | Functions | Added to an earlier table |
|---|---|---|---|---|
| `owt_accounts` | `accounts`, `account_identities`, `sign_in_links` | `accounts_pkey`, `accounts_id_seq`, `accounts_username_key`, `accounts_email_key`, `account_identities_pkey`, `account_identities_id_seq`, `account_identities_provider_subject_key`, `account_identities_account`, `sign_in_links_pkey`, `sign_in_links_account` | | |
| `owt_accounts_roles` | `account_roles` | `account_roles_pkey`, `account_roles_role` | | |
| `owt_accounts_constraints` | | `accounts_username_skeleton_key` | | `accounts.username_skeleton`; constraints `accounts_username_skeleton_form`, `accounts_password_hash_form`, `accounts_username_nfkc`, `accounts_email_form`, `accounts_session_epoch_check` on `accounts`, `account_identities_named` on `account_identities`, `sign_in_links_lifetime` and `sign_in_links_digest` on `sign_in_links` |
| `owt_accounts_policies` | `policy_versions`, `policy_acceptances`, `policy_acceptance_events` | `policy_versions_pkey`, `policy_versions_id_seq`, `policy_versions_kind_version_key`, `policy_acceptances_pkey`, `policy_acceptances_version`, `policy_acceptance_events_pkey`, `policy_acceptance_events_id_seq`, `policy_acceptance_events_account` | `policy_versions_immutable()`, `policy_versions_keep_current()` | |
| `owt_accounts_local` | `account_local_identities` | `account_local_identities_pkey`, `account_local_identities_account` | | `accounts.password_sign_in`; constraint `accounts_password_sign_in_hash` on `accounts` |

Each table is also a type of its name, and its triggers and constraints are its own.
An app that already has any of these names (a table, view, index, sequence, type or
function, or a column or constraint of that name on the table named) renames its own
first, in a migration of its own placed before owt-accounts' files. A taken table or index name fails the migration at `CREATE`; a
taken key index or sequence name is worse: Postgres gives the library's a suffix
silently, and the library no longer recognizes a taken username. Renaming a table
keeps the names of its indexes and sequences, so rename those
too (`ALTER INDEX accounts_pkey RENAME TO holdings_pkey`, and so on). When the
migrations fail, `owt_accounts::migrations::conflicts(&pool)` names each name
something else holds, skipping migrations sqlx's ledger records as applied; a test
can call it against a copy of the app's schema before adopting the crate. Migrate with
`migrate_locked`, not `Migrator::run` on the pool: a failed `run` keeps sqlx's
database-wide advisory lock on the connection it returns to the pool, where every later
migration waits on it, while `migrate_locked` closes that connection.

```rust,no_run
# async fn start(pool: sqlx::PgPool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
if let Err(e) = owt_runtime::db::migrate_locked(&pool, migrator, 8_531_207).await {
    for clash in owt_accounts::migrations::conflicts(&pool).await? {
        // "public.accounts is already a table, and owt-accounts' `owt_accounts`
        // migration creates accounts: rename the app's ..."
        eprintln!("{clash}");
    }
    return Err(e);
}
# Ok(()) }
```

**Provider identities are found by subject, never by email.** `identities::arrive`
looks up the provider's key and the identity's subject, and nothing else. An address
changes at the provider and can pass to someone else (a recycled workplace mailbox, a
re-registered domain, an issuer that vouches loosely), so a newcomer whose verified
email matches an account is still a stranger: they get a new account without the
address (or `Unknown` without self-signup). A person adds a provider to their account
by signing in to it first and calling `identities::link` from that session. Two first
sign-ins with one identity at once (a callback opened twice) wait for each other and
resolve to one account. A created account takes the provider's verified address as
its own sign-in email only with `Welcome::record_email`, for providers whose
verification the app trusts; otherwise the address stays in the identity's claims,
and no loosely vouched address can be taken before its owner registers.

An OIDC issuer is operator configuration, never a tenant's or a visitor's input: it
is the namespace its subjects are trusted in, so two configurations naming one issuer
share people. `identities::list` returns `Linked::provider` as stored, the issuer's
URL for an OIDC provider and the id (`google`) for a preset; match it against
`Provider::key()`, not `Provider::id`.

**Local and system accounts have no provider and no password.** An app that vouches
for someone itself (its own check: a kiosk's code, a device it enrolled) or keeps an
account its jobs act as reaches it with `identities::arrive_as(&pool, key, subject,
create)`: `key` is a namespace of the app's own and `subject` an id in it. These
local identities are stored apart from providers' identities, so no provider's
subject ever matches one (a key of `google` is not Google's), and `identities::list`,
`unconfigured` and the connections page never show one. Given a username, an unknown
pair creates an account under it (a number after it when taken) with no email and
**password sign-in off**; given `None`, it finds only. With password sign-in off,
`store::authenticate` never finds the account, by username or email, `store::by_email`
does not either (so a reset by email cannot reach it), and `store::set_password`
refuses it with `Refused::NoPasswordSignIn` (the admin's generated password too).
`store::set_password_sign_in(&pool, id, false)` turns it off for any account,
clearing its password and signing it out everywhere (its sessions end and its unused
sign-in links are void); turning it back on sets no password. A sign-in link an
operator mints after that still opens such an account. A local identity is a way in,
so `identities::unlink` lets a provider beside one go. `identities::forget_as(&pool,
key, subject)` retires one (a device lost or re-enrolled): the pair reaches nothing
after, and the account it reached is signed out everywhere, links voided, but kept
(deactivate it too to retire it whole). `arrive_as_in` works in the app's
transaction, as `arrive_in` does.

```rust,no_run
# async fn demo(
#     pool: sqlx::PgPool, session: owt_web::session::Session<owt_accounts::session::Data>,
#     device: &str, id: i64,
# ) -> anyhow::Result<()> {
use owt_accounts::{identities, session, store};
// The app's own check passed for this device: its account, made at first use.
let arrival = identities::arrive_as(&pool, "kiosk", device, Some("kiosk")).await?;
if let Some(account) = arrival.account() {
    session::sign_in(&session, account);
}
// The account the app's jobs act as, found or made at start.
let jobs = identities::arrive_as(&pool, "system", "jobs", Some("jobs")).await?;
// An existing account that no password opens any more.
store::set_password_sign_in(&pool, id, false).await?;
// The device was lost: its pair reaches nothing now, and its sessions are over.
let _retired: Option<i64> = identities::forget_as(&pool, "kiosk", device).await?;
# let _ = jobs; Ok(()) }
```

**Upgrading from 0.4 (roles and admin):** install `ALL[1]` (roles) as the app's next
migration (above). `Account` gains `roles`, read by `store::COLUMNS`, now public; a
query of the app's own that decodes an `Account` without it reads no roles. The
admin's `Admin::routes` nests itself at its base: merge it, don't nest it.

**Upgrading from 0.4 (identities):** identities are stored under `Provider::key()`: the issuer for
an OIDC provider (it used to be the id, `sso`), and `google`, `discord` or `twitch`
for the presets (unchanged, if the app passed exactly those names). An identity
under any other key is a stranger at its next sign-in (a second, empty account with
self-signup on; refused without). At start, before serving, move the old rows and
refuse to serve while any remain:

```rust,no_run
# async fn start(pool: sqlx::PgPool, sso: owt_auth::oauth::Provider) -> anyhow::Result<()> {
use owt_accounts::identities;
let configured = [&sso, &owt_auth::oauth::google()];
// Refused when "sso" is still a configured provider's key, or is the issuer's.
let moved = identities::rekey(&pool, "sso", &sso, &configured).await?;
// A subject the new key has already: that person signed in between the deploy
// and the rekey, and has two accounts. Which to keep is a person's decision.
anyhow::ensure!(moved.conflicts.is_empty(), "identities to reconcile: {:?}", moved.conflicts);
let stray = identities::unconfigured(&pool, &configured).await?;
anyhow::ensure!(stray.is_empty(), "identities under keys no provider gives: {stray:?}");
# Ok(()) }
```

An issuer is written in canonical form (a lower-case host, no default port, no
trailing `/`); `oidc` refuses another spelling, since it would match no token's
`iss`.

**Logins:** a username is one token without `@`; an email always has one. So a login
is never both, and nobody can register a username equal to someone else's email to
shadow their sign-in. The table's `CHECK` enforces it on writes made around the
library. An email is a sign-in name too (with the password), not only contact data.

**Usernames cannot pass for one another.** Logins are stored NFKC-normalized and
lower-cased (`ＡＤＭＩＮ` is `admin`; a composed and a decomposed `é` are one name). A new
username is letters, digits and combining marks that Unicode's identifier profile
allows (UTS #39), or `-`, `.` and `_`, starting with a letter or digit, in one
script: no zero-width or filler characters, no bidirectional controls, no Cyrillic
`а` inside a Latin `admin`. `store::username_problem` checks that rule alone, without
the database, so a sign-up form can show it beside the field with the others. And no
new name may look like an existing one: each account stores its username's confusable
skeleton (`store::skeleton`, Unicode TS #39), unique, so `paypa1` beside `paypal`, the
all-Cyrillic `сосо` beside `coco`, or `modem` beside `modern` is refused
(`Refused::UsernameLookalike`); a provider sign-up moves on to another name. The
skeleton is deliberately broad: `rn` is `m`, `0` is `o`, `1` is `l`. Accounts older
than the rule that already look like an earlier one keep their names; the rule holds
every name made after.

**Revocation, and what it does not reach:**

- `session::sign_out` replaces this browser's cookie; a copy of it taken earlier
  still opens until it expires. Only `sign_out_everywhere` (the epoch) revokes.
- A password change, deactivation or a demotion ends every session at its next
  request, but a stream opened before (SSE, a WebSocket) was checked at its start:
  an app that streams to signed-in people re-checks `store::by_id_in_epoch` on
  each event, or closes streams on a schedule.
- `store::authenticate` stands only if the hash it checked is still the account's,
  so a sign-in with the old password that finishes after a change fails.
- The sign-in throttle counts each login string: an account's username and its
  email are two budgets. An app that wants one per account also charges the
  throttle with the account's id once the login resolves.
- Everything that revokes an account's sessions moves `accounts.session_epoch`
  (`sign_out_everywhere`, `set_password` and `change_password`, deactivating,
  revoking staff, turning password sign-in off), and nothing else does. An app that keeps something per account
  that must go with the sessions (a provider's tokens, sealed) puts a trigger on
  that column in a migration of its own, so it goes in the same transaction
  whichever path revoked, the staff pages and a console included. The `WHEN` clause
  matters: `set_active`, `set_staff` and `set_password_sign_in` write the column
  even when it does not change.

```sql
-- migrations/0009_provider_tokens.sql (the app's next unused version)
CREATE TABLE provider_tokens (
    account_id bigint PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    sealed text NOT NULL
);

CREATE FUNCTION forget_provider_tokens() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM provider_tokens WHERE account_id = NEW.id;
    RETURN NULL;
END $$;

CREATE TRIGGER forget_provider_tokens
    AFTER UPDATE OF session_epoch ON accounts
    FOR EACH ROW WHEN (NEW.session_epoch <> OLD.session_epoch)
    EXECUTE FUNCTION forget_provider_tokens();
```

```rust,no_run
# async fn demo(
#     pool: sqlx::PgPool, session: owt_web::session::Session<owt_accounts::session::Data>,
#     ip: std::net::IpAddr, login: &str, given: &str, who: owt_auth::oauth::Identity,
#     discord_who: owt_auth::oauth::Identity,
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
// An htmx request (not a boosted one) meets the wall as a 204 with `HX-Redirect` instead:
// htmx would follow a 303 and swap the sign-in page into its target. Its `?next=` is the
// page the visitor was on (`HX-Current-URL`, when it is this site's: the same host as the
// request), not the fragment. A fragment polling a page still open after a sign-out
// takes the whole page to sign-in, and back to that page after.
async fn admin(Staff(me): Staff) -> String { me.username } // signed in, not staff: 403
// Database down: `Maybe` reads as anonymous, `Signed` and `Staff` answer 503 (the
// sign-in page could not help), and the cookie keeps its signature for when it is back.
let app: Router = Router::new()
    .route("/", get(home))
    .route("/settings", get(settings))
    .route("/admin", get(admin))
    .layer(from_fn_with_state(accounts, Accounts::load::<session::Data>));

// Sign-in: throttle, authenticate (by username or email; an unknown login costs a
// real check; an old hash is replaced; `last_sign_in` is stamped), then the session:
// new id, account and epoch. A refusal's message is the form's error, its status the
// answer's: 429 throttled (`Retry-After: SignInRefused::RETRY_AFTER`), 422 a mismatch
// that says neither which part was wrong nor whether the account exists, 500 a fault
// (whose message says only that; log its source).
let throttle = Throttle::default(); // in the app's state
match session::password_sign_in(&pool, &throttle, &session, ip, login, given).await {
    Ok(account) => { let _ = account; /* redirect to `next` */ }
    Err(refused) => { let _ = (refused.status(), refused.to_string()); /* the form again */ }
}
session::sign_out(&session); // this session
session::sign_out_everywhere(&pool, &session).await?; // every session: the epoch moves

// Accounts: normalized, password rules checked (`owt_accounts::password`), a taken
// username or email refused by the constraint, so two racing sign-ups cannot both win.
// A sign-up form shows every problem at once: `store::problems` lists each refusal
// `create` would give (shapes, password rules, a name or email taken or too alike),
// after `throttle.attempt(ip)`, since it says which names have accounts.
// `store::username_problem` is the username rule alone, without the database.
assert_eq!(store::username_problem("Ada"), None);
let new = New {
    username: "Ada", email: "ada@example.com", password: Some("correct horse battery"), is_staff: false,
};
if !throttle.attempt(ip) {
    return Ok(()); // 429
}
if !store::problems(&pool, &new).await?.is_empty() {
    return Ok(()); // the form again, with every problem
}
// `create_in` instead, inside the transaction that makes the app's own rows.
let ada = store::create(&pool, new).await?;
store::set_password(&pool, &ada, "a different passphrase").await?; // staff or a link's reset: signs out everywhere
// The account's own change asks for the current password (Refused::CurrentPassword),
// so whoever holds a session cannot also take the password; throttle it like a sign-in.
store::change_password(&pool, &ada, "a different passphrase", "yet another passphrase").await?;
store::set_staff(&pool, ada.id, true).await?; // revoking signs out; granting does not

// A provider's identity (from `oauth::Client::complete`) becomes an account per policy:
// linked already (by subject), created, or unknown.
// `record_email`: a created account takes the provider's verified address.
let welcome = identities::Welcome { create: true, record_email: false };
let google = owt_auth::oauth::google();
if let Some(account) = identities::arrive(&pool, &google, &who, welcome).await?.account() {
    session::sign_in(&session, account);
}
// Or in the app's transaction, so what it keeps beside the account (the provider's
// tokens, sealed) commits with the arrival or not at all.
let mut tx = pool.begin().await?;
let arrival = identities::arrive_in(&mut tx, &google, &who, welcome).await?;
if let Some(account) = arrival.account() {
    sqlx::query("INSERT INTO provider_tokens (account_id, sealed) VALUES ($1, $2)")
        .bind(account.id).bind("…").execute(&mut *tx).await?;
}
tx.commit().await?;
// Adding a provider: only from a session signed in to the account (`Signed(me)`).
identities::link(&pool, ada.id, &owt_auth::oauth::discord(), &discord_who).await?;

// A one-time sign-in link, minted by an operator; only its SHA-256 is stored. The
// lifetime is capped at `links::MAX_TTL` (30 days), and `Minted`'s Debug leaves the
// token out. It travels in the URL, so it reaches access logs and link scanners that
// open it: the app's route shows a page with a button that POSTs it, and redeems on
// that POST, not on the GET.
let minted = links::mint(&pool, ada.id, std::time::Duration::from_secs(900), "new account").await?;
let _url = format!("https://app.example/login/link/{}", minted.token);
let _opened = links::redeem(&pool, &minted.token, &ip.to_string()).await; // Refused::Link when spent
# let _ = app; Ok(()) }
```

A refusal (`owt_accounts::Refused`) carries the sentence the person reads; a handler
matches `Error::Refused` to re-render the form with it, and the `From` into
`owt_web::Error` answers 422 with the same text.

**More about the viewer on every request** (a display name, a profile flag): implement
`store::Extra` for a `sqlx::FromRow` type of the app's and install
`Accounts::load_with::<session::Data, Viewer>` in place of `Accounts::load`. Its
`QUERY` is a `SELECT` that names the account's row as `accounts`; the layer runs it as
a `LEFT JOIN LATERAL` in the one query that loads the account and checks the session's
epoch, so it costs no second round trip and a revoked session reads nothing. A
handler names `SignedWith<Viewer>` (walled as `Signed`) or `MaybeWith<Viewer>`;
`Maybe`, `Signed`, `Staff` and `roles::Holds` work as before. `QUERY` is SQL pasted
as it is, so it is a constant in the app's code, never built from a request; it binds
no parameters. Its columns are named apart from the account's (`id`, `username`,
`email`, `is_staff`, `is_active`, `session_epoch`, `roles`): a row with a name twice
(`SELECT p.*` of a table with an `id`, an extra `roles`) is refused, never read in
place of the account's. That refusal, and a column that fails to decode, fail the
load as a database outage would, on every walled page, so an app sees it at once. A
viewer with no joined row reads `NULL` in each column (make the field an `Option`).
`QUERY` yields at most one row: several fail the load too, rather than pass one off
as the viewer's. Join on a key or end with `LIMIT 1`, and never name `accounts` in
its own `FROM` (that reads the whole table, not the viewer's row).
`store::by_id_in_epoch_with` is the same query outside the
layer (a stream re-checking its viewer).

```rust,no_run
use axum::{Router, middleware::from_fn_with_state, routing::get};
use owt_accounts::{Accounts, SignedWith, session, store};

#[derive(Clone, sqlx::FromRow)]
struct Viewer {
    display_name: Option<String>, // from the app's `profiles`, if the viewer has one
    beta: bool,                   // the app's own column on `accounts`
}

impl store::Extra for Viewer {
    const QUERY: &'static str = "SELECT accounts.beta, (SELECT p.display_name
        FROM profiles p WHERE p.account_id = accounts.id) AS display_name";
}

async fn home(SignedWith(me, viewer): SignedWith<Viewer>) -> String {
    viewer.display_name.unwrap_or(me.username)
}

# fn demo(accounts: Accounts) {
let app: Router = Router::new()
    .route("/", get(home))
    .layer(from_fn_with_state(accounts, Accounts::load_with::<session::Data, Viewer>));
# let _ = app; }
```

#### Roles

Three tiers, and the third is the app's:

| Tier | Held by | Extractor |
|---|---|---|
| user | every active, signed-in account | `Signed` |
| staff | `accounts.is_staff` (`store::set_staff`) | `Staff` |
| a role the app declares | a row of `account_roles` (`roles::grant`), or staff too when the role is `held_by_staff()` | `roles::Holds<R>` |

A role is a constant in the app's code; the database holds only who has it (with who
granted it). `Account::roles` is read with the account on every request, so a revoked
role is refused at the holder's next request, without signing them out.

```rust,no_run
# async fn demo(pool: sqlx::PgPool, ada: owt_accounts::Account, boss: owt_accounts::Account) -> anyhow::Result<()> {
use owt_accounts::roles::{self, Holds, Named, Role};

/// May run a live session. Staff may too, without a grant.
pub struct Host;
impl Named for Host {
    const ROLE: Role = Role::new("host", "Host", "May run a live session.").held_by_staff();
}

async fn start_session(Holds(me, _): Holds<Host>) -> String { me.username } // others: 403

roles::grant(&pool, ada.id, &Host::ROLE, Some(boss.id)).await?; // `false` when already held
let _hosts = roles::holders(&pool, &Host::ROLE).await?; // active holders, staff included here
let _may_host = ada.holds(&Host::ROLE); // from the loaded account, no query
roles::revoke(&pool, ada.id, &Host::ROLE).await?;
// Page chrome, from a request's extensions: show the link only to hosts.
# let req: axum::extract::Request = axum::extract::Request::default();
let _show_host_link = roles::signed_in_holds(req.extensions(), &Host::ROLE);
# Ok(()) }
```

A role name is lower-case letters, digits and `_`, a letter first, and none of
`roles::RESERVED` (`user`, `staff`, `inactive`); `Role::new` checks it at compile time
(and is the only way to make a `Role`), and the table's `CHECK` on writes. A role the
app stops declaring keeps its rows, and `Account::holds` matches by name: the admin
shows such a role on the account's page so staff can revoke it, and a name declared
again later grants whatever it means then to whoever still holds it.
An app moving a boolean column onto a role (`can_host`, say) copies it in its own
migration: `INSERT INTO account_roles (account_id, role) SELECT id, 'host' FROM
accounts WHERE can_host`, then drops the column.

#### The accounts admin

`owt_accounts::admin` is the staff pages for accounts, mounted once: find (search by
username, email or the app's own columns; filter by staff, each role, or deactivated;
paged), create (username, email, staff, roles; no password), and change (email,
active, staff, each role; a generated password or a sign-in link, shown once; sign out
everywhere; remove a sign-in connection; turn password sign-in on or off; retire a
local identity). Lists show `admin::PER_PAGE` accounts a page.

An account with password sign-in off (a local or system account from
`identities::arrive_as`, say) carries a "Password sign-in off" badge in the list, and
its page says so and offers no password, only a button to turn it on. Turning it off
there removes the password and signs the account out everywhere, as
`store::set_password_sign_in` does. The page lists the account's local identities
(key, subject, when added and last used), each with a button that retires it through
`identities::forget_as`, which signs the account out everywhere too.

- **Who:** only `Staff`, and each change re-checks inside its transaction that its
  author is still active staff (locking both rows, so two staff removing each other at
  once cannot leave none). It refuses your own staff access, deactivating yourself,
  turning your own password sign-in off, retiring your own local identity, unlinking
  an account's last way in and a password for an account whose password sign-in is
  off.
- **From where:** the routes refuse a cross-origin `POST` themselves, with
  `owt_web::csrf::CrossOrigin`, whatever the app layers: `SameSite=Lax` alone lets a
  sibling subdomain post.
- **What a revocation takes:** a generated password, deactivation and "sign out
  everywhere" end every session and void the account's unused sign-in links (in the
  same statement); removing a sign-in connection, retiring a local identity and
  turning password sign-in off sign the account out everywhere too.
  A link is not issued to a deactivated account.
- **What is kept:** every response is `no-store` and never framed, a refusal (a 403,
  a 404, a 422) included; a password or link is shown once; each change is logged at
  `info` with who made it and what changed.

The app gives it a layout and, optionally, its roles, a sign-in-link route, a link
to its own page about each account (what the admin does not show: a nickname, what
they own) and a search of its own columns. The layout is a `Chrome` (a closure from
`Page` to a response, as below) or, where it reads something per page before it
wraps the body (an inbox count, the viewer's display name), an `admin::AsyncChrome`:
a type whose `page` returns a boxed future borrowing the `Page`, awaited by the admin.
`policies::AsyncChrome` is the same for the policy pages. Every `Chrome` is an
`AsyncChrome` too, so a layout that awaits nothing changes nothing.

```rust,no_run
use std::pin::Pin;
use axum::response::{Html, IntoResponse, Response};
use owt_accounts::admin::{AsyncChrome, Page};

struct Shell { pool: sqlx::PgPool }

impl AsyncChrome for Shell {
    fn page<'a>(&'a self, page: Page<'a>) -> Pin<Box<dyn Future<Output = owt_web::Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            let unread: i64 = sqlx::query_scalar("SELECT count(*) FROM inbox WHERE account_id = $1")
                .bind(page.me.id)
                .fetch_one(&self.pool)
                .await?;
            // The app's Askama layout escapes the title and embeds the body as it is.
            Ok(Html(format!("<title>{}</title><nav>{unread}</nav>{}", page.title, page.body)).into_response())
        })
    }
}
# fn demo(pool: sqlx::PgPool) {
let _admin = owt_accounts::admin::Admin::new(pool.clone(), "/staff/accounts", Shell { pool });
# }
```

`Admin::search` names what it searches (the box reads "Username, email or nickname")
and gets the trimmed term, never an empty one; it answers the ids of the accounts it
matches, which the list shows with
the username and email matches, once each, under the same filters, order and pages.
An id with no account is ignored. Bind the term, never format it into SQL (and in a
`LIKE` its `%` and `_` are wildcards; `strpos` takes it as text). When it fails, the
admin logs the error at `warn` and lists the username and email matches alone, saying
so on the page.

```rust,no_run
# fn demo(pool: sqlx::PgPool, accounts: owt_accounts::Accounts) {
# use owt_accounts::roles::{Named, Role};
# pub struct Host;
# impl Named for Host { const ROLE: Role = Role::new("host", "Host", "May run a live session."); }
use askama::Template;
use axum::response::{Html, IntoResponse};
use owt_accounts::admin::{Admin, Body, Page};

// The app's shell around the admin's body: its own Askama layout, which escapes the
// title (an account's username, which its owner chose) and embeds the body, already
// escaped by the admin, as it is. Never `format!` the title into HTML. The request's
// extensions hold what the layout reads (session, nonce, account), and its `uri` is
// the page's own (`/staff/accounts?q=ada`), not the nested router's stripped path.
#[derive(Template)]
#[template(source = "<!doctype html><title>{{ title }}</title><main>{{ body }}</main>", ext = "html")]
struct Shell<'a> { title: &'a str, body: Body }
let chrome = |page: Page<'_>| -> owt_web::Result<axum::response::Response> {
    let html = Shell { title: page.title, body: page.body }.render().map_err(|e| owt_web::Error::Internal(e.into()))?;
    Ok(Html(html).into_response())
};
let profiles = pool.clone();
let admin = Admin::new(pool, "/staff/accounts", chrome)
    .roles(&[Host::ROLE])
    .sign_in_links(std::time::Duration::from_secs(86_400), |token| {
        format!("https://myapp.example/login/link/{token}") // the app's `links::redeem` route
    })
    .more("Profile", |a| format!("/staff/profiles/{}", a.id))
    .search("nickname", move |term| {
        let pool = profiles.clone();
        async move {
            let ids: Vec<i64> = sqlx::query_scalar(
                "SELECT account_id FROM profiles WHERE strpos(lower(nickname), lower($1)) > 0",
            )
            .bind(term)
            .fetch_all(&pool)
            .await?;
            Ok(ids)
        }
    });
let _app: axum::Router = axum::Router::new()
    .merge(admin.routes()) // at /staff/accounts; `Staff` only, same-origin posts only
    .layer(axum::middleware::from_fn_with_state(accounts, owt_accounts::Accounts::load::<owt_accounts::session::Data>));
# }
```

Its markup (`admin::Tailwind`, the default) carries only `owt-*` classes from
`tailwind/owt.css` (buttons, tables, badges, checkboxes), so it takes the app's tokens
with no CSS of the app's. A test here fails if a template names a class the stylesheet
lacks.

**Its words** are `admin::Words`: what staff are called, the headings, hints, buttons,
badges, filters and the one-line outcomes, English (`Words::ENGLISH`) unless the app
passes its own to `Admin::words`. Build them from the English with struct update
syntax, so a word added later needs nothing from the app; a `{what}`, `{name}`,
`{username}`, `{lifetime}` or `{n}` in a sentence stands for what the admin fills in. The
view models carry the words (`ListView::words`, and the others'), so an app's own
`Views` draws its markup with the same ones, and `Words::duration` writes a lifetime
in them.

```rust,no_run
use owt_accounts::admin::{Admin, Words};
# fn demo(pool: sqlx::PgPool, chrome: fn(owt_accounts::admin::Page<'_>) -> owt_web::Result<axum::response::Response>) {
let words = Words {
    staff: "Team",
    staff_hint: "May use the team pages, this one included. Removing it signs the account out.",
    staff_hint_new: "May use the team pages, this one included.",
    cannot_remove_own_staff: "You cannot take away your own team access.",
    ..Words::ENGLISH
};
let admin = Admin::new(pool, "/staff/accounts", chrome).words(words);
# let _: axum::Router = admin.routes();
# }
```

An app with another design system draws the pages itself: it implements
`admin::Views` and passes it to `Admin::views`. Each method gets a page's view model
(`ListView`, `NewView`, `AccountView`: what the page shows, the URLs its links and
forms use, and on each type's docs the fields its forms post) and answers the body,
which the app's `Chrome` then wraps as before. A method left out draws the `owt-*`
page. The routes, the staff check, the cross-origin refusal, the locking, the
refusals and the log stay in the admin whatever the markup: a page that leaves out
the "Staff" box on your own account is the app's choice, and a post that takes it
away is still refused.

The body is embedded as it is, so render the view models only through a template
Askama escapes HTML in: a file ending `.html`, or a `source` with `ext = "html"`.
Usernames, emails and provider labels are their owners' text; a `.txt` or `.md`
template, `escape = "none"` or a `|safe` prints them as markup on a staff page. If
the app's account page fails while showing a new password or sign-in link (already
made, and shown once), the admin logs the error and shows it on the `owt-*` page
instead.

```rust,no_run
use askama::Template;
use axum::http::request::Parts;
use owt_accounts::admin::{Body, ListView, Views};
use owt_web::ui::Kind; // what each pager item is, for the `match` below

#[derive(Template)]
#[template(source = r#"<table class="pf-table">
{% for r in v.rows %}<tr><td><a href="{{ r.href }}">{{ r.username }}</a></td>
<td>{% for b in r.badges %}<span class="pf-label">{{ b.text }}</span>{% endfor %}</td></tr>
{% endfor %}</table>
{% if v.pagination.pager.is_paginated() %}<nav class="pf-pagination" aria-label="Pages">
{% for i in v.pagination.items() %}{% match i.kind %}
{% when Kind::Previous %}<a href="{{ i.href }}" rel="prev">Previous</a>
{% when Kind::Next %}<a href="{{ i.href }}" rel="next">Next</a>
{% when Kind::Current %}<span aria-current="page">{{ i.label }}</span>
{% when Kind::Gap %}<span aria-hidden="true">…</span>
{% when _ %}<a href="{{ i.href }}">{{ i.label }}</a>{# a page link, and whatever kind comes later #}
{% endmatch %}{% endfor %}</nav>{% endif %}"#, ext = "html")]
struct AccountList<'a, 'b> { v: &'a ListView<'b> }

struct MyViews;

impl Views for MyViews {
    // The request's extensions hold the locale, nonce and session, as for `Chrome`.
    fn list(&self, _request: &Parts, view: &ListView<'_>) -> owt_web::Result<Body> {
        Body::render(&AccountList { v: view })
    }
    // `new_account` and `account` likewise, from `NewView` and `AccountView`.
}
# fn demo(pool: sqlx::PgPool, chrome: fn(owt_accounts::admin::Page<'_>) -> owt_web::Result<axum::response::Response>) {
let admin = owt_accounts::admin::Admin::new(pool, "/staff/accounts", chrome).views(MyViews);
# let _: axum::Router = admin.routes();
# }
```

**Testing your templates.** With `owt-accounts`' `test-util` feature in the app's
dev-dependencies (`owt-accounts = { git = "…", tag = "…", features = ["test-util"] }`
under `[dev-dependencies]`, beside the plain one under `[dependencies]`),
`ListView::example()`, `NewView::example()` and `AccountView::example()` are filled-in
view models: every field holds a value, with one of each badge, a notice, a secret, a
refused email, a declared and an undeclared role, a connection and a local identity,
so a template that prints every field is exercised with no database and no sign-in.
A username in them holds a `<`, so a template that stops escaping fails its test.
Render each page through the app's `Views` and snapshot the body with
`owt_test::golden`, or assert on it:

```rust
use axum::http::Request;
use owt_accounts::admin::{AccountView, ListView, NewView, Views};
# struct MyViews;
# impl Views for MyViews {}

let parts = Request::get("/staff/accounts").body(()).unwrap().into_parts().0;
let list = MyViews.list(&parts, &ListView::example()).unwrap();
assert!(list.to_string().contains("ada"));
let _new = MyViews.new_account(&parts, &NewView::example()).unwrap();
let account = MyViews.account(&parts, &AccountView::example()).unwrap();
assert!(account.to_string().contains("correct-horse-battery-staple")); // the secret shown once
```

#### Site policies

`owt_accounts::policies` tracks which version of each of the app's policies (its
terms, its privacy notice) each account has agreed to. It asks again when one
changes. The app declares the documents and writes their text, and supplies its
layout as for the admin. The tables come from `0004_owt_accounts_policies.sql`
(above), and they start empty.

- **Versions:** staff write a draft, preview it and publish it. Publishing numbers
  it (1, 2, 3… per document), fixes its text for good (a trigger refuses any change)
  and records the SHA-256 of that text. A document with no published version is
  not asked for.
- **The gate:** a signed-in account that has not accepted the current version of
  each document is sent to the page that asks (`/agree?next=…`) before any other
  page. This includes an account just made through a provider, and someone already
  signed in when a new version is published. Only a document load is sent (a `GET`
  made for a `Sec-Fetch-Dest: document` or, from a browser that sends no such
  header, asking for `text/html`; an htmx request only when it is a boosted
  navigation, which swaps in a whole page), so what a page loads for itself (an
  image, a script, a fetch), a socket, a stream or a fragment is never interrupted,
  nor a non-browser client that asks for no HTML. If the database can't say, the
  request goes through.
  The gate reads
  the account loaded for the request and caches nothing in the session, so a second
  person signing in on the same browser is asked for themselves.
- **The page that asks** shows only what is outstanding. For a document agreed to
  before, it shows the version agreed to and what changed (the draft's summary,
  required to publish any version after the first). It records exactly the versions
  it showed: if one is published while the person reads, they are asked again.
- **What is kept:** each account's latest acceptance per document, and an
  append-only record of every acceptance (version, hash, time, address, browser).
  An older version stays on record (at `/{slug}/v/{n}`) while it is somebody's
  latest acceptance. `policies::prune` removes the rest; run it on a schedule, or
  from the staff pages.
- **Where:** each document at `/{slug}` (or below a prefix, `documents_at`), the
  page that asks at `/agree` (`agree_at`), and the staff pages wherever `admin`
  puts them. They carry only `owt-*` classes and refuse a cross-origin `POST`
  themselves. With `sign_out`, the page that asks also offers a button posting to the
  app's sign-out route, for someone who would rather not agree.

```rust,no_run
# fn demo(pool: sqlx::PgPool, accounts: owt_accounts::Accounts) {
use askama::Template;
use axum::middleware::from_fn_with_state;
use axum::response::{Html, IntoResponse};
use owt_accounts::policies::{self, Document, Page, Policies};

#[derive(Template)]
#[template(source = "<!doctype html><title>{{ title }}</title><main>{{ body }}</main>", ext = "html")]
struct Shell<'a> { title: &'a str, body: owt_accounts::admin::Body }
let chrome = |page: Page<'_>| -> owt_web::Result<axum::response::Response> {
    let html = Shell { title: page.title, body: page.body }.render().map_err(|e| owt_web::Error::Internal(e.into()))?;
    Ok(Html(html).into_response())
};
// `TERMS` is at /terms and `PRIVACY` at /privacy; an app may declare others.
let cookies = Document::new("cookies", "Cookie Policy");
let policies = Policies::new(pool, chrome, &[policies::TERMS, policies::PRIVACY, cookies])
    .admin("/staff/policies") // staff only
    .agreement("I have read and agree to these, and I am at least 13 years old.")
    .exempt(&["/static/", "/ws/"]) // never sent to the page that asks
    .client_ip(owt_web::client_ip::Source::ForwardedFor { proxies: 1 }); // the address recorded
let _app: axum::Router = axum::Router::new()
    .merge(policies.routes())
    // Inside the accounts layer, which loads the account the gate reads.
    .layer(from_fn_with_state(policies, Policies::gate))
    .layer(from_fn_with_state(accounts, owt_accounts::Accounts::load::<owt_accounts::session::Data>));
# }
```

The first versions can be published from the staff pages, or in code (a one-off
command, a seed) with the same functions the staff pages use. `accept` records an
acceptance outside the page that asks, for a seeded account for example:

```rust,no_run
# async fn demo(pool: sqlx::PgPool, seeded: &[i64]) -> anyhow::Result<()> {
use owt_accounts::policies::{self, Draft};
let draft = policies::draft(&pool, "terms", Draft {
    title: "Terms of Service",
    effective_date: "2026-10-16",
    summary: "",
    body_markdown: "## Using the site\n\n…",
}, None).await?;
let v1 = policies::publish(&pool, draft.id).await?.expect("a draft with text");
for &id in seeded {
    policies::accept(&pool, id, &[v1.id], None, Some("seed")).await?;
}
let removed = policies::prune(&pool).await?; // nightly: versions nobody holds
# let _ = removed; Ok(()) }
```

Each replica keeps the current versions for 30 seconds (`refresh`). A version
published from the staff pages is asked for at once on that replica, and on others
within that time.

**Their words and markup** are the app's to give. `policies::Words` holds every word of
the pages everyone reads (a document and the page that asks), English unless the app
passes its own to `words`, built from `Words::ENGLISH` with struct update syntax; a
sentence's `{n}`, `{date}` and `{version}` go wherever the language puts them, and a
linked `{version}` stays a link. `dates` formats the `YYYY-MM-DD` dates those pages
show. An app with a design of its own implements `policies::Views`: each method
(`document`, `agree`, `admin_list`, `admin_form`) gets the page's view model, with
its URLs worked out and its words, and answers the body its `Chrome` wraps. The
methods default to the Tailwind pages (`policies::Tailwind`), so it overrides only
what it draws, and the staff pages stay in English unless it draws them. With the
`test-util` feature, each view model has an `example()` for the app's tests of its
templates.

```rust,no_run
# fn demo(policies: owt_accounts::policies::Policies) {
use axum::http::request::Parts;
use owt_accounts::admin::Body;
use owt_accounts::policies::{DocumentView, Views, Words};

#[derive(askama::Template)]
#[template(source = r#"<article class="prose"><h1>{{ v.version.title }}</h1>
<p>{{ v.date }}</p>{{ v.body }}</article>"#, ext = "html")]
struct Doc<'a, 'b> { v: &'a DocumentView<'b> }

struct Mine;
impl Views for Mine {
    fn document(&self, _: &Parts, view: &DocumentView<'_>) -> owt_web::Result<Body> {
        Body::render(&Doc { v: view }) // an .html template: it escapes the title
    }
}

let _policies = policies
    .views(Mine)
    .documents_at("/legal") // /legal/terms, /legal/terms/v/2
    .sign_out("/logout") // "Sign out instead" on the page that asks
    .words(Words { agree: "Accepter et continuer", ..Words::ENGLISH })
    .dates(|d: &str| d.split('-').rev().collect::<Vec<_>>().join("/")); // 01/10/2026
# }
```

### Sign-in with a provider

`owt_accounts::social` is the whole "Continue with Google" feature: the start,
callback and remove routes, their configuration, the sign-in buttons and the
connections list. The app writes no OAuth handler. It supplies four things:
credentials and its public URL (environment), a registration at each provider, a
session type that can hold a sign-in in progress, and two pages that embed the
pieces (its sign-in page and a settings page).

It keeps who signed in and nothing the provider granted. An app that calls the
provider's APIs as the person gets the tokens from its hooks (`on_arrival` and
`on_connect`, under "3. Wiring the app") and stores them itself. An app that needs
other routes writes its own callback over `oauth::Client::complete_with_tokens` (see
"Authentication"), then hands the identity to `identities::arrive` (or `arrive_in`,
to keep the tokens in the same transaction) or `link` as `social` does. Like
`social`'s, such a callback takes the pending sign-in out of the session first and answers every
failure after that, the database's included, with a redirect, never a 5xx: a 5xx
seals no session change, so the pending sign-in would outlive the callback that was
meant to use it up.

**What it does, and refuses:**

- A person is the provider's key plus its subject, never an email (see "Accounts").
  A first sign-in creates an account when `Welcome { create: true }`; otherwise it
  is turned away with `?social=unknown`.
- The start and remove are `POST` forms: layer the app's `CrossOrigin` around them
  (below). The pending sign-in (state, PKCE verifier, where to land) lives in the
  session and is used up by the first callback, whatever it brings, so a replayed or
  forged callback lands on `?social=expired` and so does the real one after it. It
  lapses after `social::PENDING_FOR` (10 minutes) and finishes only in the session
  it began in: one begun on a shared browser before its owner signed in (which
  replaces the session's id) finishes nothing. Sessions are sealed cookies, so a
  copy of the cookie made while a sign-in was pending still holds it; within those
  10 minutes such a copy is a stolen session, which can sign in as its owner anyway.
  And someone at an unlocked browser already signed in who starts a sign-in there
  can, for those 10 minutes, send its owner a link that signs the browser in to
  the starter's account: hands on a signed-in browser are beyond what this guards.
- A callback for one provider cannot finish a sign-in begun with another. `next` is
  followed only when it is a path on this site, and dropped when longer than
  `social::MAX_NEXT` bytes (it rides in the session cookie, which a browser drops
  past about 4 KB). Signing in cycles the session id.
- Connecting a provider (`connect=1` on the start form) needs a session signed in
  within the last 15 minutes (`SocialSignIn::connect_within`; older lands on
  `?social=sign-in-again`, so the sign-in page must let a signed-in person sign in
  again), checked when it starts and again when it comes back, and links only to the
  account that began it, even if someone else signs in on the browser meanwhile. A
  session that is not fresh therefore cannot quietly add a provider that outlives a
  password reset. Remove never removes the last way in,
  and never another account's connection (404).
- An identity linked to a deactivated account signs nobody in and creates nothing:
  `?social=unknown`.
- Every outcome redirects with `?social=<code>`, to the sign-in page or, for a
  connect or remove, the connections page; a database failure in the callback is
  logged at error level and lands on `?social=failed`. `social::outcome` turns the code into a
  message for `owt_web::ui::Alerts`.

#### 1. Configuration

`Providers::from_env(callback)` reads these at start and fails start-up, naming the
variable, when one is wrong (a credential in `PUBLIC_BASE_URL` is left out of the
message). A deployment never discovers a typo at a user's first sign-in.
`Providers::from_values(lookup, callback)` reads the same names through `lookup`
instead of the environment: a secrets manager, or a test.

| Variable | Required | Value |
|---|---|---|
| `PUBLIC_BASE_URL` | when any provider is set | The origin people reach the site at, exactly: `https://myapp.example`. No path, query, fragment or credentials, and no trailing slash (one is trimmed). `https` only, except `http://localhost:<port>`, `http://127.0.0.1:<port>` or `http://[::1]:<port>` for development. Behind a CDN or the OpenShift router, this is the public host, not the pod's. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | both or neither | From the Google Cloud console (below). Neither: no Google button. |
| `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET` | both or neither | From the Discord developer portal. |
| `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET` | both or neither | From the Twitch developer console. |

With no provider configured, `Providers` is empty: start and callback answer 404
(remove still answers, as for an account with no connections) and the buttons render
nothing, so one build serves a deployment with and without sign-in by
provider. Blank values count as unset. Setting one variable of a pair is an error.

An OpenID Connect issuer (Keycloak, an Entra tenant) is added in code, with its
issuer URL and endpoints from its discovery document
(`<issuer>/.well-known/openid-configuration`). Its identities are keyed by the
issuer, so pointing `sso` at a different realm later starts a fresh set of
identities rather than mixing two realms' users. The issuer and endpoints must be
`https` (`oidc` refuses others), and every sign-in must bring an ID token from that
issuer for this client. An app configuring providers without the environment uses
`Providers::new(public_base_url, callback)` and `.with(…)` for each:

```rust,no_run
# fn demo() -> anyhow::Result<()> {
use owt_accounts::social::{Providers, DEFAULT_CALLBACK};
use owt_auth::oauth;

let issuer = "https://sso.example/realms/staff";
let providers = Providers::from_env(DEFAULT_CALLBACK)?.with(
    oauth::oidc("sso", "Staff SSO", issuer,
        &format!("{issuer}/protocol/openid-connect/auth"),
        &format!("{issuer}/protocol/openid-connect/token"),
        &format!("{issuer}/protocol/openid-connect/userinfo"))?,
    owt_runtime::env::required("SSO_CLIENT_ID")?,
    owt_runtime::env::required("SSO_CLIENT_SECRET")?,
)?;
# let _ = providers; Ok(()) }
```

**The callback path** is `/auth/{provider}/callback` (`social::DEFAULT_CALLBACK`).
An app whose providers are already registered with another path passes that instead
(`"/accounts/{provider}/login/callback/"`), so existing registrations keep working;
it must start with `/` and name `{provider}` once, with no other capture, wildcard,
query or fragment. Start and remove are always
`/auth/{provider}/start` and `/auth/connections/{id}/remove`.

#### 2. Registering at each provider

Each provider needs the **redirect URI** exactly as the app sends it:
`PUBLIC_BASE_URL` followed by the callback path with the provider's id, for example
`https://myapp.example/auth/google/callback`. `Providers::redirect_uri("google")`
prints it. Scheme, host, port, path and trailing slash must all match, or the
provider refuses with "redirect_uri_mismatch" before the person sees a consent
screen. Register one URI per environment (production, staging,
`http://localhost:8000/...` for development), or one client per environment.

| Provider | Where | What to set |
|---|---|---|
| Google (id `google`) | Google Cloud console → APIs & Services → Credentials → Create credentials → OAuth client ID | Application type **Web application**. **Authorized redirect URIs**: the redirect URI above. The OAuth consent screen needs the `openid`, `.../auth/userinfo.profile` and `.../auth/userinfo.email` scopes (the app asks for `profile email`), and must be **published** (not "Testing") for people outside the test-user list. |
| Discord (id `discord`) | discord.com/developers → Applications → your app → OAuth2 | **Redirects**: the redirect URI. Copy the client id and reset to get the secret. Scopes requested: `identify email`. |
| Twitch (id `twitch`) | dev.twitch.tv/console → Applications → Register | **OAuth Redirect URLs**: the redirect URI (Twitch allows `http` only for `localhost`). Category: Website Integration. **Client type: Confidential** (a public client gets no secret). Scope requested: `user:read:email`. |
| OIDC issuer (id of your choice) | The issuer's admin console (Keycloak: Clients → Create) | A **confidential** client with the authorization-code ("standard") flow. **Valid redirect URIs**: the redirect URI. PKCE method **S256** allowed. Scopes: `openid profile email`. |

The client secret belongs in a secret store, never in the repository or the image.
It is never logged: `oauth::Client`'s `Debug` leaves it out.

#### 3. Wiring the app

```rust,no_run
# use std::time::Duration;
# async fn demo(pool: sqlx::PgPool, key: cookie::Key) -> anyhow::Result<()> {
use axum::{Router, middleware::from_fn_with_state};
use owt_accounts::identities::Welcome;
use owt_accounts::social::{self, Providers, SocialSignIn, DEFAULT_CALLBACK};
use owt_accounts::Accounts;
use owt_auth::oauth;
use owt_web::csrf::CrossOrigin;
use owt_web::headers::Csp;
use owt_web::session::Sessions;

let providers = Providers::from_env(DEFAULT_CALLBACK)?; // fails start-up on bad config
// Configure fully before `routes()`: the routes keep the configuration they were made with.
let social = SocialSignIn::new(pool.clone(), oauth::http_client()?, providers, Welcome { create: true, ..Welcome::default() })
    .sign_in_page("/login")                  // failures land here with ?social=
    .connections_page("/account/connections") // connects and removals land here
    .after_sign_in("/")                      // when the form gave no `next` on this site
    .connect_within(Duration::from_secs(15 * 60)); // how recent a sign-in a connect needs

// The start form's redirect goes to the provider: allow its origin in form-action.
let mut form_action = vec!["'self'".to_owned()];
form_action.extend(social.providers().form_action_sources());
let _csp = Csp::new().directive("form-action", &form_action.join(" "));

// Session data that can hold a sign-in in progress: `social::Data`, or the app's
// own type implementing `social::Social` (below). Lax cookies (the default) are
// required: the provider's redirect back is a cross-site navigation, and a Strict
// cookie would not come with it. A `__Host-` name keeps a sibling subdomain from
// planting a cookie of its own for these paths.
let sessions: Sessions<social::Data> =
    Sessions::new(key, "__Host-session", Duration::from_secs(14 * 86_400), true);
let app: Router = Router::new()
    .merge(social.routes::<social::Data, ()>()) // merge: the paths are absolute
    .layer(from_fn_with_state(Accounts::new(pool, "/login"), Accounts::load::<social::Data>))
    .layer(from_fn_with_state(sessions, Sessions::layer))
    // Outermost: a cross-origin POST (a sibling subdomain is same-site, so Lax
    // cookies come with it) is refused before it reaches start or remove.
    .layer(from_fn_with_state(CrossOrigin::new(), CrossOrigin::layer));
# let _ = app; Ok(()) }
```

An app with its own session type adds one field and the trait:

```rust
use owt_accounts::session::{Signature, Signed};
use owt_accounts::social::{Social, Started};

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct MySession {
    #[serde(flatten)]
    signed: owt_accounts::session::Data,
    #[serde(rename = "o", default, skip_serializing_if = "Option::is_none")]
    started: Option<Started>,
    // ...the app's own fields
}
impl Signed for MySession {
    fn signature(&self) -> Option<Signature> { self.signed.signature() }
    fn set_signature(&mut self, s: Option<Signature>) { self.signed.set_signature(s) }
}
impl Social for MySession {
    fn started(&self) -> Option<&Started> { self.started.as_ref() }
    fn set_started(&mut self, s: Option<Started>) { self.started = s }
}
```

**The two pages** embed the pieces; the app writes the rest of each page.
`?social=` codes are shown with `outcome`:

```rust,no_run
# async fn demo(social: owt_accounts::social::SocialSignIn, me: owt_accounts::Account, info: owt_web::request::RequestInfo) -> anyhow::Result<()> {
// Sign-in page: `{{ alerts }}` and `{{ buttons }}` in its template.
let flashes: Vec<_> = owt_accounts::social::outcome(info.query_value("social")).into_iter().collect();
let _alerts = owt_web::ui::Alerts { flashes: &flashes };
let next = info.query_value("next").unwrap_or("");
let _buttons = social.buttons(next); // "Continue with Google", one form each

// Settings page (behind `Signed`): `{{ alerts }}` and `{{ connections }}`.
let _connections = social.connections(me.id).await?; // each with Remove, then "Connect …"
# Ok(()) }
```

A page in another language passes the words: `{provider}` stands for the provider's
name. `outcome` is English; such an app shows each of `social::CODES` in its own words,
and a test of its own can check it has them all.

```rust,no_run
# async fn demo(social: owt_accounts::social::SocialSignIn, me: owt_accounts::Account) -> anyhow::Result<()> {
use owt_accounts::social::{ButtonWords, CODES, ConnectionWords};

let _buttons = social.buttons("/es/inicio").words(ButtonWords {
    continue_with: "Continuar con {provider}",
    connect: "Conectar {provider}",
});
let _connections = social.connections(me.id).await?.words(ConnectionWords {
    none: "Aún no hay conexiones.",
    provider: "Proveedor",
    account: "Cuenta allí",
    actions: "Acciones",
    remove: "Quitar",
    connect: "Conectar {provider}",
});

// The app's own messages, one per code.
fn mensaje(code: &str) -> Option<&'static str> {
    Some(match code {
        "connected" => "Conectado.",
        // …one arm per code in `CODES`
        _ => return None,
    })
}
let _missing: Vec<_> = CODES.iter().filter(|c| mensaje(c).is_none()).collect();
# Ok(()) }
```

**An app with a design of its own** draws the buttons and the table itself:
`SocialSignIn::views` takes a `social::Views` whose `buttons` and `connections`
answer from a view model (`ButtonsView`, `ConnectionsView`: each form's action, the
provider's name, its label in the page's words, `next`, whether it connects), and
`{{ buttons }}` and `{{ connections }}` then print the app's markup. Both default to
the Tailwind forms (`social::Tailwind`). `Buttons::view` and `Connections::view`
hand the same view model to a template that draws them in place. Either way the
routes check what is posted.

```rust,no_run
# fn demo(social: owt_accounts::social::SocialSignIn) {
use owt_accounts::admin::Body;
use owt_accounts::social::{ButtonsView, Views};

#[derive(askama::Template)]
#[template(source = r#"{% for b in v.buttons %}<form method="post" action="{{ b.action }}">
{% if !v.next.is_empty() %}<input type="hidden" name="next" value="{{ v.next }}">{% endif %}
<button class="btn btn-{{ b.provider|lower }}">{{ b.label }}</button></form>{% endfor %}"#, ext = "html")]
struct Providers<'a, 'b> { v: &'a ButtonsView<'b> }

struct Mine;
impl Views for Mine {
    fn buttons(&self, view: &ButtonsView<'_>) -> owt_web::Result<Body> {
        Body::render(&Providers { v: view })
    }
}
let social = social.views(Mine);
let _sign_in = social.buttons("/games"); // `{{ buttons }}` draws Mine's forms
# }
```

**The app's own code at each arrival:** `on_arrival` runs after the account is found
or created and before the session is signed in, with the account, whether this
sign-in created it, the provider's id, and the tokens the provider granted
(`Arrived::tokens`, an `oauth::Tokens`). It is for what every new account gets (a
profile, a default setting), the app's own sign-in bookkeeping, and keeping the
tokens of an app that calls the provider's APIs as the person. An error is
logged and signs nobody in: the person lands on the sign-in page with the `failed`
outcome. An account it created stays, and arrives with `created` false next time, so
set-up that must happen should also be done where it is found missing later.
Connecting a provider signs nobody in and does not call it. A second `on_arrival`
replaces the first. To unit-test a hook, build its argument with `Arrived::new`
(account, created, provider), and `.with_tokens(oauth::Tokens::bearer("…"))`.

`on_connect` is the same for connecting a provider to the signed-in account, after
the identity is linked, with the account, the provider's id and the tokens
(`Connected`; `Connected::new(account, provider)` in a test): a person who signed
up with a password hands the app a provider's tokens here. An error is logged and
lands on the connections page with `failed`; the identity stays linked, and the
next sign-in with it brings fresh tokens to `on_arrival`.

```rust,no_run
# fn demo(
#     social: owt_accounts::social::SocialSignIn, pool: sqlx::PgPool,
#     seal: fn(&owt_auth::oauth::Tokens) -> String,
# ) {
let social = social.on_arrival(move |arrived| {
    let pool = pool.clone();
    async move {
        if arrived.created {
            sqlx::query("INSERT INTO profiles (account_id) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(arrived.account.id)
                .execute(&pool)
                .await?;
        }
        // Sealed by the app (with the expiry as an instant: the lifetime is relative),
        // never in the clear. Each sign-in replaces what the last one granted.
        sqlx::query("INSERT INTO provider_tokens (account_id, sealed) VALUES ($1, $2)
                     ON CONFLICT (account_id) DO UPDATE SET sealed = EXCLUDED.sealed")
            .bind(arrived.account.id)
            .bind(seal(&arrived.tokens))
            .execute(&pool)
            .await?;
        Ok(())
    }
});
# let _ = social; }
```

#### 4. Deploying

- **OpenShift:** keep the credentials in the app's environment Secret, `myapp-env`
  ("The app's environment" under "Commands, CI, releases and deployment"), with
  `PUBLIC_BASE_URL` beside them, and restart to read them (`oc set data` changes a
  Secret that exists; `oc create secret generic myapp-env` makes it):

  ```sh
  oc set data secret/myapp-env \
    GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... PUBLIC_BASE_URL=https://myapp.example
  oc rollout restart deployment/myapp
  ```

- **Development:** the app's `.env` (which `just` loads) holds
  `PUBLIC_BASE_URL=http://localhost:8000` and a development client's credentials,
  registered with `http://localhost:8000/auth/<provider>/callback`. Sessions there
  need `secure: false` in `Sessions::new`, since the browser will not send a `Secure`
  cookie over `http`.
- **Before going live,** for each provider: sign in, sign out, connect a second
  provider from settings, remove it, and confirm the browser lands where expected each
  time.

#### Troubleshooting

| Symptom | Cause |
|---|---|
| The provider says `redirect_uri_mismatch` (or "invalid redirect") | The registered URI differs from `Providers::redirect_uri(id)`: scheme, host, port, path or trailing slash. Check `PUBLIC_BASE_URL` against the address bar. |
| Every sign-in lands on `?social=expired` | The session cookie did not survive the trip: `PUBLIC_BASE_URL`'s host differs from the one the person started on (`www.` or not), the cookie is `Secure` over `http`, the session layer is not around the routes, or the cookie was made `SameSite=Strict`. |
| Pressing the button does nothing; the console shows a `form-action` violation | The CSP's `form-action` lacks the provider's origin: add `form_action_sources()`. |
| `?social=failed` | The code exchange or user-info request failed: a wrong secret, a Twitch client that is not Confidential, or the provider unreachable. The server log has a `warn` naming the provider. |
| `?social=unknown` | `Welcome { create: false }` and no account is linked to that identity, or the linked account is deactivated. The person signs in another way and connects the provider from settings. |
| Connect always lands on `?social=sign-in-again` | The session began longer ago than `connect_within`; the person signs in again first. If it repeats right after signing in, the sign-in page is not signing a signed-in person in again (it redirects them away instead). |
| Start-up fails naming a variable | A pair half-set, `PUBLIC_BASE_URL` missing or not an `https` origin, a callback path without `{provider}` (or with another capture), or an OIDC issuer or endpoint that is not `https`. |

### Change requests

`owt-change` lets a site's signed-in admins ask for a change from the page itself. A
floating "Request a change" button lets them point at the part of the page they mean
and say what should change. The site's server forwards that, with who asked, to a
work tracker.

- **The browser never holds a credential.** It posts to the site, same origin, with
  the admin's session; the site's server forwards under its key from a Secret. The
  routes refuse a cross-origin `POST` themselves, as the accounts admin's do, so a
  sibling subdomain (same-site, whose forms come with `Lax` cookies) cannot file a
  request as the admin whatever the app layers around them.
- **Who asked comes from the session.** `requested_by` is filled by the server
  (`Admin::requester`), so a browser cannot name somebody else.
- **Only the page's origin and path are sent.** Its query and fragment, which can
  carry a search or a sign-in token, stay in the browser.
- **Off unless configured.** With neither `CHANGE_REQUESTS_URL` nor
  `CHANGE_REQUESTS_KEY` set, the routes answer 404 and the button renders nothing.
  One without the other fails at start.
- **The key travels encrypted.** `CHANGE_REQUESTS_URL` must be `https`, except to
  `localhost` or a cluster service by its absolute name, final dot included
  (`http://tracker.tools.svc.cluster.local.:8080/…`), and may not carry credentials,
  a query or a fragment. Without the dot, a pod's resolver (`ndots:5`) tries the
  name under each search domain first, and one of those could answer for it.

```rust,no_run
# fn demo(http: reqwest::Client) -> Result<(), owt_change::ConfigError> {
use askama::Template;
use axum::Router;
use owt_change::{ChangeRequests, Config};

let changes = ChangeRequests::new(Config::from_env()?, http); // in the app's state
// `POST /change-requests` and `GET /change.js`, for staff (`owt_accounts::Staff`).
// Merge them into a router the accounts layer wraps (where the app's staff pages
// are): outside the layer nobody is signed in, and every request is walled. They
// refuse a cross-origin POST on their own, inside or outside the app's `CrossOrigin`.
let staff_pages: Router = Router::new(); // the app's own, under the accounts layer
let app: Router = Router::new().nest("/staff", staff_pages.merge(changes.routes::<owt_accounts::Staff, ()>()));

// In the page shell, for a staff viewer: `{{ change_button }}` is the script tag.
#[derive(Template)]
#[template(source = "<body>…{{ change_button }}</body>", ext = "html")]
struct Shell<'a> { change_button: owt_change::Button<'a> }
let viewer_is_staff = true;
let _ = Shell { change_button: changes.button("/staff", viewer_is_staff) };
# let _ = app; Ok(()) }
```

An app without `owt-accounts` implements `owt_change::Admin` on its own extractor,
names it in `routes::<MyAdmin, _>()`, and can leave out the `Staff` implementation
and the dependency it brings: `owt-change = { …, default-features = false }`.

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
format between replicas: change them only with every replica. The prefix is ASCII
letters, digits, `_`, `.` and `-` (`Bus::redis` refuses others): the subscription is
the pattern `<prefix>:*`, so a `*`, `?`, `[` or `:` in it would hear other
deployments' channels.

### Background jobs

Every replica runs the same binary, so a periodic task runs everywhere unless it
says otherwise. `owt_runtime::jobs` gives three modes, all with jitter, a period or
fixed times ("At fixed times", below), a loop that survives a failed or panicking
run, and graceful shutdown:

- `every_replica`: idempotent work; the task takes its rows with `SKIP LOCKED`.
- `singleton`: at most one replica at a time, by a Postgres advisory lock that is
  tried and skipped, never waited on. The lock lasts as long as its connection, which
  is checked every `jobs::LOCK_CHECK`: a run whose connection drops (a failover, an
  idle timeout) is aborted at its next `.await`, as a crash would stop it, before
  another replica's run can overlap it. It needs a direct connection, not a
  transaction-mode pooler, behind which every run longer than a check is aborted;
  a check that itself takes longer than `LOCK_CHECK` aborts the run too.
- `leased` (feature `redis`): one replica, the same one while it lives, by a Redis
  lease renewed while held; on shutdown it is released, so another replica takes over
  at once.

```rust,no_run
use std::time::Duration;
use owt_runtime::jobs::{CancellationToken, Every, JobMetrics, Jobs, lease::Leases};

# async fn demo(pool: sqlx::PgPool, redis: redis::aio::ConnectionManager) -> anyhow::Result<()> {
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
let leases = Leases::new(redis, Leases::new_holder_id(), "myapp")?;
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
# Ok(()) }
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

`Leases::new` refuses the prefixes the cache refuses (see "Caching").

A run's panic, in the future or in the closure that builds it, is one failed tick;
the loop goes on.

**At fixed times.** `Every::new(period)` counts the period from when the loop starts.
`Every::aligned(period, offset)` runs at boundaries by the wall clock instead: each
instant a whole number of periods after the UNIX epoch, plus `offset`, in UTC. Jitter
comes after the boundary (a tenth of the period, at most 10 seconds, by default), and
it works with all three modes. The epoch was a Thursday, so a weekly boundary on
Monday is `aligned(7 * DAY, 4 * DAY)` (Monday 00:00 UTC), and Monday 03:00 is
`4 * DAY + 3 * HOUR`. An offset of a period or more is taken modulo the period. A run
that lasts past boundaries is followed by the next boundary after it ends; the missed
ones are skipped, not run in a burst. Every replica wakes at each boundary, and a
`singleton` keeps them from overlapping, not from running one after another, so the
task records the boundary it did (`Every::latest_boundary`) and does nothing for one
already done:

```rust,no_run
use std::time::{Duration, SystemTime};
use owt_runtime::jobs::{CancellationToken, Every, Jobs};

# async fn demo(pool: sqlx::PgPool) {
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);
let jobs = Jobs::new(CancellationToken::new());

// Each Monday at 03:00 UTC, once, whichever replica gets there first.
let weekly = Every::aligned(7 * DAY, 4 * DAY + 3 * HOUR);
let p = pool.clone();
jobs.singleton("close_week", weekly, pool.clone(), 7_210_002, move || {
    let p = p.clone();
    async move {
        let Some(week) = weekly.latest_boundary(SystemTime::now()) else { return Ok(()) };
        let week = week.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64;
        let mut tx = p.begin().await?;
        let fresh = sqlx::query("INSERT INTO closed_weeks (starts) VALUES (to_timestamp($1)) ON CONFLICT DO NOTHING")
            .bind(week)
            .execute(&mut *tx)
            .await?
            .rows_affected() == 1;
        if fresh {
            // ... close the week, in `tx`.
        }
        tx.commit().await?;
        Ok(())
    }
});
# }
```

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

**In another language**, the app passes the words. A label, a hint, a message and an
error page's heading are the app's text already; what a component writes itself has
English defaults the app replaces: `Pagination::words` (`PagerWords`, read by screen
readers), and for sign-in with a provider `Buttons::words` and `Connections::words`
(see "Sign-in with a provider" above). `ErrorBody::for_status` is English: a page in
another language fills the fields itself.

```rust
# fn main() -> askama::Result<()> {
use askama::Template;
use owt_web::pager::Pager;
use owt_web::request::RequestInfo;
use owt_web::ui::{ErrorBody, PagerWords, Pagination};

let request = RequestInfo::at("/es/people?page=2");
let pages = Pagination::new(Pager { number: 2, pages: 7 }, &request).words(PagerWords {
    nav: "Páginas",
    previous: "Página anterior",
    next: "Página siguiente",
});
assert!(pages.render()?.contains("Página siguiente"));

let body = ErrorBody {
    title: "Página no encontrada",
    detail: "No hay nada en esta dirección.",
    home: "/es",
    home_label: "Volver al inicio",
    ..ErrorBody::for_status(axum::http::StatusCode::NOT_FOUND)
};
assert!(body.render()?.contains("<h1>Página no encontrada</h1>"));
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
// `asset_versions` drops a URL's leading `?v=…` (the fingerprint on static URLs), so
// a snapshot recorded with the stylesheet built matches a test job that builds no CSS.
let normalize = Normalizer::new().uuids("<uuid>").asset_versions();
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

**Day to day:** copy `templates/justfile` and `templates/compose.yaml` into the app,
and `templates/dependabot.yml` as `.github/dependabot.yml`, so the app's action and
workflow pins, crates and npm packages move by weekly `fix(deps)` pull requests, each
a patch release once merged, instead of by hand at the next adoption (Dependabot
follows a git dependency pinned to a version tag, such as the crates' `tag = "vX.Y.Z"`;
an app's first weekly pull request shows it). The template ignores one npm package, the
stylesheet's `github:onewaytek/owt-stack#vX.Y.Z`: Dependabot does not order a git
dependency's tags as versions and proposes moving it to an older tag, so the app moves
it with `npm install -D` when it adopts a release (**Tailwind:** below).
An app that copied the template earlier adds the same `ignore` entry to its npm
ecosystem before it resumes Dependabot. Every app then answers to the same commands:

```sh
just setup        # npm ci, sqlx-cli and cargo-audit at CI's versions
just db           # Postgres 18 and Redis 8 (compose.yaml), then the migrations
just dev          # the app, with the stylesheet rebuilt on change
just check        # the gate: fmt, clippy, rustdoc, .sqlx freshness, audit, tests
just test --test worlds
just prepare      # regenerate .sqlx/ after changing a query
```

`just check` is the gate before every commit, and CI runs the same command, so the
two lists of checks can't drift. Its first step, `just migrate`, applies the app's
migrations to `DATABASE_URL`, before clippy, rustdoc and the tests compile the
`query!` macros against that schema and before the `.sqlx` check compares the
committed query metadata with it. So point `DATABASE_URL` at a database of the app's
own (`just db`'s, or a scratch one on a shared server, `createdb myapp_check`), never
at one another app migrates: outside CI, the recipe refuses a server's shared
`postgres` or `template1` database, and a URL that names none (the user's name is
then the database). An app that copied the template earlier takes the new `migrate`
recipe and `check`'s order, or its `doc` step fails on an unmigrated database.
App-specific recipes go below the template's `---- app recipes ----` line. The
compose ports and database name come from the app's `.env` (`POSTGRES_PORT`,
`POSTGRES_DB`, ...), so two apps' stacks can run side by side.

**CI:** call the reusable check workflow with the app's gate. It runs on ARC, with
Postgres and Redis as services, installs `just` and `cargo-audit` (and `sqlx-cli`
for an app with a `.sqlx/` or `migrations/`), migrates, then runs `check-command`.
Without `check-command`, it runs its own fmt, audit, sqlx, clippy and test steps. The
tools are pinned (`templates/justfile`'s `setup` installs the same versions), and
`sqlx-cli`, which has no prebuilt binary, is built once per job image and kept in the
GitHub cache. The job runs in `container` (default
`mirror.gcr.io/library/rust:1-trixie`), and the services come from the same mirror of
Docker Hub's official images, out of reach of Docker Hub's anonymous pull limit.

The cargo registry comes from GitHub's cache. Compiled crates come from
[sccache](https://github.com/mozilla/sccache) through one Redis shared by every job on
the runners. sccache keys a Rust compile by its inputs: the source, its absolute paths,
the toolchain's own files, the flags, the features and the `CARGO_*` variables, so a
hit needs the same crate built the same way at the same paths by the same toolchain:
jobs in one image share registry crates across repositories, and a repository's own
crates hit its earlier runs. It is on when the app passes the `SCCACHE_REDIS_PASSWORD`
secret to the workflow, by name as below (an organization secret reaches a private
repository only on a paid plan, so a private repository on GitHub Free sets it as a
repository secret), and `sccache-redis` names the Redis (default
`redis://sccache-redis.sccache.svc:6379`, a Service in the cluster the runners run
in). The password is handed to the sccache server alone, never into the environment
of the gate, build scripts or tests; a password with a control character in it (a
newline pasted into the secret) is refused with a warning and the job compiles
uncached. Without the secret the job compiles without a cache. If the Redis cannot be
used (unreachable, or the password is wrong), the job warns after about ten seconds
and compiles without it; it does not fail. The job summary shows sccache's hit and
miss counts. The Redis is bounded (`maxmemory`, least recently used evicted) and
entries expire after a month unused.

**Who to give the secret to.** Every repository given the secret trusts every other
repository given it, as with a shared cache volume: the password keeps the Redis from
the network, not from a job. Any code a job runs can reach the job's own sccache
server, which writes entries without the password, and an entry's key comes from
what `rustc` reports about itself rather than the binary's hash, so a job's code can
store an object under a registry crate's real key for every other job to read. Give
the secret to the repositories whose code may run on the scale set at all (the same
judgement `RUNS_ON` makes), and keep a public repository, whose pull requests anyone
can open, on GitHub-hosted runners with `sccache-redis: ""`. `image.yml` takes the
same secret and `sccache-redis` input for its release build.

A developer machine can use the
same Redis; its paths differ from the runners', so its entries are its own (its
registry crates hit across its clean rebuilds and worktrees, not CI's). It joins with
`~/.config/sccache/config`:

```toml
[cache.redis]
endpoint = "redis://<host>:<port>"   # the Service's NodePort from the lab network
password = "<the SCCACHE_REDIS_PASSWORD secret>"
expiration = 2592000
```

and `rustc-wrapper = "sccache"` under `[build]` in `~/.cargo/config.toml`.

<!-- x-release-please-start-version -->
```yaml
jobs:
  checks:
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@v0.8.0
    with:
      check-command: just check
      database: myapp        # empty for no Postgres
      postgres-major: "18"   # the major the CNPG cluster runs
      redis: true
      css-script: css:build  # empty to skip the stylesheet job
      extra-env: |           # test-only values, never real secrets
        SESSION_SECRET=...
    secrets:                 # the one secret it declares, never `inherit`
      SCCACHE_REDIS_PASSWORD: ${{ secrets.SCCACHE_REDIS_PASSWORD }}
```
<!-- x-release-please-end -->

**What a reusable workflow is given is what it can leak.** A reusable workflow runs
inside the app's job, so pass it the secrets it declares, by name, and never
`secrets: inherit`, which hands it every secret the app holds; the same for
`release.yml`, `promote-rc.yml`, `publish-rc.yml` and `requeue-rc.yml` below, which
declare none and need only their job's token, and `image.yml`, which declares the
sccache secret as `rust-ci.yml` does. And pin each `uses:` by
commit rather than by tag, with the tag in a comment
(`uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@<commit> # vX.Y.Z`): GitHub
resolves a tag on every run, and a tag can be moved, while a commit cannot; Dependabot
(the `github-actions` ecosystem in the app's `.github/dependabot.yml`, which
`templates/dependabot.yml` is) keeps such a pin moving with the releases: it reads the
tag in the comment, moves the commit to the release after it and rewrites the comment,
for an action and for a reusable workflow alike (this repository's own pins move that
way, in its `fix(deps): bump …` pull requests). `Cargo.lock` and
`package-lock.json` already pin the crates and the stylesheet to a commit. A workflow
in the app's own repository (`ci.yml` called from `release.yml`) is the app's own
code: `secrets: inherit` on that call is fine, and it passes the one secret on.

The checks run on the `arc-openshift-k8s` scale set unless the repository or
organization variable `RUNS_ON` names other runners, as JSON (`"ubuntu-latest"`). A
public repository should: self-hosted runners in the cluster are no place for code
anyone can propose. Off the cluster the Redis's Service name does not resolve, so such
an app passes `sccache-redis: ""` (otherwise each job spends about ten seconds finding
that out, warns, and compiles without sccache). Off ARC the services are at their
names (`postgres`, `redis`) rather than localhost; `DATABASE_URL` and `REDIS_URL`
follow, so build on those rather than naming a host.

The release flow's light jobs follow the same `RUNS_ON`: `release.yml`'s release job,
`promote-rc.yml`, `publish-rc.yml`, `requeue-rc.yml` and `conventional-commits.yml`.
They assume nothing on the runner but git (Node and uv come from their setup
actions), so they run in the runner pod itself, with no job container. A fork's
`pull_request` never reaches the scale set: `rust-ci.yml` skips it, and
`conventional-commits.yml` checks it (and any repository outside the organization)
on GitHub-hosted runners instead. The jobs whose
token can write (the release, a promotion, a publish, a requeue) also refuse every
event but the repository's own: a push or a dispatch for a release; a push, a
dispatch, a schedule or a same-repository pull request for the rc jobs. A
`pull_request_target`, `workflow_run` or `issue_comment` caller runs none of them.
An app's `version-command` runs in that runner pod too, which has git, curl, jq,
tar, perl, Node and (with `uv: true`) uv, but no cargo and no gh: a command that needs
more installs it itself, or the app runs its releases GitHub-hosted with `RUNS_ON`.

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
# One run at a time per branch, none cancelled. The release job serialises itself;
# this keeps a second push's ci and image jobs from running beside the first's release.
concurrency: {group: "release-${{ github.ref_name }}", cancel-in-progress: false}
jobs:
  ci:
    uses: ./.github/workflows/ci.yml   # the app's own: it passes the sccache secret on
    secrets: inherit
  release:
    needs: ci
    permissions: {contents: write, issues: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/release.yml@v0.8.0
  image:
    needs: release
    if: needs.release.outputs.version != ''
    permissions: {contents: read, packages: write}
    uses: onewaytek/owt-stack/.github/workflows/image.yml@v0.8.0
    with: {version: "${{ needs.release.outputs.version }}", bin: myapp}  # see "Image"
    secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
```

- **An app whose code reads its version** writes it into its files with the release:
  `with: {version-command: 'uv version "$VERSION" && uv lock', version-files:
  "pyproject.toml uv.lock", changelog: true, uv: true}`. The files are committed back
  as `chore(release): vX.Y.Z [skip ci]`. The command runs in bash on main only,
  with `GITHUB_TOKEN` unset; it is a child of the process that holds the token,
  though, and could read it from there, so only reviewed code and dependencies the
  app trusts (a `uv lock` builds sdists) belong in it.
- **rc is unreviewed code,** so on rc the release removes everything in the checkout
  that could configure semantic-release (`.releaserc*`, `release.config.*`, `.config/`,
  `package.yaml`, `node_modules`; a `release` or `cosmiconfig` key in package.json
  fails the run), runs no `version-command` and commits nothing back, installs its
  tooling away from the checkout's `.npmrc`, and fails unless the version is a
  prerelease; `image.yml` builds a stable image only
  from a tag on `main`, naming every ref in full (so neither a branch named like a
  release nor a tag named `origin/main` stands in). Add a tag ruleset on `v*` in the
  repository settings so tags are created by the release job alone, and a branch
  ruleset refusing new `v*` branches. A credential that can change
  `.github/workflows` can bypass all of this (a branch's push runs its own workflow
  files): keep that permission to people, never to automation.
- **Images** are tagged `X.Y.Z`, plus `X.Y` and `latest` (and `X` from 1.0) for a
  stable release, or `rc` for a prerelease. Rebuild an existing tag (a base image
  rebuilt for a fix, a registry that lost it) from a `workflow_dispatch` of the app's
  own, with `floating-tags` off unless the tag is the newest in its channel, since
  the floating tags would otherwise move back to it:

  ```yaml
  # .github/workflows/image.yml
  on:
    workflow_dispatch:
      inputs:
        version: {description: "The released version (0.8.0, v0.2.0-rc.1)", required: true}
        floating-tags: {description: "Also move the channel's floating tags", type: boolean, default: false}
  jobs:
    image:
      permissions: {contents: read, packages: write}
      uses: onewaytek/owt-stack/.github/workflows/image.yml@v0.8.0
      with: {version: "${{ inputs.version }}", floating-tags: "${{ inputs.floating-tags }}", bin: myapp}
      secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
  ```
- **The rc channel** (optional): on each same-repository PR into `main`, once its
  checks pass, merge the PR into `rc` and cut a prerelease. After each stable
  release, merge `main` back into `rc`. A PR's checks run on the PR alone, so two
  PRs in flight can each pass and break `rc` together: two migrations taking one
  number merge without a conflict. Checking the merge first closes that. The merge
  goes to `rc-candidate`, the app's checks run on it, and `rc` fast-forwards to it
  only if they pass and `rc` hasn't moved since. `rust-ci.yml` also fails on two
  migrations with one version.
- **A promotion can be lost** in the candidate flow, two ways. GitHub keeps one
  *pending* run per concurrency group, so a third PR updated while one promotion runs
  and another waits cancels the waiting one, not queues it. And `publish-rc.yml`
  refuses a candidate when `rc` moved while it was checked (a `sync-rc`, say): that
  run fails at "Move rc to the candidate" rather than publish a merge nobody checked.
  Either way the PR is left out of `rc` until it is pushed again, unless
  `requeue-rc.yml` re-runs it. It looks for open PRs whose head isn't in `rc` and
  whose latest promoting run was cancelled or failed at that step, and re-runs the
  oldest one, one at a time and only while no run is waiting (a re-run is itself a new
  arrival in the group). A run that succeeded without running "Merge into rc" (an
  `edited` or `labeled` trigger whose candidate job was skipped) doesn't count, so it
  can't hide a lost promotion of the same head. A cancelled run always counts, since
  one cancelled before its candidate job ran can't be told from one that would have
  skipped it: a non-promoting one is re-run, succeeds having merged nothing, and the
  next pass looks beneath it. A run that timed out, failed to start or awaits
  approval is left for a person. Keeping the workflow's
  `pull_request` types to the default (`opened`, `synchronize`, `reopened`) plus
  `ready_for_review` (a draft marked ready is promoted then, not at its next push)
  avoids those wasted re-runs.
  A run that failed its checks is left alone, and so is one already on
  its fifth attempt (`max-attempts`). Run it after each promotion, so one hands on to
  the next, and on a schedule, for when none follows. The scheduled one sits outside
  the group, so both can pick the same run: the run's status and attempt are read
  before the re-run and again if GitHub refuses it, and a run that is going again, or
  whose attempt moved since the list was read (re-run by the other and finished
  again), is logged and passes, whatever the refusal's wording; a run deleted in
  between is skipped. Any other refusal of a run (one over a
  month old, say) is a warning, and the next PR is tried; a refusal for want of
  `actions: write` fails the job once every PR is walked. It sees waiting *runs*, not
  waiting jobs, so put the `promote-rc` concurrency group on the workflow, as below:
  on a job, a re-run can cancel that job while it waits (a later requeue picks it up).

```yaml
# pr.yml
on:
  pull_request:
    # The defaults plus ready_for_review: a draft marked ready is promoted then, not
    # at its next push. Not `edited` (see "A promotion can be lost" above).
    types: [opened, synchronize, reopened, ready_for_review]
concurrency: {group: promote-rc, cancel-in-progress: false}
jobs:
  ci:
    uses: ./.github/workflows/ci.yml   # the app's own
    secrets: inherit
  commits:   # the title and every commit follow Conventional Commits (release.yml reads
    permissions: {contents: read, pull-requests: read}  # them); checks "commits / title"
    uses: onewaytek/owt-stack/.github/workflows/conventional-commits.yml@v0.8.0  # and "commits / commits"
  candidate:
    needs: ci
    if: github.event.pull_request.head.repo.full_name == github.repository && !github.event.pull_request.draft
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@v0.8.0
    with: {source: "${{ github.event.pull_request.head.ref }}", pr: "${{ github.event.pull_request.number }}", candidate: true}
  check-rc:
    needs: candidate
    if: needs.candidate.outputs.changed == 'true'
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@v0.8.0
    with: {ref: "${{ needs.candidate.outputs.sha }}", database: myapp}  # as the app's CI
    secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
  promote:
    needs: [candidate, check-rc]
    permissions: {contents: write, actions: write}
    uses: onewaytek/owt-stack/.github/workflows/publish-rc.yml@v0.8.0
    with: {sha: "${{ needs.candidate.outputs.sha }}", base: "${{ needs.candidate.outputs.base }}"}
  requeue:
    needs: promote
    if: always() && github.event.pull_request.head.repo.full_name == github.repository
    permissions: {actions: write, contents: read, pull-requests: read}
    uses: onewaytek/owt-stack/.github/workflows/requeue-rc.yml@v0.8.0
    with: {workflow: pr.yml}  # this file
# in requeue-rc.yml, on {schedule: [{cron: "*/30 * * * *"}], workflow_dispatch: {}}:
# the requeue job above, without its needs and if
# in release.yml
  sync-rc:
    needs: release
    if: github.ref_name == 'main'
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@v0.8.0
    with: {source: main, dispatch-release: false}
```
<!-- x-release-please-end -->

**Image:** `image.yml` builds the image on the ARC scale set (`RUNS_ON`, as the checks)
with no Docker daemon and no privileges, from inputs rather than a Dockerfile, and
makes what `templates/Dockerfile`'s runtime stage makes. Its `build` job compiles
`cargo build --release --locked --bin <bin>` in the work directory (`/app`, where the
Dockerfile builds too, so a path baked in with `env!("CARGO_MANIFEST_DIR")` holds in
the image) in a Rust job container (`container`,
default `mirror.gcr.io/library/rust:1-trixie`; through sccache when the app passes
the secret), runs `npm ci` and `npm run <assets-script>`, and packs one layer:
`/usr/local/bin/server` (root, 0755), any `bin-links` to it, the work directory
(0755, owned by `workdir-owner`), and the `files` under it, owned by `files-owner`. The `push` job runs
none of the app's code and alone holds `packages: write`: it checks the layer's
paths and modes, checks that the base has `base-requires` and a glibc at least as
new as the binary needs, then with
[crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane) (pinned
by version and SHA-256) appends the layer to the base pinned by its linux/amd64
digest, sets the configuration, pushes by digest, reads the version label back and
only then tags. The image carries `org.opencontainers.image.version` and the base's
`org.opencontainers.image.base.name` and `.base.digest` as labels (and as manifest
annotations). A template-shaped app needs no input beyond `bin`; the defaults are
the template's:

| input | default | the Dockerfile's |
| --- | --- | --- |
| `bin` | (required) | `ARG BIN` |
| `bin-links` | none | names linked to `server` in `/usr/local/bin` |
| `cargo-args` | none | extra `cargo build` arguments |
| `assets-script` | `css:build` (empty: no npm) | `ARG CSS_SCRIPT` |
| `node-version` / `node-version-file` | `22` / none | the assets stage's `hi/nodejs` |
| `files` | `static` | `COPY` into the work directory |
| `files-owner` | `65532:0` | `--chown` |
| `base-image` | `registry.access.redhat.com/hi/core-runtime:2` | the runtime `FROM` (a digest is used as given) |
| `base-requires` | `/usr/bin/sh /usr/bin/env /usr/bin/timeout` | `RUN timeout 5 env` |
| `workdir` / `user` | `/app` / `65532` | `WORKDIR` / `USER` |
| `workdir-owner` | `65532:65532` | `WORKDIR` made as core-runtime's user |
| `port` | `8000` (empty: neither) | `ENV BIND_ADDR=0.0.0.0:<port>`, `EXPOSE <port>` |
| `entrypoint` / `cmd` | `["/usr/local/bin/server"]` / `[]` | `ENTRYPOINT` / `CMD` (JSON arrays) |
| `env` / `labels` | none | more `ENV` / `LABEL` lines, `KEY=VALUE` each |

Files are taken from the checkout after the assets build, less what
`templates/dockerignore` keeps out of a context (`.git`, `node_modules`, `target`,
`.env*`, `*.pem`, `*.key`, `.npmrc`, `.netrc`, `.git-credentials`, cargo
credentials). A symlink among them fails the build (the push job takes only files
and directories under the work directory, so no entry can write through a link
elsewhere in the image); hard links are packed as files. The push job also checks
that the tag still names the commit the build job checked out. The release build
reads and writes the same sccache as the checks, so it trusts every repository given
the secret as they do ("Who to give the secret to"); `sccache-redis: ""` builds a
release uncached. An app with more than one runtime directory lists them, and one whose
binary has a second name links it:

```yaml
    with:
      version: ${{ needs.release.outputs.version }}
      bin: myapp
      bin-links: myapp           # /usr/local/bin/myapp -> server
      assets-script: build:prod
      node-version-file: .nvmrc
      files: data static_compiled
      cmd: '["serve"]'
      labels: |
        environment=production
```

**Comparing a crane-built image** with the one the Dockerfile made, when adopting
`builder: crane`, needs no read access to ghcr. A GitHub App token without the
`packages` permission is refused there (`crane config` answers `DENIED`), but the
cluster already pulls the app's images, and two things show the whole image:

- Its configuration (entrypoint, user, environment, labels): a non-persisting import
  in the app's namespace, which the cluster answers from the registry with that
  namespace's ghcr pull secret and stores nothing. It needs `create` on
  `imagestreamimports` there, which the `edit` role has. An empty answer is a failed
  import: the reason is in `.status.images[0].status.message`.

  ```sh
  oc create -o jsonpath='{.status.images[0].image.dockerImageMetadata.Config}' -f - <<'YAML'
  apiVersion: image.openshift.io/v1
  kind: ImageStreamImport
  metadata: {name: myapp-inspect}
  spec:
    import: false
    images:
      - from: {kind: DockerImage, name: ghcr.io/onewaytek/myapp:v1.2.3}
  YAML
  ```

- Its files: the build job's `image-layer` artifact is the exact layer pushed
  (`gh run download <run-id> --repo <the app's repository> -n image-layer && tar -tvf
  layer.tar` lists paths, owners and modes, with `actions: read` there). It is kept
  for a day.

The binary is built in Debian's Rust image, not Hummingbird's (which has no `tar`
for the setup actions), so the push job checks the newest `GLIBC_` version the
binary needs against the base's libc and fails rather than push an image that
would not start. A test build of a released tag goes to a tag of its own with
`tag: arc-test` (never `latest`, `rc` or a version). `builder: docker` builds the
app's `dockerfile` with BuildKit on a GitHub-hosted runner instead, for an image the
inputs cannot describe; it bills GitHub-hosted minutes to a private app.

**The Dockerfile** stays for local builds and `builder: docker`: copy
`templates/Dockerfile` (and `templates/dockerignore` as `.dockerignore`) and set
`BIN` and `PORT`. The build fetches owt-stack like any other git dependency; no
secret is mounted. Every stage starts from a Red Hat Hummingbird image on
`registry.access.redhat.com` (`hi/nodejs:22`, `hi/rust:1`, `hi/core-runtime:2`),
which needs no login. The runtime runs as uid 65532 and keeps `sh` and coreutils for
`oc exec`; the build fails if `sh`, `timeout` or `env` stop running. The names are
fully qualified, so a local `podman build` works without a registry prompt. An app
on the earlier distroless template moves by copying the template again; one with its
own runtime stage changes `FROM` and `USER nonroot` (to `USER 65532`).

**OpenShift:** the app keeps its copies of the templates in `deploy/openshift/`, with
`apply.sh` beside them and its parameters in `params.env`, one `KEY=VALUE` a line
(`NAME`, `NAMESPACE`, `IMAGE`, `CHANNEL`, `PORT`, `POSTGRES_MAJOR`, and whatever else
it sets). The script renders each template present with the parameters it declares,
`oc diff`s by default and applies with `--apply`:

```sh
deploy/openshift/apply.sh            # what an apply would change (exit 1 when something)
deploy/openshift/apply.sh --apply
```

`app.yaml` is always rendered; `redis.yaml` and `egress.yaml` (for the app's pods,
then each task's) when present; `cronjob.yaml` once per
`deploy/openshift/jobs/<JOB>.env`, whose lines (`JOB`, `SCHEDULE`, `ARGS`, and any
override such as `INTERNET_CIDR` or the task's `MEMORY_LIMIT`) are read over
`params.env`; `monitoring.yaml` with `--monitoring`, since it needs monitoring-edit
(see "Monitoring"). One pair of quotes comes off a value (`BACKUP_SCHEDULE="0 0 2 * *
*"`). A name two templates declare means one thing in both (`NAME`, `NAMESPACE`,
`CHANNEL`, `DB_SUFFIX`); Redis's image and memory limit are `REDIS_IMAGE` and
`REDIS_MEMORY_LIMIT`, apart from the app's. Upgrading owt-stack is: copy the templates
again, keep `params.env`. Exit status 1 means the diff found changes, 2 a refusal or
a failed `oc`.
The script writes no Secret: the app's environment and a Redis password are made by
hand, as below. `templates/openshift/apply-test.sh` proves the script against a
stand-in `oc` (`just templates` runs it here).

The ImageStream polls ghcr for the channel's tag (`rc` or `latest`), and the
Deployment's trigger rolls out each new digest. By hand, the same is one
`oc process … | oc apply -f -` per template:

```sh
oc process -f templates/openshift/app.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p IMAGE=ghcr.io/onewaytek/myapp -p CHANNEL=rc -p PORT=8000 | oc apply -f -
```

**The app's environment** (`SESSION_SECRET`, a provider's credentials, its own
tuning) lives in a Secret named `myapp-env`, which the Deployment reads whole. It is
optional: until it exists, the app starts without it. A variable the template sets
(`DATABASE_URL`, `PGSSLMODE`, `BIND_ADDR`, `RUST_LOG`, …) wins over the Secret's;
`RUST_LOG` is the template's `RUST_LOG` parameter (default `info`), so a narrower
filter goes in `params.env` (`RUST_LOG=info,myapp=debug`), or in a task's
`jobs/<JOB>.env` for that task alone. A
Secret's change reaches pods only when they start, so restart after one:

```sh
oc create secret generic myapp-env \
  --from-literal=SESSION_SECRET="$(openssl rand 64 | base64 -w0)"
oc set data secret/myapp-env PUBLIC_BASE_URL=https://myapp.example   # later changes
oc rollout restart deployment/myapp
```

**Moving from `oc set env` to `myapp-env`.** An entry added to the Deployment with
`oc set env` lives outside the template, and `apply.sh` applies client-side, so the
entry is in neither its diff nor its apply: the diff comes out clean while the stale
entry, which wins over the Secret, still sets the value. Take the steps in this
order, so that no pod starts without a value:

```sh
# 1. The patched entries, as they stand.
oc set env deployment/myapp --list
# 2. The Secret, from those values: only the app's own, never one the template sets
#    (DATABASE_URL, RUST_LOG, ...).
oc create secret generic myapp-env \
  --from-literal=SESSION_SECRET='...' \
  --from-literal=PUBLIC_BASE_URL='...'
# 3. envFrom on the live Deployment. The explicit entries still win: no value changes.
deploy/openshift/apply.sh --apply
# 4. Every moved entry off, in one command: one rollout, after which the Secret answers.
oc set env deployment/myapp SESSION_SECRET- PUBLIC_BASE_URL-
# 5. Only the template's entries are left, and the diff is clean.
oc set env deployment/myapp --list
deploy/openshift/apply.sh
```

Step 3 rolls the pods once and step 4 once more; `oc rollout pause deployment/myapp`
before step 3 and `oc rollout resume deployment/myapp` after step 4 make them one.
Removing the entries before step 3 starts pods with neither.

**Redis** is a template of its own, for an app that uses the cache, the bus across
replicas or leases. It runs as compose does: nothing on disk, `MAXMEMORY` (128mb)
with `MAXMEMORY_POLICY` (`allkeys-lru`), one pod replaced rather than surged so the
replicas never split across two. A password protects it, and a NetworkPolicy admits
the app's pods alone. The password is a Secret made once by hand, since a generated
one would change on every apply. The Deployment reads `REDIS_URL` from that Secret
when it exists, so the app picks Redis up at its next restart:

```sh
pw=$(openssl rand -hex 24)
oc create secret generic myapp-redis --from-literal=password="$pw" \
  --from-literal=url="redis://:$pw@myapp-redis:6379"
oc process -f templates/openshift/redis.yaml -p NAME=myapp -p NAMESPACE=myapp | oc apply -f -
oc rollout restart deployment/myapp
```

An app whose leased work must never run twice gives it `-p MAXMEMORY_POLICY=noeviction`
("Background jobs"): a full Redis then refuses writes instead of dropping a lease.

**Scheduled tasks** run the app's image with other arguments, one `cronjob.yaml` per
task. The image's entrypoint is the binary, so `ARGS` picks the subcommand:

```sh
oc process -f templates/openshift/cronjob.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p JOB=digest -p SCHEDULE="0 6 * * *" -p ARGS='["send-digest"]' | oc apply -f -
```

It follows the app's channel through the same image trigger, and has the Deployment's
database access: `DATABASE_URL` from `myapp-db-app`, `PGSSLMODE=verify-full` with
`PGSSLROOTCERT` at the mounted `myapp-db-ca`, `POD_NAMESPACE`, `REDIS_URL` and
`myapp-env`. It takes the same `DB_SUFFIX` as `app.yaml` (default `db`), which names the
database cluster and those Secrets. Its pods are labelled `app: myapp-<JOB>`, never `app: myapp`, which the
app's Service sends traffic to. The database's and Redis's NetworkPolicies admit the
app's pods only, so the template brings two more admitting that label (policies add
up). A worker that runs all the time is the same pod spec in a Deployment, with
`app.yaml`'s strategy and image trigger (`fieldPath` naming its container), and the
same label and policies.

**Where the app may connect** is a template of its own, `egress.yaml`, applied once
per set of pods: the app's, and each task's. `app.yaml`'s policies say who may reach
the app; this one says where it may go, and nothing else. A pod that is compromised
(a dependency's bug, a request forged through one of the app's own routes) can then
open connections to the app's database, its Redis, the cluster's DNS and port 443 of
`INTERNET_CIDR`, and to nothing else: not the cluster API, not another port
anywhere. `INTERNET_CIDR` bounds the last: `0.0.0.0/0` (the default) is anywhere on
443 (a sign-in provider, a tracker for change requests, an OTLP collector over the
public web, and the cluster's own Routes, which the router answers at a node address;
also any pod or node that listens on 443, since an `ipBlock` matches those addresses
too), `0.0.0.0/32` is nowhere, for a task that sends no mail and calls no API. The
cluster's resolvers are `DNS_NAMESPACE` on `DNS_PORT` (OpenShift's CoreDNS answers on
5353).
Anything else the app calls (a cluster service in another namespace, another port) is
a further NetworkPolicy of the app's own with the same `podSelector`: policies add up.

```sh
oc process -f templates/openshift/egress.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p POD=myapp | oc apply -f -
oc process -f templates/openshift/egress.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p POD=myapp-digest -p INTERNET_CIDR=0.0.0.0/32 | oc apply -f -
```

The selected pods lose every other egress the moment it applies, so read the rules
against what the app calls, and apply it in a staging namespace first; a wrong rule
looks like a DNS failure, and deleting the policy (`oc delete networkpolicy
myapp-egress`) restores the open egress. The database's instances get no egress
policy: the CloudNativePG instance manager talks to the cluster API. `redis.yaml`'s
Redis gets one of its own there, admitting no egress at all.

**An app whose database already exists passes the major it runs**, on every apply:
`-p POSTGRES_MAJOR=16` if
`oc get cluster.postgresql.cnpg.io myapp-db -o jsonpath='{.spec.imageName}'` ends in
`:16`. Compose's `postgres` image and CI's `postgres-major` stay on the same major.
The default (18) is for a new app: given to a cluster on another major, it changes
the Cluster's image, which CNPG 1.26 and later carry out as an in-place major upgrade
and earlier versions refuse. Moving up is a step of its own ("Upgrading Postgres",
below). Read what an apply will change before making it:

```sh
oc process -f templates/openshift/app.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p IMAGE=ghcr.io/onewaytek/myapp -p POSTGRES_MAJOR=16 | oc diff -f -
```

**`DATABASE_URL` is the `uri` key of `myapp-db-app`** (`myapp-<DB_SUFFIX>-app`), in
the Deployment and in every `cronjob.yaml` task. CloudNativePG creates that Secret,
`uri` included, only when the Cluster's bootstrap (`initdb`, `recovery` or
`pg_basebackup`) names no `secret:` of its own, as the template's `initdb` and the
restore under "Restoring" below do. A Cluster made elsewhere with `secret:` gets no
`myapp-db-app` from CNPG: the pods fail to start with `secret "myapp-db-app" not
found`, or, when the app's own Secret has that name, with `couldn't find key uri in
Secret`. So before adopting the template for an existing Cluster, check: an empty first
answer means CNPG's own Secret, and the second then shows its `uri`, password masked.

```sh
oc get cluster.postgresql.cnpg.io myapp-db -o jsonpath='{.spec.bootstrap.*.secret.name}'; echo
oc get secret myapp-db-app -o jsonpath='{.data.uri}' | base64 -d | sed 's/:[^:@]*@/:***@/'; echo
```

With a `secret:`, give the pods a Secret named `myapp-db-app` whose `uri` is in the
form CNPG writes, `postgresql://myapp:<password>@myapp-db-rw.<namespace>:5432/myapp`
(the password percent-encoded, no `sslmode`, which `PGSSLMODE` supplies). When the
password changes, change `uri` in the same edit: CNPG applies a new `password` from
the Secret named in `secret:` to the database's owner at once, but never rewrites
`uri`.

The Route sends traffic through the router (HAProxy), which keeps idle connections to
the pod for reuse longer than the app's default 30-second keep-alive (its
`timeout http-keep-alive` is 300 s). Serve with a `header_read_timeout` above that, as
"Wiring an app" does, or requests on a connection the app has just closed fail with
an occasional 502. Each rollout also cuts the app's SSE streams after the 20-second
drain; their clients reconnect to the new pods ("Bounds" under "Wiring an app").
The router also cuts a response that sends nothing for `ROUTE_TIMEOUT` (its
`timeout server`, set by the Route's `haproxy.router.openshift.io/timeout`; default
`30s`, the router's own), so a quiet SSE stream sends `sse::HEARTBEAT` more often
than that. An app with a slow export or upload sets a longer one in `params.env`
(`ROUTE_TIMEOUT=2m`, always with a unit, `us`, `ms`, `s`, `m`, `h` or `d`: the router
reads a bare number as milliseconds and ignores, without a word, a value it cannot
parse, so `apply.sh` refuses one without a unit) rather than annotating the Route by
hand, outside the template. The first apply after copying the template sets the
annotation: an app that annotated its Route by hand puts that value in `params.env`
first, or the diff shows it reset to `30s`; and on a cluster whose IngressController
sets `tuningOptions.serverTimeout`, `30s` replaces that default for this Route, so
pass the cluster's value ("Upgrading from 0.8"). (An upgraded WebSocket answers to
the router's `timeout tunnel` instead, an hour by default.)

**Backups come with it.** The database takes a volume snapshot nightly
(`BACKUP_SCHEDULE`, CNPG's six-field cron, seconds first) and once at first apply.
They are offline by default (`BACKUP_ONLINE=false`): Postgres stops for the seconds an
LVM snapshot takes, because an online snapshot is only consistent with a WAL archive,
which these clusters don't have. With one instance (`DB_INSTANCES=1`, the default)
the app sees that pause: requests needing the database fail for a few seconds each
night, and once at the first apply, when the immediate backup overlaps the rollout
that same apply starts (apply outside busy hours, or expect a few errors then). The
choices: accept the pause; run two instances (`-p DB_INSTANCES=2`: CNPG snapshots the
standby and the primary keeps serving, for twice the space in the volume group, and
no help with a drain: on a single node the standby goes down with the primary); or
take online backups (`BACKUP_ONLINE=true`), only once the cluster has a WAL archive
(below), since an online snapshot without one doesn't restore.

**Draining the node** waits on CNPG's PodDisruptionBudgets whatever `DB_INSTANCES`
is: a single instance can't switch over, and on a single node neither can two. For
planned node maintenance, accept the downtime: before the drain, put the Cluster in
a maintenance window, which keeps its local volume for when the node returns and
lifts the budget, and take it out afterwards (`inProgress: false`):

```sh
oc patch cluster.postgresql.cnpg.io myapp-db --type merge \
  -p '{"spec": {"nodeMaintenanceWindow": {"inProgress": true, "reusePVC": true}}}'
```

A CronJob (`PRUNE_SCHEDULE`, after the backup) prunes
snapshots older than `BACKUP_KEEP_DAYS` (14) but always keeps the newest
`BACKUP_KEEP_AT_LEAST` (3) completed ones, so backups that silently stop are not all
aged out on schedule; a prune that fails fails its Job. **Its image comes from the
internal image registry** (`PRUNE_IMAGE`, the cluster's own `openshift/cli`). On a
cluster with that registry removed the image never pulls, nothing is pruned, and the
snapshots fill the volume group until the database stops. Check before relying on it
that the registry runs and holds the image:

```sh
oc get pods -n openshift-image-registry -l docker-registry=default  # one Running
oc get istag cli:latest -n openshift
```

and, after the first night, that a prune succeeded
(`oc get cronjob myapp-backup-prune -o jsonpath='{.status.lastSuccessfulTime}'` prints
a time). A cluster without the registry passes `-p PRUNE_IMAGE=<image>`: any image the
namespace can pull that has `bash`, `oc` and `python3`.

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
Run it (it needs a namespace admin) whenever how backups are taken changes. A Backup
restores only at the major it was taken at: re-create the Cluster with that
`POSTGRES_MAJOR`.

**Upgrading Postgres** to a new major is planned downtime, never a side effect of
re-applying the template. Rehearse it first, at the app's majors:

```sh
POSTGRES_MAJOR=16 UPGRADE_TO=18 templates/openshift/restore-drill.sh myapp
```

On throwaway clusters, this proves a backup taken at 16 restores, then upgrades the
restored cluster in place and checks its data survived. It fails at the upgrade if the
operator cannot do one. Then take one of two paths.

*In place,* with CloudNativePG 1.26 or later (`oc get csv -A | grep cloudnative-pg`
shows the version), keeping every name. CNPG stops Postgres, runs `pg_upgrade --link`
in a Job and starts the new major. The app is unavailable until that finishes, which
the drill timed. Both images must be built on the same Debian release. The template's
`ghcr.io/cloudnative-pg/postgresql:<major>` tags are, so moving from one to another
qualifies. A cluster moved to other tags (`18-minimal-trixie`) upgrades only within
their flavour.

1. Take a backup and wait for it. Like the nightly ones, it is pruned after
   `BACKUP_KEEP_DAYS`. A Backup needs the Cluster's `backup.volumeSnapshot` stanza,
   which an apply of this template puts there. A cluster that predates it
   (`oc get cluster.postgresql.cnpg.io myapp-db -o jsonpath='{.spec.backup}'` prints
   nothing) gets it only from an apply at its *current* major, since an apply at the
   new one starts the upgrade at once. So in that order: apply the template rendered
   with `-p POSTGRES_MAJOR=<current>`; take the Backup below and see it `completed`
   (without the stanza it fails, and `oc wait` waits out its timeout); only then go
   on to step 2. That first apply also starts the nightly schedule and its immediate
   backup, which pauses a single instance for a few seconds ("Backups come with it").

   ```sh
   oc create -f - <<EOF
   apiVersion: postgresql.cnpg.io/v1
   kind: Backup
   metadata: {name: myapp-db-before-18}
   spec: {cluster: {name: myapp-db}, method: volumeSnapshot}
   EOF
   oc wait backup.postgresql.cnpg.io/myapp-db-before-18 \
     --for=jsonpath='{.status.phase}'=completed --timeout=10m
   ```

2. Apply the template with `-p POSTGRES_MAJOR=18`, and pass it on every apply from
   then on.
3. If the upgrade Job fails, apply again with the old major: the operator deletes the
   Job and starts the old one again. Once the upgrade succeeds, the only way back is
   that backup, restored at the old major ("Restoring", above).
4. `pg_upgrade` carries no planner statistics, so gather them:
   `oc exec myapp-db-1 -c postgres -- vacuumdb -U postgres --all --analyze-in-stages`.
5. Move compose's image and CI's `postgres-major` to the new major. The local volume
   is new (`pgdata18`); `just db` makes and migrates it.

*Into a new cluster* works with any CNPG version and leaves the old cluster as it was,
to switch back to. The new cluster imports the app's database with `pg_dump` (`bootstrap.initdb.import`),
and the template's `DB_SUFFIX` then moves the app onto it (`DATABASE_URL`'s Secret, the
CA, the backups and the NetworkPolicy follow the name):

1. Stop the app, since writes after the dump would be lost:
   `oc scale deployment/myapp --replicas=0`, and suspend its CronJobs
   (`oc patch cronjob/myapp-digest -p '{"spec": {"suspend": true}}'`).
2. Let the new cluster's pods reach the old database, which admits only the app:

   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata: {name: myapp-db-import, namespace: myapp}
   spec:
     podSelector: {matchLabels: {cnpg.io/cluster: myapp-db}}
     policyTypes: [Ingress]
     ingress:
       - from: [{podSelector: {matchLabels: {cnpg.io/cluster: myapp-db18}}}]
         ports: [{port: 5432}]
   ```

3. Render the template with `-p POSTGRES_MAJOR=18 -p DB_SUFFIX=db18 -o yaml`, take its
   `Cluster` (`myapp-db18`), add the import to its spec, and create it with
   `oc create -f` (not `apply`, so the template's later applies leave the import
   alone). The import connects as the app's own user, which owns its database:

   ```yaml
   bootstrap:
     initdb:
       database: myapp
       owner: myapp
       import:
         type: microservice
         databases: [myapp]
         source: {externalCluster: previous}
   externalClusters:
     - name: previous
       connectionParameters:
         host: myapp-db-rw
         user: myapp
         dbname: myapp
         sslmode: verify-full
       password: {name: myapp-db-app, key: password}
       sslRootCert: {name: myapp-db-ca, key: ca.crt}
   ```

4. When `oc wait cluster.postgresql.cnpg.io/myapp-db18 --for=condition=Ready` returns,
   apply the template with `-p POSTGRES_MAJOR=18 -p DB_SUFFIX=db18`, as every apply
   will from now on (and `monitoring.yaml` and each `cronjob.yaml` with the same
   `DB_SUFFIX`). The Deployment is back at `REPLICAS`, reading the new cluster's
   Secret; resume any CronJob suspended in step 1 (`suspend: false`).
5. To switch back, apply with the old major and no `DB_SUFFIX`. Once the app is
   settled, delete the old `myapp-db` Cluster, its `myapp-db-nightly` ScheduledBackup
   and the `myapp-db` and `myapp-db-import` NetworkPolicies. The pruning follows the
   new cluster, so the old cluster's Backups stay until deleted by hand.
6. Move compose and CI as in step 5 above.

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
"devDependencies": { "@onewaytek/owt-stack": "github:onewaytek/owt-stack#v0.8.0" }
```
<!-- x-release-please-end -->

```css
@import "tailwindcss" source(none);
@import "@onewaytek/owt-stack/tailwind/owt.css";
@source "../templates";
```

Move to a release with the package named in the command:

```sh
npm install -D @onewaytek/owt-stack@github:onewaytek/owt-stack#vX.Y.Z
grep -A3 '"node_modules/@onewaytek/owt-stack"' package-lock.json   # resolved: …#<the tag's commit>
```

Editing the tag in `package.json` and running `npm install` keeps the old commit in
`package-lock.json`: the stylesheet stays at the old release while the manifest names
the new one. An app has also seen the unnamed form (`npm install -D
github:onewaytek/owt-stack#vX.Y.Z`) leave a locked dependency where it was, so name
the package, and check either way: the lock's `resolved` URL ends in the commit that
was installed, to compare with the tag's (`git ls-remote
https://github.com/onewaytek/owt-stack vX.Y.Z 'vX.Y.Z^{}'`: the `^{}` line if there is
one, otherwise the only line).
Dependabot leaves this dependency alone (`templates/dependabot.yml` ignores it), so
this command, run when the app adopts a release, is the only thing that moves it.

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
- OAuth: use `owt_accounts::social` rather than hand-written handlers (see "Sign-in
  with a provider"); it uses `oauth::http_client()`, and `Client::complete` checks the
  state and the provider itself. An app that needs the person's tokens uses
  `Client::complete_with_tokens`, `refresh` and `client_credentials`, never its own
  exchange, which would skip the ID-token checks. Key people by (`Provider::key()`,
  `Identity::uid`), never by `Identity::email`, in the app's own tables too.
- The bus's Redis is inside the trust boundary: a password or ACL user, a network
  only the app reaches, `rediss://` where the path leaves the node.
- `Limits` bounds the time to a response; `serve::serve` bounds the time to a request
  head (30 s), the connections open at once (4096) and a stop (20 s of draining). It
  does not bound a client that uploads slowly or never reads its response: `Limits`
  does, for the app's routes. The metrics listener, which nothing fronts, also caps
  each connection's life at 15 s, gives a request head 3 s, and holds 64 at most;
  a `NetworkPolicy` letting only the scraper reach it keeps others from filling them. A handler that reads `Body` or `Request` itself is
  outside `DefaultBodyLimit`; it bounds what it reads.
- The metrics middleware labels by matched route and by method, an invented method
  counting as `other`, so no client can grow the label set (each new set is a
  histogram kept for the life of the process).
- Start `Csp` in report-only mode and read the browser console before enforcing.
  htmx needs `htmx.config.includeIndicatorStyles = false` (or its
  `inlineStyleNonce`) and no `hx-on:*` attributes, which a nonce cannot cover.
  Nor can a nonce cover a `style="…"` attribute, so `Csp::new()` blocks every one,
  even those a page writes on purpose (a progress bar's width, a colour swatch, an
  SVG's presentation styles). Once enforced, those elements render unstyled.
  `allow_style_attributes()` sends `style-src-attr 'unsafe-inline'`: attributes
  only, while `<style>` elements still need the nonce. Injected markup could then
  restyle the element it lands in, a far smaller risk than `'unsafe-inline'` on
  `style-src`, which lets it bring a stylesheet for the whole page.

  ```rust
  use owt_web::headers::Csp;
  // `<div class="bar" style="width: {{ percent }}%">` renders as written.
  let _csp = Csp::new().allow_style_attributes().report_only(true);
  ```

## Upgrading from 0.8

- `app.yaml` sets the Route's `haproxy.router.openshift.io/timeout` from
  `ROUTE_TIMEOUT` (default `30s`). Before the first apply with the new template, copy
  any timeout the live Route carries into `params.env`, or the apply resets it:
  `oc get route myapp -o jsonpath='{.metadata.annotations.haproxy\.router\.openshift\.io/timeout}'`
  prints it (nothing when unset). On a cluster whose IngressController sets
  `tuningOptions.serverTimeout`, pass that value instead of taking the default.

## Upgrading from 0.7

- `release.yml`'s release job, `promote-rc.yml`, `publish-rc.yml`, `requeue-rc.yml`
  and `conventional-commits.yml` run on the `arc-openshift-k8s` scale set unless
  `RUNS_ON` names other runners, as `rust-ci.yml` does; a private app stops paying
  GitHub-hosted minutes for them. Nothing in the call changes, with one exception:
  a `version-command` runs in the ARC runner pod, which has no cargo and no gh (git,
  curl, jq, tar, perl, Node and uv are there); such a command installs what it needs, or
  the app sets `RUNS_ON` to `"ubuntu-latest"`. An app that sets
  `RUNS_ON` keeps those jobs on its runners too, and a public repository keeps
  `RUNS_ON` at `"ubuntu-latest"`.
- **Breaking:** `image.yml` builds daemonlessly on the ARC scale set by default
  (`builder: crane`), from inputs instead of the Dockerfile. A template-shaped app
  adds `bin: <its BIN>` (and `port` when its `PORT` is not 8000) to both calls of
  `image.yml` (`release.yml`'s image job and its own `image.yml`), and passes
  `secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}` there
  for a cached build. An app with its own runtime stage maps it onto the inputs (see
  "Image"), or keeps its Dockerfile with `builder: docker`, on GitHub-hosted minutes.
  The image is one manifest for linux/amd64, with no build attestation, and its
  labels add `org.opencontainers.image.base.name` and `.base.digest`. The
  Dockerfile stays for local builds.
- **Breaking** for an unusual caller only: the jobs whose token can write run only
  for the repository's own events. A release runs for a `push` or a
  `workflow_dispatch`; `promote-rc.yml`, `publish-rc.yml` and `requeue-rc.yml` for a
  `push`, a `workflow_dispatch`, a `schedule` or a `pull_request` from a branch of
  the repository. A call from `pull_request_target`, `workflow_run` or any other
  event is skipped: move it to one of those.

## Upgrading from 0.6

- A password sign-in form calls `session::password_sign_in` instead of charging the
  throttle, calling `store::authenticate` and `session::sign_in` itself, and a
  sign-up form lists `store::problems` (after `Throttle::attempt`). Every way in owt
  signs an account in through (a password, a provider, a local identity, a sign-in
  link) stamps `accounts.last_sign_in`, so an app that wrote it itself drops that
  write; one with a way in of its own calls `store::signed_in`.
- **Breaking:** `owt_accounts::session::Data` has a third field, `flashes:
  Vec<Flash>` (serialized as `f`, absent when empty, so sealed cookies stay
  readable both ways), and implements `HasFlashes`, as `social::Data` does through it.
  It is no longer `Copy`: clone it where a copy was taken. A literal
  `Data { account, epoch }` adds `..Data::default()`. An app whose own session type
  existed only to add flashes to it uses `Data` (or `social::Data`) instead.
- `client_ip::Source::from_env` and the `ClientIp` extractor replace the app's own
  client-address extractor and its `CLIENT_IP`/`TRUSTED_PROXIES` parsing (an app
  that reads a header by default sets `CLIENT_IP=header:NAME`); nothing reads a raw
  `X-Forwarded-For` any more.
- `Sessions::from_env` replaces the app's own `SESSION_SECRET` and purpose code;
  keep the purpose with `SESSION_PURPOSE` (see "Session key").
- `redis.yaml`'s image and memory-limit parameters are `REDIS_IMAGE` and
  `REDIS_MEMORY_LIMIT` (they were `IMAGE` and `MEMORY_LIMIT`), apart from `app.yaml`'s,
  so one `params.env` serves every template through `deploy/openshift/apply.sh`. An
  apply that passed `-p IMAGE=` or `-p MEMORY_LIMIT=` to `redis.yaml` passes the new
  names; the defaults are unchanged.
- Keep the templates in `deploy/openshift/` with `apply.sh` and `params.env` beside
  them, and drop the app's own process or apply script where the template's does
  the same ("OpenShift" under "Commands, CI, releases and deployment").

- `rust-ci.yml` compiles through sccache over a shared Redis instead of a cargo cache
  volume at `/cache`. To use it, pass the secret by name on the call of `rust-ci.yml`
  (`secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}`, as
  the CI snippet shows; not `secrets: inherit`, which hands the workflow every secret
  the app holds; a workflow of the app's own that calls the one that calls it may
  use `secrets: inherit`, being the app's code), and make a secret
  `SCCACHE_REDIS_PASSWORD` visible to the repository (an
  organization secret, or a repository secret for a private repository on GitHub
  Free). An app on GitHub-hosted runners (`RUNS_ON`) passes `sccache-redis: ""`. The
  job uses no `/cache` volume: remove its mount from the runner pod template. Without
  the secret the checks pass, uncached.
- Pin the reusable workflows by commit, with the tag in a comment, and let Dependabot
  (its `github-actions` ecosystem, in the app's `.github/dependabot.yml`) move the pin
  ("What a reusable workflow is given is what it can leak", under "Commands, CI,
  releases and deployment").
- **Every public enum that can grow is `#[non_exhaustive]`:** `owt_web::Error`,
  `owt_web::client_ip::Source`, `owt_web::ui::Kind`, `owt_accounts::Refused`,
  `owt_accounts::Error`, `owt_accounts::password::Problem`,
  `owt_accounts::identities::{Arrival, RekeyError}`, `owt_accounts::social::ConfigError`,
  `owt_auth::jwt::Error` and `owt_change::ConfigError` (`oauth::Error` and
  `admin::Level` were already). A `match` on one of them in the app, a template's
  `{% match %}` on `Kind` included, ends with a `_` arm; a variant added later is
  then no breaking change. `owt_web::ui::Item` is `#[non_exhaustive]` too: read its
  fields, never build or destructure it. Nothing else changes: the variants are
  still constructed and matched by name, and `Refused`'s `Display` is still the
  sentence to show for any of them.

## Upgrading from 0.5

- `Cache::connect` and `Leases::new` refuse a prefix with characters other than ASCII
  letters, digits, `_`, `.` and `-`, as `Bus::redis` already did, and `Leases::new`
  returns a `Result`: add `?`. An app whose prefix has a `:` or a space renames it:
  its cache starts cold, and while old and new replicas overlap in the rollout each
  side holds its own leases, so a leased job may run twice until the rollout ends.
- Install `owt_accounts::migrations::ALL[3]` (`owt_accounts_policies`) as the app's
  next unused migration version (see "Tables" under "Accounts"), whether or not the
  app uses site policies: `assert_installed` expects every entry. Its tables stay
  empty until the app wires `policies::Policies` ("Site policies"). It takes the
  `policy_*` names listed under "Names the migrations take": an app with a table,
  index or function of one of them renames its own first.
- Install `owt_accounts::migrations::ALL[4]` (`owt_accounts_local`) as the app's next
  unused migration version after that, whether or not the app uses local accounts,
  and keep awaiting `migrations::complete` before serving (it validates the
  constraint this one adds). It takes the table `account_local_identities` (with its
  `_pkey` and `_account` indexes), the column `accounts.password_sign_in` (every
  existing account keeps password sign-in) and the constraint
  `accounts_password_sign_in_hash`: an app with one of those names renames its own
  first (`migrations::conflicts` names it).
- `owt_accounts::Refused` has a new variant, `NoPasswordSignIn` (`store::set_password`
  on an account whose password sign-in is off). `Refused` is not `#[non_exhaustive]`:
  an exhaustive `match` on it adds an arm.
- `owt_accounts::social::Connections` has a lifetime, `Connections<'a>`, for the words
  it draws with: a field or return type naming it becomes `Connections<'static>`.
- Move the npm stylesheet package with
  `npm install -D @onewaytek/owt-stack@github:onewaytek/owt-stack#v0.6.0`, not by
  editing the tag in `package.json`, and check the lock's `resolved` commit (see
  **Tailwind:**): a plain `npm install` keeps the old commit in `package-lock.json`.
- **Re-applying the OpenShift template:** pass `-p POSTGRES_MAJOR=<the major the
  cluster runs>`, and keep compose and CI's `postgres-major` on it. The default, 18,
  upgrades an older cluster in place (or is refused before CNPG 1.26). Moving to a
  new major is its own step: "Upgrading Postgres" under "Commands, CI, releases and
  deployment". The new `DB_SUFFIX` parameter leaves the default render as it was.
- **An app moving from a template that took no backups** (a hand-written one, or
  none) applies this one, at its current major, and confirms the first backup
  completed (`oc get backups.postgresql.cnpg.io` shows the immediate one `completed`)
  before deploying a migration it can't undo. That apply's backup pauses a single
  instance for a few seconds during its rollout, and its prune needs the internal
  image registry ("Backups come with it", under "Commands, CI, releases and
  deployment").
- The OpenShift template's Deployment reads `myapp-env` whole and `REDIS_URL` from
  `myapp-redis`'s `url`, each only if it exists, so the next apply rolls the pods once
  and changes nothing else. An app whose environment was patched onto the Deployment
  (`oc set env`) moves it into `myapp-env` in the order "Moving from `oc set env` to
  `myapp-env`" gives (the Secret, then the apply, then the entries off: an entry left
  behind silently wins over the Secret), and its hand-made Redis and CronJobs onto
  `redis.yaml` and `cronjob.yaml` ("Commands, CI, releases and deployment"). Check
  first that no Secret of either name already holds something else.

### Authentication

- `oauth::Provider`'s `scope` is a `Cow<'static, str>`: a literal becomes
  `scope: "openid email".into()`, and a scope from configuration is a `String`
  (`scope: configured.into()`), no longer leaked to get a `&'static str`.
- `oauth::Error` is `#[non_exhaustive]`: a `match` on it adds a `_` arm.

## Upgrading from 0.4

- **The cache starts cold once:** its keys move from `<prefix>:` to `<prefix>:c:`, so
  no cache key can name a lease. Old keys expire or are evicted on their own.
- `Bus::redis` refuses a prefix with characters other than ASCII letters, digits,
  `_`, `.` and `-`, and a zero `beat_every`.
- `CHANGE_REQUESTS_URL` must be `https` unless it names `localhost` or a cluster
  service by its absolute name (`….svc.cluster.local.`, with the final dot), and may
  not carry credentials, a query or a fragment.
- `serve::serve` closes a connection whose request head (or the next one on a
  kept-alive connection) takes over 30 seconds, holds 4096 connections at most, and
  stops draining after 20 seconds, which also ends an SSE stream still
  open then; the new `serve_with` sets other bounds (build its `ServeOptions` from
  `default()`). It serves HTTP/1.1 only: no h2c. A WebSocket leaves the
  server at its upgrade and is bounded by none of these: its handler limits how many
  it holds and for how long. Behind the OpenShift router, and with SSE, see
  "Serving" below.
- `jobs::singleton` aborts a run whose lock is no longer seen held. Behind a
  transaction-mode pooler (PgBouncer) the check lands on another server connection,
  so every run longer than `jobs::LOCK_CHECK` is aborted: give singletons a direct
  connection.
- `CrossOrigin::trust` panics on an entry that is not an `http(s)` origin; blank
  entries are still ignored.
- A 5xx response no longer seals session changes, except a sign-out, which then
  seals an empty session.
- `session::key_for` is new and recommended: `key_from_base64` makes a secret
  copied between environments one key. Moving to it signs everyone out, unless the
  old key opens sessions for a while (`also_open_with`, above).
- `key_from_base64` and `key_for` refuse a secret that is a pattern rather than
  random bytes (fewer than 8 distinct byte values); a test fixture of `[7u8; 64]`
  needs real bytes.
- `RequestInfo::at` always yields a path starting with `/`.

### Authentication

- `oauth::oidc` takes the issuer as its third argument (as the issuer writes its
  `iss`: a lower-case host, no default port; a trailing `/` is dropped) and returns
  `Result<Provider, oauth::Error>`: it refuses an issuer or endpoint that is not
  `https` (`http` only on the loopback host). `Provider` has an `issuer` field: a
  struct literal adds `issuer: None`, or starts from a preset with `..`.
- `Client::complete` needs an ID token from an OIDC provider, held to its `iss`, its
  `aud` (and `azp`) naming this client, its `exp`, and its `sub` being the
  user-info response's; ask for the `openid` scope. A redirect from the token or
  user-info endpoint is refused.
- `complete` holds a hand-built `Provider` whose `issuer` is `Some` to the form
  `oidc` gives (no trailing `/` on the issuer; issuer, token and user-info URLs
  `https`, or `http` on the loopback host, with no credentials), or fails with
  `Error::Config`.
- The `google`, `discord` and `twitch` presets (and `oidc`'s) return no identity for
  an empty `sub` or `id`, so `complete` fails with `Error::NoIdentity`.
- `oauth::Error` has new variants, `IdToken`, `Config` and `Redirected`; a `match`
  on it needs arms.
- An app with its own code exchange (to keep the person's tokens) makes none of
  these checks. The next release brings `Client::complete_with_tokens`, `refresh`
  and `client_credentials`, which make them; move to those then.
- `password::verify_or_decoy` runs the decoy check for any stored hash it cannot
  verify, not only a missing one; `password::usable(hash)` says which those are.
- `password::needs_rehash` is true for a hash of an older Argon2 version (`v=16`)
  too, even at today's costs.
- `jwt::Verifier` refetches keys older than `jwt::KEYS_MAX_AGE` (an hour), refuses
  encryption keys, and refuses every token once its keys could not be refetched for
  `jwt::KEYS_STALE_LIMIT` (a day).

### Accounts

Install `ALL[1]` (`owt_accounts_roles`) and `ALL[2]` (`owt_accounts_constraints`)
as the app's next unused migration versions (an app's own migrations hold the low
numbers; see "Tables"), and **await `owt_accounts::migrations::complete(&pool)`
after the migrations run and before serving**, at every start. An app with an OIDC
provider moves its identities to the issuer's key first (see "Upgrading from 0.4 (identities)" under
"Accounts"); `Welcome::match_verified_email` and `Arrival::Matched` are gone.

`0003` changes only the schema, under a 5-second lock timeout (a deploy that cannot
have its locks fails and is run again): the `username_skeleton` column, and
constraints added `NOT VALID`, which bind every write from then on, a 0.4 replica's
still running included (it gets an error for a row it would write in the old form).
`complete` then moves each account made before it, in Rust, as sign-in normalizes
what is typed, and validates the constraints once every row holds them:

- **Usernames are NFKC-normalized** (a fullwidth `ａｄｍｉｎ` becomes `admin`, `´bob`
  a name without the leading space NFKC gives it), and `@` becomes `-`. One that
  would become another account's name takes its id as a suffix (`admin-42`), or the
  first free name after that. Its owner signs in with the new name, or by email or
  a provider; typing the old one now reaches the account it became like (`admin`),
  so tell them: `Completed::renamed` lists every rename, and it is logged.
- **Emails are NFKC-normalized and lower-cased.** One that would become another
  account's address, or has nothing before its `@`, is cleared
  (`Completed::emails_cleared`).
- **A password hash the library cannot verify is cleared** (a legacy format, a
  damaged value; `Completed::passwords_cleared`). It never opened the account. An
  Argon2 hash without its version field is kept: it verifies.
- **A negative session epoch becomes 0.**
- **Each account gets its lookalike key.** An old account whose name is a lookalike
  of an earlier one keeps it, under a key carrying its id; new names are held to the
  rule. A row an older replica writes during the rollout has no key until the next
  `complete`; `store::create` compares a new name against such rows too.
- **Identities with an empty provider or subject are deleted** (they matched no
  one), **sign-in links are cut to 30 days**, and links whose digest is not a
  SHA-256 (no token could match one) are deleted.

`complete` never fails a start over one account: one it cannot move is logged and
listed in `Completed::failed`, and tried again next time; `Completed::validated` is
`true` once every constraint holds for every row.

Also:

- `store::create` takes a pool; `store::create_in` takes a connection (inside a
  transaction, say).
- `links::MAX_TTL` is 30 days (it was a century); longer `ttl`s are capped.
- `store::authenticate` fails a sign-in whose password changed while it was checked;
  `store::change_password` is new.
- `Refused` has `CurrentPassword` and `UsernameLookalike` variants.
- `Linked::label` shows an email only when the provider verified it.
- The social routes refuse cross-origin `POST`s themselves.

### Serving

`serve::serve`'s bounds (above, and "Bounds" under "Wiring an app") are new in 0.5,
and two of them reach further than their names:

- **An app behind the OpenShift router serves with a longer
  `header_read_timeout`.** It is also how long an idle kept-alive connection stays
  open (30 s), and the router reuses idle connections to the pod for longer (its
  `timeout http-keep-alive` is 300 s), so a request it sends on a connection the app
  has just closed fails with a 502, now and then. Move `main` to `serve_with` with
  the timeout above the router's, as "Wiring an app" shows.
- **SSE streams count.** A Server-Sent Events stream is an ordinary HTTP/1.1
  response, so each open one holds one of the 4096 connections (`max_connections`)
  for as long as it lasts, and a stop cuts every stream still open at the 20-second
  drain. A WebSocket leaves the count at its upgrade and is not drained. An app with
  many SSE clients raises `max_connections` with `serve_with`, and its pages
  reconnect after a rollout and fetch what they missed.

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

`just check` is the gate (fmt, clippy over every crate and feature and over
`owt-change` and `owt-auth` without their defaults, the tests with the README
doctests, `cargo audit`), and CI runs the same command. The Redis tests run when
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
(`feat(web): …`, `fix(auth): …`, `docs: …`), checked on every pull request. A subject
starts lower-case unless its first word is a code identifier (`PUBLIC_URL`,
`ClientIp`, `Sessions::from_env`, or anything in backticks), so
`fix(deploy): PUBLIC_URL comes only from the params file` passes and
`fix(web): Drop the cache` does not; an app without a commitlint configuration of
its own is checked by the same rules (`commitlint.config.mjs`). Scopes
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
