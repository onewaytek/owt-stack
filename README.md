# owt-stack

An opinionated stack used as a base for One Way Tek projects:
Rust, Axum, SQLx on Postgres, Redis, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; flash messages; the request as page chrome reads it; htmx fragments at their own URLs; fingerprinted static URLs; response headers; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | Argon2id hashing off the runtime, accepting Django `pbkdf2_sha256` hashes for migration; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar; the router on an ephemeral port; golden-page snapshots; page/fragment agreement |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow: fmt, audit, sqlx metadata, clippy, tests (on ARC), and the stylesheet build |
| `templates/Dockerfile` | cargo-chef, an npm Tailwind stage, distroless non-root runtime |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger, Service, Route, CNPG Postgres |
| `tailwind/owt.css` | font stacks and htmx state variants (`htmx-request:opacity-50`) |

Every Rust example below is compiled by `cargo test` (the `readme` crate includes this
file as its docs), so an API change that breaks these instructions fails CI.

## Adding it to an app

```toml
[dependencies]
owt-web = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.2.0" }
owt-runtime = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.2.0" }
# As needed:
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.2.0" }
owt-bus = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.2.0" }

[dev-dependencies]
owt-test = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.2.0" }
```

`owt-runtime`'s features: `metrics` (default) for Prometheus, `otel` for trace export.

A shared crate is only shared while the majors agree: an app that names `axum`, `sqlx`,
`askama` or `redis` directly must use the major in this workspace's `Cargo.toml`.

**Developing against a local checkout:** patch the git source in the app's
`.cargo/config.toml` (not committed) instead of editing `Cargo.toml`:

```toml
[patch."https://github.com/onewaytek/owt-stack"]
owt-web = { path = "../owt-stack/crates/owt-web" }
owt-runtime = { path = "../owt-stack/crates/owt-runtime" }
```

**The repository is private**, so fetching it needs a token with read access to it:

- **CI:** an `OWT_STACK_TOKEN` secret (organization or repository), passed to the
  reusable workflow with `secrets: inherit`.
- **Image builds:** the same token as a BuildKit secret, `owt_stack_token`
  (`templates/Dockerfile` shows the step that mounts it).

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
use owt_web::{assets::Assets, csrf::CrossOrigin, headers, session::Sessions};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SessionData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<owt_web::flash::Flash>,
}

pub fn router(key: cookie::Key, assets: Assets, trusted: &[String]) -> Router {
    let sessions = Sessions::<SessionData>::new(key, "session", Duration::from_secs(14 * 86_400), true);
    let pages = Router::new()
        .route("/healthz", get(owt_web::healthz))
        // ... the app's routes ...
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
        .layer(from_fn(headers::private_by_default))
        .layer(from_fn(headers::security))
}
```

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
logged and never shown. An app may keep its own error enum in its domain's words and
convert it with `impl From<AppError> for owt_web::Error`.

A page's context carries the request (`RequestInfo`) and the flash messages, and
derefs to the request, so templates write `layout.path` and `layout.query_with(..)`.

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
<a href="{{ layout.query_with("page", Some("2")) }}">Next</a>"#)]
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
partial.

```rust
use askama::Template;
use axum::{http::HeaderValue, response::{IntoResponse, Response}};
use owt_web::fragment::{Fragment, reselect};

#[derive(Template)]
#[template(ext = "html", source = r#"<section id="viewport">{{ x }},{{ y }}</section>"#)]
struct Viewport { x: i64, y: i64 }

/// `GET /map?x=..&y=..`: the whole page.
async fn page() -> owt_web::Result<Response> {
    let body = owt_web::render(&Viewport { x: 1, y: 2 })?;
    // A stale client that htmx-requests this URL swaps only #viewport out of it.
    Ok(([reselect("#viewport")], body).into_response())
}

/// `GET /map/view?x=..&y=..`: the fragment, recorded in history as the page's URL.
async fn view() -> owt_web::Result<Fragment> {
    Fragment::render(&Viewport { x: 1, y: 2 }, HeaderValue::from_static("no-store"))?.page("/map?x=1&y=2")
}
```

The fragment's cache policy is a required argument; use `no-store` for anything that
differs per person. Test that page and fragment agree with `owt_test::fragment`
(below).

### Authentication

```rust,no_run
# async fn demo(stored_hash: &str, code: &str, pending: owt_auth::oauth::Pending) -> anyhow::Result<()> {
use owt_auth::{jwt, oauth, password};

// Passwords: Argon2id on the blocking pool. Django hashes verify too; rehash them.
if password::verify("correct horse", stored_hash).await && password::needs_rehash(stored_hash) {
    let _new_hash = password::hash("correct horse").await?;
}

// Sign-in with a provider: redirect to `url`, keep `pending` in the session, then
// on the callback check the state and trade the code.
let google = oauth::Client {
    provider: oauth::google(),
    client_id: "id".into(),
    client_secret: "secret".into(),
    redirect_uri: "https://app.example/accounts/google/login/callback/".into(),
};
let (_url, _pending) = google.begin()?;
if pending.matches("state from the callback") {
    let who = google.complete(&reqwest::Client::new(), &pending, code).await?;
    println!("{} <{:?}>", who.uid, who.email);
}

// Machine clients with an IdP's token: signature, issuer, audience, expiry.
let verifier = jwt::Verifier::discover(reqwest::Client::new(), "https://sso.example/realms/x", "myapp").await?;
let claims: jwt::Claims = verifier.verify("eyJ...").await?;
# let _ = claims; Ok(()) }
```

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

## CI, images and deployment

**CI:** call the reusable workflow. It runs fmt, `cargo audit`, the `.sqlx` freshness
check, clippy and the tests on ARC, with Postgres and Redis as services:

```yaml
jobs:
  checks:
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@v0.2.0
    with:
      database: myapp        # empty for no Postgres
      postgres-major: "18"   # match the CNPG image
      redis: true
      css-script: css:build  # empty to skip the stylesheet job
      extra-env: |           # test-only values, never real secrets
        SESSION_SECRET=...
    secrets: inherit
```

Image builds belong on GitHub-hosted runners (the ARC runners have no Docker daemon).

**Image:** copy `templates/Dockerfile` and set `BIN` and `PORT`. Pass the token as a
BuildKit secret (`secrets: owt_stack_token=${{ secrets.OWT_STACK_TOKEN }}` in
`docker/build-push-action`). Distroless has no shell; keep a debian-slim runtime if
operations `oc exec` shell tools into the pod.

**OpenShift:**

```sh
oc process -f templates/openshift/app.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p IMAGE=ghcr.io/onewaytek/myapp -p CHANNEL=rc -p PORT=8000 | oc apply -f -
```

The ImageStream polls ghcr for the channel's tag, and the Deployment's trigger rolls
out each new digest. App-specific environment is a patch on the Deployment.

**Tailwind:** depend on the npm half and import it after Tailwind:

```json
"devDependencies": { "@onewaytek/owt-stack": "github:onewaytek/owt-stack#v0.2.0" }
```

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
- **Sessions are cookies.** Sealed with AES-GCM; no store, no query per request.
  Revoke by epoch (a counter in the account, copied into the session at sign-in).
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

## Working on owt-stack

`cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features`.
`owt-bus`'s Redis test runs when `REDIS_URL` is set and is skipped otherwise.

**Keep this README's instructions current.** A change to a public API, a template, the
workflow's inputs or how an app adopts something updates the matching section here in
the same pull request. The Rust examples are doctests, so a stale example fails
`cargo test`; check the YAML, CSS and shell examples by eye.

**Releasing:** bump `version` in the workspace `Cargo.toml` and `package.json`, update
the tags in this README, merge, then tag `vX.Y.Z` on `main`. Apps move by changing
their tag.
