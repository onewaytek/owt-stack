# owt-stack

An opinionated stack used as a base for One Way Tek projects:
Rust, Axum, SQLx on Postgres, Redis, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; flash messages; the request as page chrome reads it; htmx fragments at their own URLs; fingerprinted static URLs; `Cache-Control` as a typed policy; security headers and a nonce-based content security policy; a response deadline and body cap; safe `?next=` redirects; preference cookies (an allowed set, `Secure`, apart from the session's); the client's address behind proxies; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers; shared page components (alerts, form fields, pagination, an error body) styled by semantic tokens |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); a Redis read-through cache that never fails a request (feature `redis`); background jobs on every replica, on one at a time or on a Redis lease's holder (feature `redis`); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | sign-in throttling by address and account; a guard for anonymous forms (honeypot, Turnstile, a budget per address); Argon2id hashing off the runtime with bounded concurrency and a decoy check for unknown accounts; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-accounts` | the `accounts` table and its migration; create and authenticate (decoy check, rehash, username or email); sessions revoked by epoch (sign out everywhere, password change, deactivation); the `Signed`, `Staff` and `Maybe` extractors over one load per request; provider identities linked to accounts; local and system accounts an app reaches by a key of its own, with no password; one-time sign-in links; roles (user, staff, and the app's own, with the `Holds<R>` extractor); the staff accounts admin; the operator's account commands as a clap subcommand (feature `cli`); sign-in with a provider (routes, configuration, buttons, connections) |
| `owt-crypt` | envelope field encryption: XChaCha20-Poly1305 field seals under data keys per tenant wrapped by a KEK, ciphertexts bound to their table, column and row, key versions with rotation, re-encryption and rewrap jobs, HMAC blind indexes for equality search, zeroized keys; a local KEK for development and staging, and a YubiHSM 2 KEK (feature `yubihsm`) |
| `owt-storage` | objects in an S3-compatible bucket (B2, R2, MinIO): client-side encryption through `owt-crypt` in bounded memory, streaming multipart uploads, presigned URLs, verified deletion |
| `owt-audit` | an append-only, hash-chained audit log: one chain per tenant, SHA-256 over a canonical encoding, triggers that refuse changes, a verifier (and its clap subcommand, feature `cli`), and anchoring of the chain heads to external write-once storage |
| `owt-change` | change requests from a site's own pages: a floating "Request a change" button for signed-in admins, and the endpoint that forwards what they ask, with who asked, to a work tracker under the site's key |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar, signed in as an account without Argon2; account fixtures; the router on an ephemeral port; golden-page snapshots; page/fragment agreement; the browser fetches nothing from another origin, and vendored files match their pins |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow on ARC: the app's `just check`, or built-in fmt, audit, sqlx metadata, clippy and tests; the stylesheet build |
| `.github/workflows/release-please.yml` | this repository's releases: versions and the changelog by release-please |
| `.github/workflows/conventional-commits.yml` | Conventional Commits checked on every pull request, here and, as a reusable workflow, in an app: the title and every commit, with one commitlint and one configuration |
| `.github/workflows/release.yml` | reusable releases from conventional commits: stable on `main`, prereleases on `rc`, optional version write-back and changelog |
| `.github/workflows/image.yml` | reusable image build for a released tag, daemonless on ARC (or the Dockerfile, GitHub-hosted), pushed to ghcr with the channel's floating tags |
| `.github/workflows/image-check.yml` | reusable, opt-in: the same image built and verified on a pull request, pushing nothing, for a caller that grants only `contents: read` |
| `.github/workflows/promote-rc.yml` | reusable rc channel: merge a PR (or `main`) into `rc` and start its prerelease, or into `rc-candidate` for checking first |
| `.github/workflows/publish-rc.yml` | reusable: move `rc` to a checked `rc-candidate` and start its prerelease |
| `.github/workflows/requeue-rc.yml` | reusable: re-run a PR's promotion that was cancelled while waiting or refused because `rc` moved |
| `templates/justfile`, `templates/compose.yaml` | the commands every app answers to (`just check`, `just db`, `just dev`), and Postgres and Redis for them |
| `templates/vendor-js` | downloads the vendored browser files `vendor.pins` lists, refusing any hash mismatch |
| `templates/dependabot.yml` | an app's `.github/dependabot.yml`: weekly `fix(deps)` pull requests for its action and workflow pins, its crates and its npm packages, minors and patches grouped |
| `templates/Dockerfile` | Red Hat Hummingbird images throughout: cargo-chef, an npm Tailwind stage, a minimal non-root glibc runtime that keeps a shell (with `templates/dockerignore`) |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger, a `migrate` init container as the schema's owner and the app serving as a runtime role that owns nothing, the app's environment from a Secret, Service, Route, CNPG Postgres over verified TLS with nightly volume-snapshot backups and their pruning, NetworkPolicies |
| `templates/openshift/redis.yaml` | an optional Redis for the cache, the bus and leases: in memory, bounded, LRU-evicted, behind a password, reachable by the app alone, connecting to nothing |
| `templates/openshift/egress.yaml` | where the app's pods (or a task's) may connect: its database, its Redis, the cluster's DNS and port 443 of the internet, and nothing else |
| `templates/openshift/tunnel.yaml` | the public address on a private cluster: a locally managed Cloudflare named tunnel of the app's own, two `cloudflared` connectors forwarding its host to the app's Service, and their NetworkPolicies |
| `templates/openshift/apply.sh` | renders every template present from the app's `params.env` (and `jobs/*.env`), plus an optional `pre-render` hook, `oc diff` by default, `--apply` to apply; `apply-test.sh` proves it against a stand-in `oc` |
| `templates/openshift/cronjob.yaml` | a scheduled task in the app's image, with the app's database, TLS, environment and NetworkPolicies |
| `templates/openshift/env.sh` | creates and patches the app's `myapp-env` Secret from an `env.env` of its settings: literals, keys generated once, keys taken from the caller's environment; `env-test.sh` proves it |
| `templates/openshift/restore-drill.sh` | proves a backup restores, on throwaway clusters, and rehearses a Postgres major upgrade |
| `templates/openshift/monitoring.yaml` | Prometheus scraping for the app's metrics and its Postgres (needs `monitoring-edit`) |
| `tailwind/owt.css` | font stacks, htmx state variants (`htmx-request:opacity-50`), and the `owt-*` classes the shared components and the change-request button use |

Every Rust example below is compiled by `cargo test` (the `readme` crate includes this
file as its docs), so an API change that breaks these instructions fails CI.

## Adding it to an app

<!-- x-release-please-start-version -->
```toml
[dependencies]
owt-web = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-runtime = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
# As needed:
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-bus = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-accounts = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-change = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-crypt = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-storage = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
owt-audit = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }

# The app's own: static files, request logs, compression.
tower-http = { version = "0.7", features = ["fs", "trace", "compression-gzip", "compression-br"] }

[dev-dependencies]
owt-test = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0" }
```
<!-- x-release-please-end -->

`owt-runtime`'s features: `metrics` (default) for Prometheus, `otel` for trace export,
`redis` for leases and leased jobs.
`owt-crypt`'s: `yubihsm` for `YubiHsmKek` (it builds libusb from source when the system has none, so it needs a C compiler).
`owt-change`'s: `accounts` (default) for `owt_accounts::Staff` as its admin.
`owt-accounts`' `test-util` (off by default, for `[dev-dependencies]`) gives the admin's
view models an `example()` each, for an app's tests of its own templates, and
`policies::agree_to_current` for fixtures (`owt-test` turns it on).
`owt-auth`'s: `jwt` (default) for bearer-token verification, which brings `rsa` and an
audit ignore (see "Authentication"); `redis` for a sign-in throttle counted in Redis, so
its budgets hold across replicas (see "Authentication"). The TOTP, recovery-code and
password-policy modules need no feature.

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
        ..logging::Options::default()
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

A credential is read with `env::secret`, which returns a
`logging::Sensitive<String>` that prints as `[redacted]` (`expose()` reads it), so
a derived `Debug` of the config that keeps it does not print it. `env::Vars`, a map
of variables for tests, prints its names and never its values.

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
a bare `axum::serve` also answers HTTP/2 without TLS (h2c) when axum's `http2`
feature is on.

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

`PoolConfig::connect` keeps trying an unreachable database for a minute
(`db::STARTUP_PATIENCE`), with a warning each time, so a pod that starts while the
database is fenced for a nightly offline snapshot, or switching over, waits rather
than crash-restarting; a refused password, a missing database or a certificate that
does not verify fails at once. Each attempt also waits out `acquire_timeout` (5 s)
for a refused connection, so the worst case is a little over a minute, inside the
template's five-minute startup probe. `connect_within(url, patience)` sets another
bound (`Duration::ZERO` tries once).

`PoolConfig` also bounds what one request can hold. `acquire_timeout` is 5 s, so a
saturated pool fails a request in seconds instead of holding it to the request
deadline. Every connection carries Postgres's `statement_timeout` (30 s, the `Limits`
request deadline: a query whose request timed out stops on the server too) and
`idle_in_transaction_session_timeout` (60 s: a transaction left open while its task
awaits something else ends, with its locks), as startup parameters that win over the
URL's `options`. `migrate_locked` runs without the statement timeout; other long work
uses `SET LOCAL statement_timeout` in its transaction, or a pool with
`statement_timeout: None` (`reserve_beside` builds one beside the main pool). `None`
leaves either to the server. A connection pooler in transaction mode that refuses
startup parameters needs both `None`, and the timeouts set on the database role. It also warns at start when the database is not
on this machine and its TLS is not verified (`db::unverified_tls(&options)` asks the
same of any `PgConnectOptions`): give the pod `PGSSLMODE=verify-full` and
`PGSSLROOTCERT` (the OpenShift template does), since sqlx's default (`prefer`)
neither requires TLS nor checks the server.

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
    let sessions = Sessions::<SessionData>::new(key, "__Host-session", Duration::from_hours(12), true)
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
    // `/static`, outside the session: immutable for a fingerprinted URL, `no-cache` else.
    assets.mount(Router::new())
        .merge(pages)
        .layer(from_fn_with_state(csp, Csp::layer))
        .layer(from_fn(headers::private_by_default))
        .layer(from_fn(headers::security))
}
```

**Idle timeout and lifetimes.** Three limits end a session: `max_age` (how long a
cookie lives without being resealed), `absolute_lifetime` (from sign-in, however
active: `session::ABSOLUTE_LIFETIME`, 24 hours, unless set, or `max_age` if longer),
and `idle_timeout` (since the person's last activity: `session::IDLE_TIMEOUT`, 30
minutes, unless set). These are NIST SP 800-63B-4's AAL2 bounds; an app handling
health data sets AAL3's (12 hours, 15 minutes). An app whose sessions guard nothing
a copied cookie could misuse (a game's guest identity) may call
`without_idle_timeout()`. Revocation is the epoch above:
`sign_out_everywhere`, a password change or a deactivation moves the account's
`session_epoch`, and the validator refuses every session sealed under the old one on
its next request, on every replica.

With an idle timeout, the cookie also carries the last-active time. Activity (a
request that carries the session, is not passive and does not fail) refreshes it at
most once per `idle_refresh` (a tenth of the timeout, at least 15 s, by default;
never more than half the timeout), so a busy page does not rewrite a cookie on every
request, and a session ends between the timeout less one refresh and the timeout
after the last activity, give or take the replicas' clock skew. An activity-only
refresh sets a second cookie (`<name>-seen`), sealed and bound to the session's id,
and leaves the session cookie alone: a slow request in one tab cannot put back a
session another tab has since signed out of. Activity alone does not extend `max_age`: the
session cookie's own expiry moves only when a handler changes the session, so set
`max_age` to the longest working day the app allows, and let the idle timeout end
sessions sooner.

A session past the timeout is no session: its cookies are removed, and
`Session::idle_expired()` is true for that request, so a guard on the app's pages
can redirect to `/login?reason=idle` (the next request carries no cookie to tell).
A request with `owt-passive: 1` (`session::PASSIVE_HEADER`), or whose handler calls
`Session::passive()`, is not activity, so a poll cannot keep an unattended screen
signed in. An app marks its server-sent-event and long-poll routes the same way: an
`EventSource` reconnects on its own and a long poll returns and is reissued, so left
unmarked each reconnect counts as activity and the idle timeout never fires. An
`EventSource` cannot set request headers, so its route calls `Session::passive()`;
a `fetch`-based long poll may send `owt-passive: 1` instead. Every response to a
request whose session stands carries
`owt-idle-remaining: <seconds>` (`session::IDLE_REMAINING_HEADER`), with
`Cache-Control: no-store` and `Vary: cookie`, since the value is one person's.

Turning the timeout on (an upgrade to a build where it is the default included) ends
every session older than it (a cookie sealed without the last-active time counts from
its sign-in), and replicas without it drop the time when they reseal: enable it once
every replica runs a build that knows it, or call `without_idle_timeout()` until
then.

```rust,no_run
use std::time::Duration;
use axum::{Router, routing::get};
use owt_web::session::{Session, Sessions};

# #[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
# struct SessionData {}
# fn demo(key: cookie::Key) -> (Sessions<SessionData>, Router) {
let sessions = Sessions::<SessionData>::new(key, "__Host-session", Duration::from_hours(12), true)
    .absolute_lifetime(Duration::from_hours(12))
    .idle_timeout(Duration::from_mins(15));

// The page polls this (passively) and shows a warning in the last two minutes.
let routes = Router::new().route("/session/idle", get(|session: Session<SessionData>| async move {
    session.passive();
    match session.idle_remaining() {
        Some(left) if left <= Duration::from_mins(2) => format!(
            r#"<div role="alert">Signing you out in {} s for inactivity.
               <button hx-post="/session/stay" hx-swap="none">Stay signed in</button></div>"#,
            left.as_secs()
        ),
        _ => String::new(),
    }
}))
// Any request that is not passive extends the session; this one does nothing else.
.route("/session/stay", axum::routing::post(|| async { "" }));
# (sessions, routes) }
```

The poller is a sibling of the warning it fills, so the "Stay signed in" button
does not inherit its passive header (htmx inherits `hx-headers` from ancestors), and
its click counts as activity. Cross-origin protection needs no token here (see
"Decisions").

```html
<span hx-get="/session/idle" hx-trigger="every 30s" hx-target="#idle-warning"
      hx-headers='{"owt-passive": "1"}'></span>
<div id="idle-warning" aria-live="polite"></div>
```

**The same stack as a builder.** `owt_web::stack::Stack` applies these layers, and the
rest of the order the prose above implies, in the one correct order, so an app does not
re-derive it (axum runs the layers in the reverse of the order they are written, and a
mistake is silent). Innermost first: a marked `NotFound` fallback; the account loader,
inside `Limits` so its database read counts against the deadline; `Limits`; the metrics
timer, outside the limits so a timed-out request is recorded as the 503 it is; the
error pages; the session layer, which seals nothing for a 5xx;
`CrossOrigin`; then, around the routes and `/static` together, `Csp` (so error pages
and refusals carry the nonce and the policy), the default cache policy, the security
headers and, when asked, `noindex`. `/static` sits beside the routes, outside the
session and the error pages, and so outside `Limits` and the timer: a static request
has no deadline of its own and is absent from the duration metric. The session
validator also runs outside the `Limits` deadline. Only the
sessions are required. The account loader and
the timer are closures over the router because `owt-accounts` depends on `owt-web`
(and the timer lives in `owt-runtime`); `with_state` goes before `apply`.

```rust,no_run
use axum::{Router, middleware::from_fn_with_state, response::Html};
use owt_accounts::{Accounts, session};
use owt_runtime::metrics::{self, HttpTimer};
use owt_web::{assets::Assets, csrf::CrossOrigin, headers::Csp, limits::Limits};
use owt_web::{session::Sessions, stack::Stack};

fn router(
    routes: Router,
    sessions: Sessions<session::Data>,
    assets: Assets,
    cross_origin: CrossOrigin,
    pool: sqlx::PgPool,
) -> Router {
    Stack::new(sessions)
        .limits(Limits::default())
        .cross_origin(cross_origin)
        .csp(Csp::new().report_only(true))
        .timer(|r| r.layer(from_fn_with_state(HttpTimer("myapp_http_request_seconds"), metrics::http)))
        .accounts(move |r| {
            r.layer(from_fn_with_state(Accounts::new(pool, "/login"), Accounts::load::<session::Data>))
        })
        .error_pages(|status| Some(Html(format!("<h1>{status}</h1>"))))
        .assets(assets)
        .noindex(false) // true on staging hostnames
        .apply(routes)
}
```

`no_store_by_default()` swaps `headers::private_by_default` (HTML only) for
`headers::no_store_by_default` (every response); `apply` installs the marked
`NotFound` fallback, **replacing** a fallback the routes already have (a sign-in
redirect, a catch-all page); `keep_fallback()` leaves the router's own.

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
  from `SESSION_SECRET` (required), the purpose `SESSION_KEY_PURPOSE` when it is set
  (the whole purpose, taken exactly), else `myapp/` plus `SESSION_PURPOSE`, else
  `POD_NAMESPACE`, else `local` (`session::purpose_from`); `local` is for
  development, and in a pod (`KUBERNETES_SERVICE_HOST` set) without any of the three
  variables it is an error. `Sessions::from_vars` reads a map instead, for tests.

  **Moving onto `from_env` without signing anyone out.** The key must stay the one
  the app derives today, so first read the purpose actually in effect, from the live
  configuration rather than the code's defaults: an app whose unset purpose meant
  `myapp/development` changes key once `POD_NAMESPACE` reaches its pods, because
  `from_env` reads that next. Then keep it: an old purpose `myapp/<rest>` is
  `SESSION_PURPOSE=<rest>`, and one of another shape (`myapp https://myapp.example`)
  is `SESSION_KEY_PURPOSE` set to the whole of it. `SESSION_KEY_PURPOSE` replaces the
  `myapp/` and the environment both, so it is only for reproducing a key that
  already exists, set per environment (each environment's own `myapp-env`), never in
  configuration two environments share: there, with a copied secret, it would make
  their keys one. When the purpose must change
  anyway, open the old key's sessions for one `max_age` and drop it after: assert it
  in a test with `Sessions::opens`, which seals a session under a key and reports
  whether these sessions open it.

  ```rust
  # fn main() -> anyhow::Result<()> {
  use owt_web::session::{Sessions, key_for};
  # #[derive(Clone, Default, serde::Serialize, serde::Deserialize)] struct SessionData;
  # let secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==".to_owned();
  # let vars = |name: &str| match name {
  #     "SESSION_SECRET" => Some(secret.clone()),
  #     "POD_NAMESPACE" => Some("myapp-prod".to_owned()),
  #     _ => None,
  # };
  let max_age = std::time::Duration::from_secs(14 * 86_400);
  let old = key_for(&secret, "myapp https://myapp.example")?;
  let sessions = Sessions::<SessionData>::from_vars("myapp", "__Host-session", max_age, true, vars)?
      .also_open_with(old.clone()); // for one max_age after the change, then removed
  assert!(sessions.opens(&old));
  # Ok(()) }
  ```

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
  // `secret`, not `required`: a `Sensitive<String>`, which prints as `[redacted]`.
  let secret = owt_runtime::env::secret("SESSION_SECRET")?;
  let purpose = format!("myapp/{}", owt_runtime::env::required("POD_NAMESPACE")?);
  let sessions = Sessions::<SessionData>::new(
      key_for(secret.expose(), &purpose)?,
      "__Host-session",
      std::time::Duration::from_secs(14 * 86_400),
      true,
  )
  // For one `max_age` after the move, then drop it (never after a leak).
  .also_open_with(key_from_base64(secret.expose())?);
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
- **Static URLs:** `Assets::new("static", "/static").watch(cfg!(debug_assertions))`,
  served by `assets.mount(router)` (or `assets.service()`, nested where the app
  likes): a request whose `?v=` is the file's current hash is `immutable`, any other
  is `no-cache`, a missing file included. Templates call a function that returns
  `assets.url("css/app.css")`, which carries the content hash. Call `assets.warm()`
  at startup, before binding the listener: it hashes every file up front, so no
  request reads a file for its hash (a miss in the static service is read off the
  async executor, but `url` in a handler's template blocks on one). The macro
  `owt_web::static_assets!("static", "/static")` defines both in one module:
  `assets()` (the `Assets`, rehashing on every call in a debug build) and
  `url(path)`.

  A `.css` file is served with the relative URLs inside it versioned too: each
  `url(...)` and `@import` that names a file in the directory (`url(../fonts/a.woff2)`,
  `url('b.woff2#id')`) gains `?v=<hash>` of that file, so fonts and images a
  stylesheet loads are `immutable` like the stylesheet. Absolute and root-relative
  URLs, `data:` URLs, fragments, URLs that already have a query, percent-encoded
  paths and files that are not there are left as written. The stylesheet's own hash
  folds in the hashes of the files it names, so changing a font changes the
  stylesheet's URL, and it is served with an `ETag` (its hash) and a `Content-Length`
  of the rewritten bytes. Nothing changes in the file on disk; the vendored font
  files need no hash in their names.

  ```rust,no_run
  mod assets {
      owt_web::static_assets!("static", "/static");
  }
  # fn main() {
  assets::assets().warm(); // before binding the listener
  let app = assets::assets().mount(axum::Router::new());
  # let _: axum::Router = app;
  let stylesheet = assets::url("css/app.css"); // /static/css/app.css?v=<hash>
  # let _ = stylesheet;
  # }
  ```
- **Metrics:** `owt_runtime::metrics::install(&[], describe)` once, the
  `metrics::http` layer with an `HttpTimer("myapp_http_request_seconds")` on the routed
  router, and the metrics listener on its own port (9464 in the OpenShift template),
  never through the Route: `metrics::spawn_listener(addr, sample).await?` binds `addr`
  (so a taken port fails the start), logs it, serves `/metrics` from a task and returns
  the bound address and the task's handle. It refuses `0.0.0.0`, `::` and `::ffff:0.0.0.0`, so an address
  from an unset variable cannot expose the endpoint on every interface: pass
  `127.0.0.1:9464` on a workstation, and in a pod, where the scraper reaches the pod's
  address, `metrics::spawn_listener_on_all_interfaces(9464, sample)`, which says what it
  does. `metrics::serve` stays for an app that owns its listener.

### Keeping sensitive values out of logs

`logging::init` redacts by field name: a `tracing` event or span field whose name
matches the denylist is logged as `[redacted]`, in the JSON and the text output and, with
feature `otel`, in the span, event and link attributes exported over OTLP. The value is
replaced before it is formatted, so the original never reaches the writer or the
exporter. This includes fields added later with `span.record(..)`.

A name is normalized before it is compared, so `passwordHash`, `Set-Cookie` and
`access.token` are judged as `password_hash`, `set_cookie` and `access_token`, and each
segment of a dotted name is judged on its own (`password.value`). Redacted by default:

* the names `password`, `passwd`, `pwd`, `secret`, `token`, `access_token`,
  `refresh_token`, `id_token`, `authorization`, `cookie`, `set_cookie`, `api_key`,
  `apikey`, `private_key`, `ssn`, `dob`, `date_of_birth`, `email`, `phone`, `address`,
  `name`, `first_name`, `last_name` and `content`;
* a name ending `_secret`, `_token` or `_password`, and one that is or ends in `_` and
  `api_key`, `private_key`, `secret_key`, `access_key`, `signing_key` or
  `encryption_key` (`cache_key` and `idempotency_key` are not);
* a name starting `ssn` or `authorization`, and a name with a `_`-separated word
  (trailing digits ignored) `password`, `passwd`, `pwd`, `secret`, `token`,
  `authorization`, `cookie`, `apikey`, `ssn`, `dob`, `email`, `phone`, `address` or
  `name`, so `user_email`, `phone_number` and `password1` are caught.

The defaults are credentials and personal identifiers any app has. A domain's vocabulary
is the app's to add: `Options::redact_words` takes `_`-separated words that redact a name
wherever they appear, like the default words, and applies whether or not the defaults
do. An app handling health records adds `logging::HEALTH_WORDS` (`diagnosis`, `note`,
`notes`, `transcript`, `mrn`), so `diagnosis_code` and `visit_notes` are caught.

The word rule catches operational names too (`bind_address`, `file_name`), so a name can be
allowed. The defaults never redact the attributes the tracing layers write, by exact
name (`code.filepath`, `code.lineno`, `code.module.name`, `otel.name`, `otel.kind`,
`otel.status_code`, `thread.id`, `thread.name`, ...), nor `target`, `level`, `message`,
`server.address`, `host.name`, `db.name`, `service.name`, `token_count` and
`max_tokens`; any other name under `code.` or `otel.` is judged like the rest, so
`otel.secret` is redacted. `Options::redact_allow` lists names that are never
redacted and wins over every other rule; a dotted name is judged segment by segment,
skipping allowed segments. `Options::redact_fields` adds names to redact,
and wins over the defaults' allowlist. `redact_defaults: false` drops the defaults (and
every rule above) so that exactly `redact_fields` applies.

`logging::Sensitive<T>` wraps a value whose `Debug` and `Display` print `[redacted]`,
also inside a derived `Debug`. It has no `Deref`: `expose()` and `into_inner()` are the
only reads, so each is visible in review. `Deserialize` is transparent, so a form or
configuration struct can hold one. There is no `Serialize`: storing `"[redacted]"` in a
cache or a queue would corrupt the value silently, so persisting one is a compile
error and the code that stores it calls `expose()`.

```rust,no_run
use owt_runtime::logging::{self, Sensitive};

# #[derive(serde::Deserialize)]
struct Login {
    email: String,
    password: Sensitive<String>,
}

# fn run(login: Login) {
let _logging = logging::init(&logging::Options {
    service: "myapp",
    // Redacted in addition to the defaults.
    redact_fields: vec!["nickname".into()],
    // A health-records app's vocabulary.
    redact_words: logging::HEALTH_WORDS.iter().map(|w| (*w).to_owned()).collect(),
    ..logging::Options::default()
});
// `email` is denied by name; `credential` is not, so `Sensitive` keeps the password out.
tracing::info!(email = %login.email, credential = ?login.password, "login attempt");
let password: &str = login.password.expose();
# let _ = password;
# }
```

Redaction is a safety net, not a policy. An app must still not log PHI or credentials
on purpose, and the list is a floor: a field named for something it does not know is
logged. Only names are judged:

* A value inside a message, as in `info!("saw {}", name)`, is not a field and is
  logged as it is. A bridged `log` record is only a message, so it is logged as it is
  too.
* With feature `otel`, span names, event names (a tracing event's message) and status
  descriptions are exported as written, like a message, so they must never carry data.
* A `Debug` or `Display` value is not inspected. `info!(req = ?login)` prints every
  member of `login`, because the field is named `req`; wrap the members in `Sensitive`.
  An error's message prints whatever it contains (a unique violation names the
  duplicate value), so log an error's code or kind where data may appear.

With JSON output (production), `logging::init` also replaces the panic hook: a panic is
logged as one `error` event with its `panic.location` and `thread.name`, and its payload
is left out, because an `expect` message or an unwrapped error's `Debug` can carry data
and the default hook writes it to stderr, the log stream. Text output keeps the default
hook, payload and all, for development.

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

With `owt-accounts`, `owt_accounts::PageCtx` is that context, extracted: the viewer
(`viewer`, `None` when anonymous; the app's `load_with` read as `extra`), the
`request`, the CSP `nonce`, and `flashes()`. The flashes are taken from the session
once, by the first call to `flashes()` (when the page is drawn), so a handler that
draws the page shows each exactly once and one whose later extractor rejects (a
`Form`, say) leaves them for the next page; a request htmx sent for a fragment takes
none (they wait for the next full page; a boosted navigation and a history restore are
full pages). Extract it once per request: a second `PageCtx` finds the session empty
once the first has taken the messages; clones share them.
`PageCtx<T>` names the app's session data when it is not `session::Data`; it must be
`HasFlashes` and the type the session layer holds (another type, or no layer, reads an
empty session and logs at `debug`). Install the session layer outside `Accounts::load`;
without either the context reads as anonymous with no messages, and the CSP layer is what
gives the nonce meaning. `.at("/games/")` is the context for another address (an
error page's "you are here"); `.bare()` is the context for a fragment drawn within or
beside the page, without the flashes, so they are shown once. An app with fields of
its own wraps it and extracts a `PageCtx` first:

```rust
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use owt_accounts::PageCtx;

pub struct Layout {
    page: PageCtx,
    pub theme: &'static str,
}

impl std::ops::Deref for Layout {
    type Target = PageCtx;
    fn deref(&self) -> &PageCtx { &self.page }
}

impl<S: Send + Sync> FromRequestParts<S> for Layout {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self { page: PageCtx::from_request_parts(parts, state).await?, theme: "light" })
    }
}

async fn games(layout: Layout) -> String {
    // `layout.viewer`, `layout.flashes()`, `layout.nonce`, and the request's `path` and
    // `url_with(..)` through the `Deref`s.
    let _fragment = layout.bare();
    format!("{} {}", layout.path, layout.theme)
}
```

### Text in pages

`owt_web::text` holds the small renderings pages repeat. A moment is a `SystemTime`
(a `time::OffsetDateTime` or `chrono::DateTime<Utc>` converts with `.into()`); every
rendering is UTC and rounds down, so two pages show one moment alike.

| function | gives |
|---|---|
| `utc_minute(t)`, `iso_date(t)` | `2026-10-20 14:05 UTC`, `2026-10-20` |
| `ago(t, &words)`, `until(t, &words)` | `5 minutes ago`, `in 2 days`: the largest whole unit (a month is 30 days, a year 365); under a minute, or the wrong way round, is `words.now` |
| `ago_at(t, now, &words)`, `until_at(..)` | the same from a `now` the caller holds (tests, a page rendered once) |
| `plural(n, "game", "games")` | the first word for 1, else the second |
| `like_escape(term)` | `term` with `%`, `_` and `\` literal in a `LIKE`/`ILIKE` pattern |
| `slugify`, `truncate_words`, `linebreaks` | slugs, word truncation, escaped paragraphs |

`Words::ENGLISH` is the default `Words`; an app in another language builds its own
(`now`, the `ago` and `until` patterns with `{}` for the span, and a `Unit` for each of
minute, hour, day, month and year). The functions are plain paths in Askama.

```rust
use std::time::SystemTime;
use askama::Template;
use owt_web::text::{like_escape, Words};

#[derive(Template)]
#[template(ext = "html", source = r#"
<time>{{ owt_web::text::utc_minute(self.at) }}</time>
{{ owt_web::text::ago(self.at, words) }}
{{ self.n }} {{ owt_web::text::plural(self.n, "game", "games") }}"#)]
struct Row<'a> { at: SystemTime, n: u64, words: &'a Words<'a> }

# fn pattern(q: &str) -> String {
// Search with the term's own `%` and `_` taken literally:
//   WHERE name ILIKE '%' || $1 || '%'
like_escape(q.trim())
# }
```

Pass the escaped term as a bound parameter, never spliced into the SQL.

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

### Preference cookies

A language, a theme or a reading mode is a choice from a closed set, kept in an
unsealed cookie for months. `owt_web::preference::Preference` fixes what goes wrong
with a hand-written `Set-Cookie`: it is always `Secure`, `SameSite=Lax`, `Path=/`, with
no `Domain` and a `Max-Age` capped at 400 days (a browser's limit). It reads only a
value in the allowed set (markup or a smuggled second cookie reads as unset), sets
only such a value, and refuses an empty or non-cookie-value allowed set, and a name that is not a
cookie token or that is the session's (with or without `__Host-`), so a preference never shares the session's name.
Name it `__Host-<name>`.

```rust
use std::time::Duration;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect};
use owt_web::preference::Preference;

# fn demo(headers: &HeaderMap) -> Result<(), owt_web::preference::BadName> {
// Once, at start, with the session's cookie name (`Sessions::cookie_name`).
let theme = Preference::new(
    "__Host-theme", &["light", "dark"], Duration::from_secs(365 * 86_400), "__Host-session",
)?;

// Per request: `None` when unset or not an allowed value.
let current = theme.read(headers).unwrap_or("light");
# let _ = current;

// Saving the choice: `set` is `None` for a value outside the set.
let mut response = Redirect::to("/settings/").into_response();
if let Some(cookie) = theme.set("dark") {
    response.headers_mut().append(header::SET_COOKIE, cookie);
}
// `theme.clear()` is the `Set-Cookie` that removes it.
# Ok(())
# }
```

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
// A check that finds no permit within `password::DEFAULT_PERMIT_TIMEOUT` (5 s) fails
// with `password::Busy`: answer 503 (`owt_web::Error::unavailable`), not a mismatch.
let checked = match password::check_or_decoy(given, stored_hash).await {
    Ok(checked) => checked,
    Err(busy) => return Err(owt_web::Error::unavailable(busy.to_string()).into()),
};
if checked.matched() {
    // A hash made with weaker parameters than today's, or of the password as typed
    // before passwords were normalized (`Check::MatchRaw`): store a fresh one.
    if checked == password::Check::MatchRaw || stored_hash.is_some_and(password::needs_rehash) {
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

**A saturated hasher answers 503.** Argon2 checks run a bounded number at once
(`password::set_concurrency`; the CPU count, at most 8). A check waits for a permit
at most `password::DEFAULT_PERMIT_TIMEOUT`, five seconds, then fails with
`password::Busy` instead of queueing for as long as the burst lasts; change the wait
at startup with `password::set_permit_timeout`. `verify`, `check`, `verify_or_decoy`,
`check_or_decoy` and `recovery::find_match` return `Result<_, Busy>`, and `hash`'s
`anyhow::Error` downcasts to `Busy`. `owt_accounts` turns it into
`SignInRefused::Unavailable`, `MfaError::Unavailable` or `Error::Busy`, each a 503
with `Retry-After` through `owt_web::Error::Unavailable`; it is never counted as a
wrong password.

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
rather than key every client alike. A router tested in-process takes its peer from
axum's `MockConnectInfo<SocketAddr>` layer, as axum's own `ConnectInfo` does, and
`owt_test::Client` supplies one by default. `Policies::client_ip` takes its own copy: pass
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
through its RustCrypto backend, `rsa` and `crypto-bigint` 0.5, which carry
RUSTSEC-2023-0071 (Marvin) and RUSTSEC-2026-0387 (timing variability) with no fixed
release on their line, so the app's `cargo audit` fails until it ignores both.
`oauth` needs neither: it reads the ID token the token endpoint answered over TLS and
checks its claims (OIDC Core 3.1.3.7), not its signature. An app that names `owt-auth`
only for passwords, throttles or `oauth` turns the feature off:

<!-- x-release-please-start-version -->
```toml
owt-auth = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.11.0", default-features = false }
```
<!-- x-release-please-end -->

An app that verifies bearer tokens keeps it, and says why the advisories do not apply
in its `.cargo/audit.toml`:

```toml
[advisories]
ignore = [
    # rsa: Marvin, a timing side channel on private-key operations (decryption,
    # signing); no fixed release. It arrives through owt-auth's `jwt` feature, which
    # only verifies signatures, a public-key operation.
    "RUSTSEC-2023-0071",
    # crypto-bigint 0.5: secret-dependent branches in constant-time arithmetic. It
    # arrives the same way (p256/p384), and verifying a signature computes on public
    # values only.
    "RUSTSEC-2026-0387",
]
```

### Anonymous forms

A form anyone can post (a contact form, a public intake) is a free write into the
app's database or an operator's inbox. `owt_auth::bots::Guard` decides each post:

- no Turnstile, `Guard::require_sign_in_without_turnstile()` set and the poster
  anonymous: `Verdict::SignInRequired`, redirect to sign in (nothing is charged);
- over its address's budget: `Verdict::TooMany`, answer 429;
- the honeypot filled: `Verdict::Pretend`, answer **exactly as for a person** (same
  redirect, same thanks) and store or send nothing, so a bot learns nothing to adapt to;
- Turnstile on and the token missing, refused or unverifiable (Cloudflare down fails
  closed): `Verdict::Failed`, show the form again; this is a person's expired token as
  often as a bot, so it is not pretended away;
- otherwise `Verdict::Accept`.

The budget is checked first and the honeypot before Turnstile, so a flood costs a
lookup and a bot costs no Cloudflare request. Give the guard a `Throttle` of its own with
form-sized budgets (`attempts_per_address` a few a minute), so forms and sign-ins do not
spend each other's. Turnstile is configured by `TURNSTILE_SITE_KEY` and
`TURNSTILE_SECRET_KEY`: neither set is off (a honeypot and a budget), one without the
other fails at start, as does an HTTP client that cannot be built. Verification calls
`challenges.cloudflare.com` over TLS, so the runtime image needs CA certificates (the
templates' images have them). `Turnstile::expect_hostname("app.example")` also refuses
a token Cloudflare issued for another site.

`Turnstile::verify` (which `Guard` calls) answers `Result<Outcome, VerifyError>`:
`Outcome::Passed`, `Outcome::Refused { codes }` with siteverify's `error-codes` (empty
for a blank or oversized token), or `Outcome::WrongHostname { got }`.
`Outcome::is_misconfigured()` is true for `missing-input-secret` and
`invalid-input-secret`: the deployment's secret is wrong and every post is refused, so
log those at `warn` or `error` and the rest at `debug`. `Guard` does exactly that
(`error` for a wrong secret, `warn` for a wrong hostname, `debug` for the rest) and
still answers `Verdict::Failed`.

A form that allows "5 an hour" sets `Budgets { attempts_per_address: 5, attempt_window:
Duration::from_secs(3600), .. }` (the window defaults to a minute; the budget refills
evenly across it). A signed-in poster goes through `guard.check_signed_in(ip, honeypot)`:
the budget and the honeypot apply, Turnstile does not, and the answer is `Accept`,
`Pretend` or `TooMany`. With Turnstile off, a guard is open to anyone unless it is built
with `.require_sign_in_without_turnstile()`, so the form can say "only signed-in people
can send" when the keys are missing.

Pick the honeypot's field name so browsers will not autofill it: not `website`,
`email`, `phone` or `name`, which password managers fill for people, and a person
who trips the honeypot is silently dropped. `Honeypot::new("company_url")`, say.

`Verdict::Failed` is a person's problem to fix: render the form again with their input
kept and a message such as "The check did not complete; please try again", and a fresh
widget (a token is single use). Do not say the post was received.

```rust,no_run
use std::sync::Arc;
use owt_auth::bots::{Guard, Honeypot, Turnstile, Verdict};
use owt_auth::throttle::{Budgets, Throttle};
use owt_web::client_ip::ClientIp;

#[derive(serde::Deserialize)]
struct Contact {
    message: String,
    #[serde(default)] company_url: String, // the honeypot's field
    #[serde(default, rename = "cf-turnstile-response")] token: String,
}

# async fn demo(ClientIp(ip): ClientIp, form: Contact) -> anyhow::Result<()> {
// Once, at start; keep it in the app's state.
let guard = Guard::new(
    Honeypot::new("company_url"),
    Turnstile::from_env()?,
    Arc::new(Throttle::new(Budgets { attempts_per_address: 5, ..Budgets::default() })),
);
// In the form's template: `guard.honeypot().markup()` (safe to emit unescaped) and,
// when `guard.turnstile()` is `Some(t)`, Turnstile's widget with `t.site_key()`.

match guard.check(ip, &form.company_url, &form.token).await {
    Verdict::Accept => { /* store or send `form.message`, then redirect */ }
    Verdict::Pretend => { /* the same redirect, nothing stored or sent */ }
    Verdict::TooMany => { /* 429 */ }
    Verdict::SignInRequired => { /* redirect to sign in */ }
    _ => { /* render the form again: "please try the check again" */ }
}
# let _ = form.message;
# Ok(())
# }
```

#### A password policy, a second factor and a throttle across replicas

`password::Policy` is NIST SP 800-63B-4's rules for a new password (a sign-up, a change,
a reset), not for a sign-in: a stored password that no longer passes is not refused.
Revision 4 sets the minimum by use: **15 characters** when the password is the only
authenticator (`Policy::single_factor()`), **8** only as one factor of a pair. `Policy::new()`
is 8, so use it only where every account it covers must have a second factor; raise
either with `min_len`. At most 128, counted in Unicode code points after NFKC
normalization (`password::hash` and `verify` normalize too, so a composed and a decomposed
`é` are one password, and hashes made before that still open and are reported by
`password::check` as `Check::MatchRaw`, to be rehashed); every character allowed,
spaces included; **no composition rules and no expiry** (see "Decisions"). It refuses a
password that contains the username, the email's name part or a word the app lists, and
one in a breached-password corpus the app supplies. The check is offline: no password,
and no prefix of its hash, ever leaves the process.

```rust,no_run
# fn demo(new_password: &str) -> anyhow::Result<()> {
use owt_auth::password::{Bloom, Context, Policy, Refusal, SortedHashes};

// The corpus is a file of SHA-1 hex lines, `HASH` or `HASH:count`: the Pwned Passwords
// download (sorted, ~30 GB for all of it), or the top of it. `SortedHashes` reads the
// file into memory at 20 bytes a hash and answers exactly (200 MB for 10 million
// passwords). `Bloom` is 3.6 bytes a hash at a one in a million false-positive rate (a
// good password sometimes refused, a breached one never accepted); build it once, offline.
Bloom::build_from_file("pwned-sha1.txt", 1e-6)?.save("pwned.bloom")?;
let _exact = SortedHashes::open("pwned-sha1.txt")?;

// At start, then in the app's state.
let policy = Policy::new().min_len(12).breached(Bloom::load("pwned.bloom")?);

let ctx = Context::new()
    .username("ann")
    .email("ann.lee@example.com")
    .word("Sunrise Clinic");
if let Err(refusals) = policy.check(new_password, &ctx) {
    // Each `Refusal` displays as a sentence a form can show.
    let messages: Vec<String> = refusals.iter().map(ToString::to_string).collect();
    let _too_short = refusals.contains(&Refusal::TooShort { min: 12 });
    println!("{}", messages.join(" "));
}
# Ok(())
# }
```

`totp` is the six-digit code an authenticator app shows (RFC 6238: HMAC-SHA1, 30
seconds, the parameters every app implements). `Secret::generate()` is 20 bytes from
the operating system, zeroed on drop, with a `Debug` that prints nothing; store its
bytes sealed. `verify` accepts the current step and one either side, compares in
constant time, and refuses any step at or before `last_used_step`: it returns the
matched step, which the app stores with the sign-in so that a code works once. Throttle
the attempts per account (below): six digits are a one in a million guess.

```rust,no_run
# fn demo(now: std::time::SystemTime, typed: &str, stored: &[u8], last_step: Option<u64>) {
use owt_auth::totp::{self, Secret};

// Enrollment: show the secret once (QR code of the URI, or the base32 to type in),
// and store `secret.as_bytes()` only after a first code verifies.
let secret = Secret::generate().unwrap();
let _uri = totp::otpauth_uri("Acme Health", "ann@example.com", &secret);
let _typed_in = secret.to_base32();

// Sign-in: the matched step is stored as `last_used_step`, in the transaction that
// signs the person in; a replay of the same code finds it spent.
let secret = Secret::from_bytes(stored).unwrap();
if let Some(step) = totp::verify(&secret, typed, now, last_step) {
    let _store_this = step;
}
# }
```

`recovery` makes the codes for a lost authenticator: ten characters of Crockford
base32 (50 bits), shown once as `XXXXX-XXXXX`, stored as Argon2id hashes through the
password hasher. Argon2id rather than a peppered HMAC: at 50 bits a bare fast hash is too weak
to store, a pepper is one more secret to hold and rotate, and the memory-hard hash
needs nothing beyond the table. `find_match` normalizes what was typed (case, hyphens,
spaces, `I` and `L` as `1`, `O` as `0`) and says which stored hash it matches. **Single use is the
caller's:** pass only unused hashes, and mark the row used with a conditional update
(`UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL`), signing in only if it
changed a row.

```rust,no_run
# async fn demo(typed: &str, unused: Vec<(i64, String)>) -> anyhow::Result<()> {
use owt_auth::recovery;

// Enrollment: show `code`s once; store the `hash`es.
let codes = recovery::generate(recovery::DEFAULT_COUNT).await?;
let _show_once: Vec<&str> = codes.iter().map(|c| c.code.as_str()).collect();
let _store: Vec<&str> = codes.iter().map(|c| c.hash.as_str()).collect();

// Sign-in: which unused code, if any, was typed. `password::Busy` (no hashing
// permit in time) is a 503, not a wrong code.
let hashes: Vec<&str> = unused.iter().map(|(_, hash)| hash.as_str()).collect();
if let Some(i) = recovery::find_match(typed, &hashes).await? {
    let _row_to_mark_used = unused[i].0;
}
# Ok(())
# }
```

`Throttle` keys an account's budget on the login as the account store matches it
(NFKC, lower case, trimmed), so `admin` and `ａｄｍｉｎ` spend one budget; a username and
its account's email are two logins and two budgets. Its counts live in the process, and
its first sign-in warns when `POD_NAMESPACE` is set (a pod, likely one of several).
`throttle::shared::SharedThrottle` (the `redis` feature) is `Throttle` counted in Redis, so
a budget holds across replicas instead of multiplying by their number. It has the same
budgets and keys, in the same order, charged before the password is checked; its calls
are async and return a `Refusal`. Counters are fixed windows in one Lua script (a window never slides, and a budget spent
at the end of one and again at the start of the next gives twice it within moments), and an
account's name is stored as a hash. Keys carry `{prefix}` as a hash tag, so it works on Redis
Cluster; the counters expire, so the Redis needs `maxmemory-policy noeviction` (or to be
its own), as the leases do. **When Redis
fails, sign-in fails closed** (`Refusal::Unavailable`: answer 503, not "too many
attempts"): the throttle is all that bounds online guessing, and an outage that locks
people out is a better failure for health records than one that lets an attacker guess;
`FailMode::Open` reverses it. `on_lockout` is called once per window when an account
crosses its limit, the moment to email its owner.

```rust,no_run
# async fn demo(url: &str, ip: std::net::IpAddr, account: &str) -> anyhow::Result<()> {
use owt_auth::throttle::{Budgets, shared::{FailMode, Refusal, SharedThrottle}};

// The prefix is the deployment's, as for `Cache`, `Leases` and `Bus`.
let throttle = SharedThrottle::connect(url, "myapp", Budgets::default())
    .await?
    .fail_mode(FailMode::Closed) // the default
    .on_lockout(|lockout| {
        // Queue "someone is trying to sign in to your account" for `lockout.account`.
        eprintln!("sign-ins locked: {}", lockout.account);
    });

match throttle.sign_in(ip, account).await {
    Ok(()) => { /* check the password */ }
    Err(Refusal::Unavailable) => { /* 503, and page whoever runs Redis */ }
    Err(_) => { /* 429 */ }
}
# Ok(())
# }
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

**Tables:** the library migrates its own tables. At every start, before the app's
own migrator (its tables reference `accounts(id)`), the app awaits
`owt_accounts::migrations::run(&pool)`. It applies `owt_accounts::migrations::ALL`
with a sqlx migrator whose ledger is a table of its own, `_owt_accounts_migrations`,
beside the app's `_sqlx_migrations` in the same schema, under an advisory lock of its
own (`migrations::LOCK_ID`) held on one connection, so replicas starting together
migrate once. The app's `migrations/` holds none of the library's files, its
`sqlx migrate run` never touches the library's tables, and a release that adds a
table changes nothing the app writes. Calling `run` again changes nothing; it
returns what it adopted and applied, and logs it.

A shipped migration never changes: every database that ran it records its checksum,
and sqlx refuses to start against a recorded migration whose text differs (an
error, `MigrationError::Migrate(VersionMismatch)`). A later release appends a new
entry to `ALL`, and a test here pins each file's SHA-256. A migration moves the rows
already there along with the schema, so a database that has run the library for
years ends in the state a new one starts in. The constraints hold what the library
assumes (names in stored form, Argon2 hashes or none, no hash where password sign-in
is off, links of 30 days at most, non-empty subjects), so a row written around it
(an import, a console) cannot be one it would misread. After the migrations run, at
every start and before serving, the app awaits
`owt_accounts::migrations::complete(&pool)`: it moves rows made before a migration
to the stored form (in Rust, as sign-in normalizes) and validates the constraints
the migration added; once done it reads an index and the catalog.

`owt_accounts::migrations::start(&pool, || app_step)` is that sequence once: `run`,
then the app's step (its migrator, under its own lock), then `complete`. `run` and
`complete` log what they did; a failure stops the sequence and is returned, its context
naming the step (`owt-accounts migrations`, `the app's migrations`, `completing the
accounts tables`), so `main` reports it once (`{err:#}` prints the chain).
The binary's `migrate` subcommand and its start-up both call it, so the order cannot
differ between them. Deployed from the OpenShift template, only the `migrate`
subcommand does, in the init container, as the schema's owner; the app serves as a
role that cannot migrate (see "Database roles").

```rust,no_run
# async fn start(pool: sqlx::PgPool, app_migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
let done = owt_accounts::migrations::start(&pool, || {
    owt_runtime::db::migrate_locked(&pool, app_migrator, 8_531_207) // the app's own
})
.await?;
for r in &done.renamed {
    eprintln!("account {} is now {:?} (was {:?}): tell its owner", r.id, r.to, r.from);
}
// ... then serve.
# Ok(()) }
```

An app whose own migrations must partly run first (one that renames an `accounts` of
its own out of the way, say) runs its migrator to that version, then the library's,
then the rest: `migrate_locked_to(&pool, &MIGRATOR, <the rename's version>, id)`,
`migrations::run`, `migrate_locked`, then `migrations::complete`, in place of `start`. Each
is a no-op once applied.

CI and a developer's `just migrate` create a database from nothing, where the app's
migrations need the library's tables first, so the app's binary takes a `migrate`
subcommand that runs this sequence and exits, and both run it instead of `sqlx migrate
run`: the template justfile's `migrate` recipe runs `SQLX_OFFLINE=true cargo run
--locked -- migrate` (the offline build needs the committed `.sqlx/`), and
`rust-ci.yml` takes `migrate-command: SQLX_OFFLINE=true cargo run --locked -- migrate`.
A test's database is made the same way: `#[sqlx::test(migrations = false)]`, then the
test awaits that sequence on its pool before anything else.

**Names the migrations take**, in the schema they run in (the first on the
`search_path`, usually `public`):

| Migration | Tables | Indexes and sequences | Functions | Added to an earlier table |
|---|---|---|---|---|
| `owt_accounts` | `accounts`, `account_identities`, `sign_in_links` | `accounts_pkey`, `accounts_id_seq`, `accounts_username_key`, `accounts_email_key`, `account_identities_pkey`, `account_identities_id_seq`, `account_identities_provider_subject_key`, `account_identities_account`, `sign_in_links_pkey`, `sign_in_links_account` | | |
| `owt_accounts_roles` | `account_roles` | `account_roles_pkey`, `account_roles_role` | | |
| `owt_accounts_constraints` | | `accounts_username_skeleton_key` | | `accounts.username_skeleton`; constraints `accounts_username_skeleton_form`, `accounts_password_hash_form`, `accounts_username_nfkc`, `accounts_email_form`, `accounts_session_epoch_check` on `accounts`, `account_identities_named` on `account_identities`, `sign_in_links_lifetime` and `sign_in_links_digest` on `sign_in_links` |
| `owt_accounts_policies` | `policy_versions`, `policy_acceptances`, `policy_acceptance_events` | `policy_versions_pkey`, `policy_versions_id_seq`, `policy_versions_kind_version_key`, `policy_acceptances_pkey`, `policy_acceptances_version`, `policy_acceptance_events_pkey`, `policy_acceptance_events_id_seq`, `policy_acceptance_events_account` | `policy_versions_immutable()`, `policy_versions_keep_current()` | |
| `owt_accounts_local` | `account_local_identities` | `account_local_identities_pkey`, `account_local_identities_account` | | `accounts.password_sign_in`; constraint `accounts_password_sign_in_hash` on `accounts` |
| `owt_accounts_link_next` | | | | `sign_in_links.next` |
| `owt_accounts_mfa` | `account_totp`, `account_recovery_codes` | `account_totp_pkey`, `account_recovery_codes_pkey`, `account_recovery_codes_id_seq`, `account_recovery_codes_account` | | |

Each table is also a type of its name, and its triggers and constraints are its own.
An app that already has any of these names (a table, view, index, sequence, type or
function, or a column or constraint of that name on the table named) renames its own
first, in a migration of its own that runs before the library's (the paragraph on
`migrate_locked_to`, above). A taken table or index name fails the migration at `CREATE`; a
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
`Provider::key()`, not `Provider::id`. An issuer is written in canonical form (a
lower-case host, no default port, no trailing `/`); `oidc` refuses another spelling,
since it would match no token's `iss`.

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

- `session::sign_out` revokes this session alone: its id goes into
  `revoked_sessions` (migration 0009) until its cookie would have expired anyway,
  and the per-request account load checks it by primary key in the same query, so a
  copy of the cookie taken earlier opens nothing. Expired rows are deleted by later
  sign-outs. `sign_out_everywhere` bumps the epoch and ends every session of the
  account. A database error from `sign_out` still replaces the cookie, but the
  copy stays good until it expires.
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
// that says neither which part was wrong nor whether the account exists (also a login
// with a control character, refused before the throttle is charged), 500 a fault
// (whose message says only that; log its source).
let throttle = Throttle::default(); // in the app's state
match session::password_sign_in(&pool, &throttle, &session, ip, login, given).await {
    Ok(account) => { let _ = account; /* redirect to `next` */ }
    Err(refused) => { let _ = (refused.status(), refused.to_string()); /* the form again */ }
}
// A deployment-wide password (one Argon2 hash in the environment) opening a fixed
// account, which needs no password of its own: the same refusals, throttle and
// `last_sign_in` stamp. The account must be active; a wrong password, a hash that
// opens nothing and a deactivated account all answer `Mismatch`. Everyone shares the
// one account, so its budget is shared by every client: give the gate a `Throttle` of
// its own with a larger `sign_ins_per_account` (and not the one ordinary logins use,
// which it would loosen), and the per-address budgets limit.
# let (shared_hash, desk) = (String::new(), 1_i64);
let gate_throttle = Throttle::new(owt_auth::throttle::Budgets {
    sign_ins_per_account: 1_000,
    ..Default::default()
});
let gate = session::Gate { hash: &shared_hash, account: desk };
match session::password_gate(&pool, &gate_throttle, &session, ip, given, gate).await {
    Ok(account) => { let _ = account; /* redirect */ }
    Err(refused) => { let _ = (refused.status(), refused.to_string()); /* the form again */ }
}
session::sign_out(&pool, &session).await?; // this session, copies of its cookie too
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
// A link can name where to land: `mint_with` takes a local path (`links::valid_next`:
// one `/`, no `//host`, backslash, whitespace or scheme; else `Refused::Next`), and
// `redeem_with` returns it for the handler to redirect to after `session::sign_in`.
let minted = links::mint_with(&pool, ada.id, std::time::Duration::from_secs(900), "outage", Some("/admin/")).await?;
let opened = links::redeem_with(&pool, &minted.token, &ip.to_string()).await?;
let _land_on = opened.next.as_deref().unwrap_or("/"); // opened.account signs in
# let _ = app; Ok(()) }
```

A refusal (`owt_accounts::Refused`) carries the sentence the person reads; a handler
matches `Error::Refused` to re-render the form with it, and the `From` into
`owt_web::Error` answers 422 with the same text.

**Account commands for the operator** (feature `cli`, so clap is built only when asked
for): `owt_accounts::cli::AccountCommand` is a clap `Subcommand` with `create`,
`set-password`, `link`, `staff`, `unstaff` and `hash`, the recovery path for an app
with no staff or a lost password. No password rides in argv: `create` and
`set-password` read one line from stdin when something is piped and generate a
password otherwise (`--generate` forces it); `hash` reads one and prints its Argon2
hash, for a deployment-wide password (`session::password_gate`). A generated password
and a sign-in link are printed once, to stdout, and logged nowhere; `link` takes
`--minutes` (60, at most 30 days), `--reason` (kept with the link for the audit trail,
`cli` unless given) and `--next` (a path on the site to land on after signing in,
`/admin/` say; a host, scheme or backslash is refused), and needs the URL of the app's
`links::redeem_with` route, which returns the `--next` to redirect to. `login` is a username or an email; `create --no-password` makes an account
that a link or a provider opens. The hash begins `$argon2id$…`: quote it with single
quotes in a shell or env file, and double each `$` in a compose file, or it is expanded
and opens nothing. A generated password is shown after the account is made; if the
output fails, the error says the account exists and to set another. The futures are
`Send` and hold no lock on stdin or stdout across an await. `run_with` takes the input
and output explicitly, for a test.

An app with command names or flags of its own (`create-user --host`, a `login-link` that
lives 15 minutes by default) keeps its own clap enum and reuses the handlers:
`#[command(flatten)]` `cli::CreateArgs` or `cli::LinkArgs` into a variant beside its
flags, then call `cli::create(pool, stdin, out, &args)`, which returns the new
`Account` for the app to go on with, or `cli::link(pool, out, &args, default_minutes,
link_url)`. `AccountCommand::Create` and `Link` hold the same two structs.

```rust
use std::io::{self, BufRead, BufReader, IsTerminal};
use clap::Subcommand;
use owt_accounts::cli::{self, CreateArgs, LinkArgs};

#[derive(Subcommand)]
enum Command {
    CreateUser {
        #[command(flatten)]
        account: CreateArgs,
        /// The app's own flag.
        #[arg(long)]
        host: bool,
    },
    LoginLink(LinkArgs),
}

async fn run(command: Command, pool: sqlx::PgPool) -> anyhow::Result<()> {
    let mut piped = (!io::stdin().is_terminal()).then(|| BufReader::new(io::stdin()));
    let piped = piped.as_mut().map(|input| input as &mut (dyn BufRead + Send));
    let mut out = io::stdout();
    match command {
        Command::CreateUser { account, host } => {
            let made = cli::create(&pool, piped, &mut out, &account).await?;
            if host {
                // The app's own step, now that `made.id` exists.
            }
        }
        // A quarter of an hour unless `--minutes` says otherwise.
        Command::LoginLink(args) => {
            cli::link(&pool, &mut out, &args, 15, |t| format!("https://myapp.example/login/link/{t}")).await?;
        }
    }
    Ok(())
}
```

```toml
owt-accounts = { git = "…", tag = "…", features = ["cli"] }
```

```rust
use clap::{Parser, Subcommand};
use owt_accounts::cli::{self, AccountCommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    #[command(subcommand)]
    Account(AccountCommand),
}

async fn main_with(cli: Cli, pool: sqlx::PgPool) -> anyhow::Result<()> {
    match cli.command {
        Command::Serve => Ok(()),
        Command::Account(command) => {
            cli::run(command, &pool, |token| format!("https://myapp.example/login/link/{token}")).await
        }
    }
}
// $ printf '%s\n' "$PASSWORD" | myapp account create ada --email ada@example.com --staff
// $ myapp account link ada --minutes 15
```

**More about the viewer on every request** (a display name, a profile flag): implement
`store::Extra` for a `sqlx::FromRow` type of the app's and install
`Accounts::load_with::<session::Data, Viewer>` in place of `Accounts::load`. Its
`QUERY` is a `SELECT` that names the account's row as `accounts`; the layer runs it as
a `LEFT JOIN LATERAL` in the one query that loads the account and checks the session's
epoch, so it costs no second round trip and a revoked session reads nothing. A
handler names `SignedWith<Viewer>` (walled as `Signed`) or `MaybeWith<Viewer>`;
`Maybe`, `Signed`, `Staff` and `roles::Holds` work unchanged beside them. `QUERY` is SQL pasted
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

#### Multi-factor sign-in and step-up

`owt_accounts::mfa` adds a second factor after the password: an authenticator app (TOTP,
`owt_auth::totp`) with single-use recovery codes behind it (`owt_auth::recovery`), a
policy that can require it, and step-up re-authentication for sensitive actions. Like
the sign-in functions above, they are library functions an app wires to its own routes.
(Passkeys are not here yet.)

`Mfa::password_sign_in` is `session::password_sign_in` plus the question *what does this
account need next?* It answers `Next::Done` (signed in), `Next::Challenge` (it has a
factor) or `Next::Enroll` (the policy requires one and it has none). In the last two the
session holds only a **pending** sign-in: it carries no signature, so `Signed`, `Staff`
and `Maybe` all see an anonymous visitor until `Mfa::challenge` (or, for enrollment,
`Mfa::confirm_totp`) signs it in with a new session id. A pending sign-in lasts ten
minutes, and every answer is charged to the throttle under a key of the account's, so
six digits cannot be guessed. A code works once: a TOTP step at or before the last
accepted is refused (replay), and a recovery code is marked used by the same statement
that checks it is unused.

**Every door is closed where the session is read.** Build the layer's `Accounts` with
`.require_mfa::<T>(mfa)` (`T` the session data type): `Accounts::load::<T>` and `load_with`
then enforce it, with no second layer to remember (installing `load` with another data type
logs an error and answers 503 to anyone signed in, rather than run single-factor). A
signature for an account that has a confirmed factor, or that the policy requires to have
one, then counts as signed in only when the session shows a second factor passed for that
account and epoch; until then the request is anonymous and the session becomes the pending
sign-in above, so a challenge or enrollment page can continue it
(`Mfa::pending_account`). A provider sign-in (`social`), a sign-in link, `password_gate` and
an old `/login` route left in place are all held; none can skip the second factor. Without
that layer only the doors that call `Mfa::first_factor_passed` enforce it. Session data
needs the state: `session::Data` and `social::Data` have it; an app with its own session type
implements `mfa::MfaSession` beside `session::Signed` and clears the state in
`Signed::on_sign_in`. `Mfa::password_sign_in` does not stamp `last_sign_in` until the second
factor passes.

```rust,no_run
use axum::extract::{Form, State};
use owt_accounts::mfa::{Answer, Mfa, Next};
use owt_accounts::session::{Data, SignInRefused};
use owt_auth::throttle::Throttle;
use owt_web::client_ip::ClientIp;
use owt_web::session::Session;

#[derive(Clone)]
struct AppState { pool: sqlx::PgPool, mfa: Mfa, throttle: std::sync::Arc<Throttle> }

#[derive(serde::Deserialize)]
struct Login { login: String, password: String }

async fn sign_in(
    State(app): State<AppState>, ClientIp(ip): ClientIp, session: Session<Data>,
    Form(form): Form<Login>,
) -> Result<&'static str, SignInRefused> {
    let next = app
        .mfa
        .password_sign_in(&app.pool, &*app.throttle, &session, ip, &form.login, &form.password)
        .await?;
    Ok(match next {
        Next::Done => "redirect to the page asked for",
        Next::Challenge => "redirect to the code form",
        _ => "redirect to enrollment",
    })
}

#[derive(serde::Deserialize)]
struct Code { totp: Option<String>, recovery: Option<String> }

async fn challenge(
    State(app): State<AppState>, ClientIp(ip): ClientIp, session: Session<Data>,
    Form(form): Form<Code>,
) -> Result<&'static str, owt_web::Error> {
    let answer = match (&form.totp, &form.recovery) {
        (Some(code), _) => Answer::Totp(code),
        (_, Some(code)) => Answer::Recovery(code),
        _ => return Err(owt_web::Error::bad_request("Enter a code.")),
    };
    // A wrong or replayed code is `MfaError::Invalid`: show it, keep the form, and
    // write the failure to the audit log. A used recovery code is an event to tell the
    // owner about.
    let (_account, events) = app.mfa.challenge(&app.pool, &*app.throttle, &session, ip, answer).await?;
    for event in events {
        println!("audit {} account {}", event.name(), event.account);
    }
    Ok("redirect to the page asked for")
}
```

Enrolling an authenticator is `begin_totp` (a fresh secret, stored unconfirmed, with the
`otpauth://` URI and a QR code as SVG, to show once with `Cache-Control: no-store`) then
`confirm_totp` with the first code, which turns it on and returns ten recovery codes
**once** (only their hashes are stored). `Mfa::factors` lists what an account holds,
`remove_totp` removes the authenticator and its codes (refused with `MfaError::LastFactor`
when the policy requires one), and `regenerate_recovery_codes` replaces the codes.
**Each takes a `ChangeProof`**, which only `Mfa::authorize_change` makes: for an account
that has a factor it requires a second factor used lately (a recovery code counts), for the
first enrollment a recent sign-in, and for a pending enrollment under `Required` it allows
it. A handler that forgets the step-up does not compile. Each change moves the account's
session epoch on, so its *other* sessions end at their next request, and reseals the
current one. Each returns `Event`s with stable names (`mfa.totp.enrolled`, `mfa.totp.removed`,
`mfa.recovery_codes.issued`, `mfa.recovery_code.used`, `mfa.factor.unlocked`,
`mfa.challenge.passed`) for the app's audit log. **Email the account's owner** on a removal,
on a used recovery code, and on any event with `while_pending` set (a factor enrolled from a
pending sign-in, on a password alone). Ten wrong authenticator codes in a row lock it for 15 minutes
(`MfaError::Locked { until, just_locked }`, counted in the database; the answer that locked it
has an event, `err.locked_event(account_id)`, to email the owner about); a recovery code or
`Mfa::unlock_totp` (for staff) unlocks it at once. A `SharedThrottle`'s `on_lockout` hook gets the throttle key of a
second-factor lockout; `mfa::lockout_account(&lockout.account)` is the account id to email.

**The policy and the secret.** `MfaPolicy::Optional` challenges only accounts that
enrolled; `Required` is every account; `MfaPolicy::when(|a| a.is_staff)` is the accounts
the closure names. An account the policy requires, and without a factor, is sent to
enrollment and gets nothing else until it enrolls. Whoever knows its password can
enroll their own authenticator at that point, so the policy protects accounts that
have a factor from a stolen password, not a never-enrolled account from one: give new
accounts a one-time sign-in link, or have staff enroll them. The TOTP secret in
`account_totp.secret` lets whoever reads it make that account's codes for ever:
supply a `SecretSealer` that encrypts it with a key the database does not hold
(`owt-crypt`'s, say). The stored value carries a format byte and the sealer's key id, so
keys rotate (a secret sealed under an older id is opened with it and resealed at its next
use). The default, `Unsealed`, stores it in the clear, marked plain, and logs a warning; it is
for development, and a release build (no `debug_assertions`) refuses it: enrolling, and
signing in with a factor it stored, fail as a fault until a real sealer is set. A plain row is
accepted and sealed at its next use once one is, so adopting one later locks nobody out. Then turn `Mfa::accept_plaintext(false)` on once
none remain (`SELECT count(*) FROM account_totp WHERE get_byte(secret, 0) = 0` is 0): until
then anyone who can write to the table can plant a known secret in a plain row, which the
sealer's authentication would have stopped. A sealer must treat the key id it is handed as
untrusted input (a lookup, never a path).

```rust,no_run
use owt_accounts::mfa::{Mfa, MfaPolicy, SecretSealer};

struct Sealer; // wraps the app's `owt-crypt` key
impl SecretSealer for Sealer {
    // The id of the key `seal` uses now; stored with the ciphertext.
    fn key_id(&self) -> &str { "2026-10" }
    // `context` binds the ciphertext to the account's row: pass it as the associated data.
    fn seal(&self, plaintext: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>> {
        # let _ = context;
        Ok(plaintext.to_vec()) // encrypt here
    }
    // `key_id` names the key it was sealed under, which may be an older one.
    fn open(&self, key_id: &str, sealed: &[u8], context: &[u8]) -> anyhow::Result<Vec<u8>> {
        # let _ = (key_id, context);
        Ok(sealed.to_vec()) // and decrypt here
    }
}

# fn demo(pool: sqlx::PgPool) {
use axum::{Router, middleware::from_fn_with_state};
use owt_accounts::{Accounts, session::Data};

// Staff must use a second factor; everyone else may.
let mfa = Mfa::new("Acme Health")
    .sealer(Sealer)
    .policy(MfaPolicy::when(|account| account.is_staff));

// The layer that reads sessions holds every signature to it, wherever it came from.
let accounts = Accounts::new(pool, "/login")
    .reauth_at("/reauth")
    .enroll_at("/mfa/enroll")
    .require_mfa::<Data>(mfa);
let _app: Router = Router::new()
    .layer(from_fn_with_state(accounts, Accounts::load::<Data>));
# }
```

**Step-up.** The session records when the account last proved who it is, and when it last
used a second factor, tied to the account and epoch it signed in under. `Recent<SECS>`
is an extractor: the handler runs only if the proof is under `SECS` seconds old, and
otherwise the visitor is sent to `Accounts::reauth_at(path)` (`/reauth` by default) with
`?next=` set. `RecentMfa<SECS>` asks for a second factor in that time, for what must not
be done on a password alone. `require_recent` and `require_recent_mfa` are the same
check as a function returning a typed `StepUp` (never recorded, stale, no second factor)
for an app that answers in its own way. An account with no second factor gets
`StepUp::NoSecondFactor` from `RecentMfa` (under `require_mfa`) and is sent to
`Accounts::enroll_at(path)` (`/mfa/enroll`), not to a re-authentication that cannot help. A
session signed in by a way that records nothing (`session::sign_in`, a link, a provider)
counts as *unrecorded* until `mfa::mark_authenticated` stamps it (for the account the
session is signed in as, and only that), so step-up fails closed; it refreshes recency only,
and records no second factor, which the layer still demands of an account that has one. Call
it straight after a credential was checked, never as a keep-alive. `last_sign_in` is stamped
at the password by the older doors (`session::password_sign_in`, links, providers) and after
the second factor by `Mfa::password_sign_in`. The re-authentication page
calls `Mfa::begin_reauth` (the password, for an account that has one), then
`Mfa::challenge` if the account has a factor; both renew the times. Use it before
exporting records, changing or removing a factor or regenerating recovery codes,
changing the password or email, and break-glass access.

```rust,no_run
use std::time::Duration;
use owt_accounts::mfa::{Recent, RecentMfa, require_recent_mfa};
use owt_accounts::session::Data;
use owt_accounts::Signed;
use owt_web::session::Session;

// Ordinary sensitive action: signed in within the last 15 minutes.
async fn export(_: Recent<900>, Signed(me): Signed) -> String {
    format!("export for {}", me.username)
}

// Changing the factors: a second factor within the last 5 minutes.
async fn remove_authenticator(_: RecentMfa<300>, Signed(me): Signed) -> String {
    format!("removing the authenticator of {}", me.username)
}

// The same check, answered in the app's own way.
async fn break_glass(session: Session<Data>) -> Result<&'static str, &'static str> {
    require_recent_mfa(&session, Duration::from_secs(120)).map_err(|_| "re-authenticate")?;
    Ok("access granted and logged")
}
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

- **Who:** only `Staff` who used a second factor within `admin::STEP_UP` (15
  minutes) for every change (any `POST`): a member of staff without one is sent to
  the re-authentication page (`Accounts::reauth_at`), or to enrollment when the
  account has no factor under `require_mfa`, with `?next=` the account's page. Pages
  that only show still open on `Staff` alone. Each change re-checks inside its
  transaction that its
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
  A link is not issued to a deactivated account, and lives at most
  `admin::MAX_LINK_TTL` (24 hours), whatever `Admin::sign_in_links` asks.
- **What is kept:** every response is `no-store` and never framed, a refusal (a 403,
  a 404, a 422) included; a password or link is shown once; each change is logged at
  `info` with who made it and what changed.
- **What is recorded:** each change is an `admin::Event` (actor, account, an
  `EventKind`, a dotted `name()` such as `admin.password.reset`) handed to the app's
  `admin::Recorder` (`Admin::audit`) on the change's own transaction, so the change
  and its audit record commit together; a recorder that fails rolls the change back
  and answers 500. Without a recorder `Admin::routes` warns at startup. An app with
  its own session type names it with `Admin::session::<T>()`, where the step-up
  proof is read.

```rust,no_run
use std::pin::Pin;
use owt_accounts::admin::{Admin, Event, Recorder};
use owt_audit::{ActorKind, Event as AuditEvent};

/// The admin's changes, into the audit chain, in the change's transaction.
struct Audited;

impl Recorder for Audited {
    fn record<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let audit = AuditEvent::new(ActorKind::Account, event.actor.to_string(), event.name(), "account")
                .resource_id(event.account.to_string());
            owt_audit::record_in(conn, &audit).await?;
            Ok(())
        })
    }
}
# fn demo(pool: sqlx::PgPool, chrome: fn(owt_accounts::admin::Page<'_>) -> owt_web::Result<axum::response::Response>) {
let _admin = Admin::new(pool, "/staff/accounts", chrome).audit(Audited);
# }
```

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
layout as for the admin. The tables come from the `owt_accounts_policies` migration
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
    .connect_within(Duration::from_mins(15)); // how recent a sign-in a connect needs

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
use owt_accounts::mfa::{MfaSession, State};
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
    fn on_sign_in(&mut self) { self.signed.on_sign_in() }
}
// A provider's sign-in is recorded here as a recent sign-in (`Recent`), never as a
// second factor (`RecentMfa` takes the app's own TOTP or a recovery code).
impl MfaSession for MySession {
    fn mfa(&self) -> &State { &self.signed.mfa }
    fn mfa_mut(&mut self) -> &mut State { &mut self.signed.mfa }
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
  `PUBLIC_BASE_URL` beside them, listed in `env.env` for `env.sh`, which makes the
  Secret and patches a changed key, and restart to read them:

  ```sh
  # env.env: GOOGLE_CLIENT_ID=@env, GOOGLE_CLIENT_SECRET=@env, PUBLIC_BASE_URL=https://...
  read -rs GOOGLE_CLIENT_SECRET && export GOOGLE_CLIENT_SECRET   # not in argv or history
  deploy/openshift/env.sh --apply
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

### Field encryption

`owt-crypt` encrypts the columns that hold health or other sensitive data, so the
database, its backups and its replicas hold only ciphertext. Each tenant (a
*scope*) has its own AES-256 data keys, stored only wrapped by a key-encryption key
(KEK). A value is sealed with XChaCha20-Poly1305, and its associated data binds it to
its `Field`: scope, table, column and row. A ciphertext copied into another row, column
or tenant does not decrypt there.

**Ciphertext format.** `format (1 byte) || key version (u32, big-endian) || nonce ||
sealed bytes (plaintext + 16-byte tag)`. Format `0x02`, which every seal writes, is
XChaCha20-Poly1305 with a random 24-byte nonce; format `0x01` is AES-256-GCM with a
random 12-byte nonce, which `owt-crypt` only reads. The format byte is in the
associated data and picks the cipher, so a value relabelled as the other format does
not open. The same data keys serve both, so values sealed before format `0x02` keep
opening with no migration; `reencrypt` and `reencrypt_column` seal them again as
`0x02` (a value under the current key in format `0x01` counts as not yet moved). A
release that writes `0x02` must be on every replica before the first `0x02` value is
read: a build that knows only `0x01` refuses it as `CryptError::Malformed`.
`owt_crypt::format` has the parser (`Sealed::parse`, `Format`).

```rust,no_run
use std::sync::Arc;
use owt_crypt::kek::{KekProvider, LocalKek};
use owt_crypt::{Crypt, Field};

# async fn demo(pool: sqlx::PgPool, note_id: &str) -> anyhow::Result<()> {
owt_crypt::migrate(&pool).await?;

// Production: the YubiHSM (below). Everywhere else: a software keyring.
let kek: Arc<dyn KekProvider> = Arc::new(LocalKek::from_env("MYAPP_KEK")?);
let hardware = owt_runtime::env::flag("MYAPP_REQUIRE_HARDWARE_KEK", false)?;
let crypt = Crypt::new(pool.clone(), kek).require_hardware_kek(hardware)?;
if hardware {
    // No key may still be wrapped by a software KEK (a chain's old provider, say).
    crypt.check_keys_hardware().await?;
}

// The row id is the app's, made before the insert (a UUID), and never changes.
let field = Field::new("practice-3", "notes", "body", note_id);
let sealed: Vec<u8> = crypt.encrypt_str(&field, "Reports sleeping better.").await?;
sqlx::query("INSERT INTO notes (id, tenant, body) VALUES ($1, $2, $3)")
    .bind(note_id).bind("practice-3").bind(&sealed)
    .execute(&pool).await?;

// Decrypted values are zeroized when dropped.
let body = crypt.decrypt_string(&field, &sealed).await?;
# let _ = body; Ok(()) }
```

Store ciphertexts as `bytea`. A value's row reference must be known before the
insert and never change: an id the app makes (a UUID as text), not a sequence the
database assigns on insert.

**Length padding.** A ciphertext is its plaintext's length plus a fixed overhead, so
a short value tells itself apart from a long one (a three-character diagnosis code
from a five-character one). For a field where that matters, seal it padded: the
plaintext is padded to a multiple of a bucket (`Padding::DEFAULT`, 64 bytes, or
`Padding::new(n)`) inside the AEAD, ISO/IEC 7816-4 style (`0x80`, then zeros), as
format `0x03`. Every value whose length falls in one bucket has a ciphertext of one
length; a value on a boundary takes the next bucket. `decrypt` and `Sealer::open`
remove the padding, and the format byte (in the associated data) says it is there,
so a padded value relabelled as unpadded, or the reverse, does not open. Unpadded
seals are unchanged; `reencrypt` keeps a padded value padded, at the same length.
A build without format `0x03` refuses such a value as `CryptError::Malformed`: roll
the release out everywhere before sealing padded.

```rust,no_run
use owt_crypt::{Crypt, Field, Padding};
# async fn demo(crypt: Crypt, sealer: owt_crypt::Sealer) -> anyhow::Result<()> {
let field = Field::new("practice-3", "diagnoses", "code", "4b2e");
let sealed = crypt.encrypt_str_padded(&field, "F32.1", Padding::DEFAULT).await?;
let other = sealer.seal_str_padded(&field, "F33.40", Padding::DEFAULT)?;
assert_eq!(sealed.len(), other.len());
assert_eq!(&*crypt.decrypt_string(&field, &sealed).await?, "F32.1");
# Ok(()) }
```

**Equality search.** A blind index is HMAC-SHA256 of the value under the tenant's
index key (not its data key), stored beside the ciphertext and searched instead of
it. It shows which rows hold equal values, so index only what must be found by
exact match (an email, a record number), never free text, and normalize first:

```rust,no_run
# async fn demo(pool: sqlx::PgPool, crypt: owt_crypt::Crypt) -> anyhow::Result<()> {
let email = "Ann@Example.com".trim().to_lowercase();
let idx = crypt.blind_index("practice-3", "patients", "email", email.as_bytes()).await?;
let found: Option<String> = sqlx::query_scalar("SELECT id FROM patients WHERE tenant = $1 AND email_idx = $2")
    .bind("practice-3").bind(&idx[..])
    .fetch_optional(&pool).await?;
# let _ = found; Ok(()) }
```

**Rotation.** `crypt.rotate(scope, Purpose::Data)` adds a data key version: new
values use it, old ones still decrypt, and `reencrypt_column` moves a column onto it
in batches, beside live writes (each row is updated only if it still holds the value
read). Rotating the index key changes every index: search with
`blind_index_candidates` (`= ANY($1)`) until the column's indexes are recomputed. A
KEK rotation touches no data: put the new KEK first (a keyring entry, or a
`KekChain` of the new provider and the old) and run `rewrap`, which wraps every data
key under the new KEK, checking that each rewrapped key unwraps to the same bytes
before replacing the old; then retire the old one. Rotating to a new HSM wrap key is
a new object id, so a new KEK id: chain the two providers and rewrap.

```rust,no_run
use owt_crypt::{Column, Purpose, Scope};
# async fn demo(crypt: owt_crypt::Crypt) -> anyhow::Result<()> {
crypt.rotate("practice-3", Purpose::Data).await?;
let column = Column { table: "notes", id: "id", column: "body", scope: Scope::Column("tenant") };
let moved = crypt.reencrypt_column(&column, 500).await?;
let rewrapped = crypt.rewrap().await?; // after a KEK change
# let _ = (moved, rewrapped); Ok(()) }
```

```rust,no_run
use std::sync::Arc;
use owt_crypt::Crypt;
use owt_crypt::kek::{KekChain, KekProvider};
use owt_crypt::yubihsm::YubiHsmKek;

# async fn demo(pool: sqlx::PgPool, password: &str) -> anyhow::Result<()> {
// Rotating from wrap key 0x0064 to 0x0065: the new one wraps, the old one still unwraps.
let old: Arc<dyn KekProvider> = Arc::new(YubiHsmKek::http("127.0.0.1", 12345, 0x0002, password.as_bytes(), 0x0064)?);
let new: Arc<dyn KekProvider> = Arc::new(YubiHsmKek::http("127.0.0.1", 12345, 0x0002, password.as_bytes(), 0x0065)?);
let crypt = Crypt::new(pool, Arc::new(KekChain::new(new, vec![old])));
crypt.rewrap().await?;
// Nothing may stay under a software KEK in production: alarm on a non-empty list.
assert!(crypt.software_wrapped_keys().await?.is_empty());
# Ok(()) }
```

`reencrypt_column` returns a `Reencrypted` (non-exhaustive) with `moved`, `failed`,
`no_key` and `complete`. A row that does
not decrypt (malformed, an older key version shredded, refused) is listed in `failed`
by id and skipped, and the job stops after 10,000 failures or a pass that moves
nothing (a trigger or policy swallowing the update, or live writers winning every
race), so a bad row cannot wedge it. Rows whose scope has no data key cannot be
visited at all: they are counted in `no_key`, not listed. Those two stops, and any
`no_key`, return `complete: false`:
retire an old key version only after a run that is `complete` with nothing in
`failed`, never on `moved: 0` alone. A KEK id no provider knows aborts the job with an
error. A data key seals with random 192-bit nonces, so the number of seals per key
is not a limit (a repeated nonce is expected only after about 2^96 seals): rotate data
keys for a suspected leak or a policy, not for a nonce budget. Two concurrent `rotate`
calls may each add a version; that is harmless.

**Synchronous sealing.** `encrypt` and `decrypt` are `async`, because they may ask the
database or the KEK for a key. Code that cannot `.await` (serde and template paths,
`FromRow` decoding) uses a `Sealer`: `crypt.sealer(scope).await?` loads and unwraps the
scope's current data key, every older data key version and every index key version
once, and `seal`, `open`, `blind_index` and `blind_index_candidates` (for `= ANY($1)`
during an index rotation) are then plain functions. Load it once per request or
job and pass it down. Its ciphertexts and blind indexes are exactly `Crypt`'s, so the
two read each other's values, and a `Sealer` clones cheaply. It refuses a `Field` of
another scope with `CryptError::Invalid`.

```rust,no_run
use owt_crypt::{Crypt, CryptError, Field};

# async fn demo(crypt: Crypt, note_id: &str) -> anyhow::Result<()> {
let sealer = crypt.sealer("practice-3").await?;

// Synchronous from here on.
let field = Field::new("practice-3", "notes", "body", note_id);
let sealed: Vec<u8> = sealer.seal_str(&field, "Reports sleeping better.")?;
let body = sealer.open_string(&field, &sealed)?;
let idx = sealer.blind_index("patients", "email", b"ann@example.com")?;
# let _ = (body, idx);

// A long-lived sealer reloads when told it is stale.
let sealer = match sealer.seal(&field, b"x") {
    Err(CryptError::Stale(_)) => sealer.refresh(&crypt).await?,
    _ => sealer,
};
# let _ = sealer; Ok(()) }
```

A `Sealer` is a snapshot, so it has rules. After `rotate` or `shred` on the same
`Crypt` (or a clone) it is stale: `seal` and `blind_index` return `CryptError::Stale`,
so a new value never uses an old key (`blind_index_candidates` refuses too, as the
sealer may lack the new index version), while `open` still reads old ciphertexts. After
a shred it refuses everything with `CryptError::Shredded`. A rotation or shred on
*another replica* is invisible to this process, so every `Sealer` also has a maximum
age, `Crypt::sealer_max_age` (by default `cache_ttl`, five minutes, counted from
before the load starts): past it, every
method, `open` included, returns `Stale`, which bounds how long a replica misses a
rotation or keeps opening a shredded scope. `open` of a version made after loading
returns `CryptError::NotLoaded`. In each case `sealer.refresh(&crypt).await?` (or
`crypt.sealer(scope)`) loads a new one; `sealer.is_stale()` asks without trying.
Keys in a `Sealer` are zeroized when its last clone drops, and its `Debug` shows no
key.

**Shredding.** `crypt.shred(scope)` deletes a tenant's keys and records a tombstone
in `owt_crypt_shredded`, in one transaction, so everything encrypted for the tenant is
unreadable and the scope can never get keys again (the tombstone is permanent, so a
shredded scope id is never reusable: do not shred ids the app recycles) (`encrypt` and `rotate` fail with
`CryptError::Shredded`). Each `Crypt` caches unwrapped keys for `cache_ttl` (default
five minutes, `Crypt::new(..).cache_ttl(Duration::from_secs(60))`), so another
replica can still decrypt for up to that long after a shred, or notice a `rewrap`:
the TTL is the shred latency, and a shorter one asks the HSM more often. Shredding
does not reach WAL archives, replicas, logical-decoding slots or backups; they hold
the wrapped keys until they expire, so set their retention with that in mind.

**The software KEK** (`LocalKek`) is for development, CI and staging: a keyring of
`name:base64key` entries, the current first, from an environment variable
(`LocalKek::from_env`) or a mounted file (`from_file`). Make an entry with
`LocalKek::generate_entry("2026-10")`; to rotate, put a new entry first, deploy, run
`rewrap`, then drop the old entry. Anyone who can read the variable can read every
key it wraps, so production sets `require_hardware_kek(true)` and starts only with a
hardware KEK. `require_hardware_kek` checks the current KEK only: a `KekChain` from a
software KEK to an HSM passes it while rows are still software-wrapped. So production
runs `require_hardware_kek(true)` and then `crypt.check_keys_hardware().await?` at
start-up, which fails while any stored key is wrapped by a KEK that is not hardware
(`software_wrapped_keys()` lists those ids). Treat a non-empty list after `rewrap` as
an alarm.

**The YubiHSM KEK** (feature `yubihsm`). The KEK is an AES-256-CCM wrap key inside
a YubiHSM 2 on the node (the YubiHSM 2 FIPS model where FIPS 140-2 validation is required, which adds restrictions on algorithms and authentication keys); it never leaves the device. Data keys are sent to it
to be wrapped and unwrapped, and unwrapped keys are cached in memory (zeroized when
dropped) for `cache_ttl`, so the HSM is asked once per key per interval. The app reaches it through
`yubihsm-connector` on the node (HTTP, `127.0.0.1:12345` by default) or USB, with an
authentication key that has only the `wrap-data` and `unwrap-data` capabilities over
the wrap key's domain, never the factory default key. `YubiHsmKek` refuses, at start,
a wrap key that is not AES-256-CCM, lacks `wrap-data` or `unwrap-data`, or has
`export-wrapped` or `import-wrapped`, and wraps and unwraps 32 random bytes as a
self-test, so a wrongly provisioned authentication key fails at startup. It also
refuses an authentication key that holds `export-wrapped`, `import-wrapped`,
`put-wrap-key`, `generate-wrap-key` or `delete-wrap-key`. An unwrap is `Refused` only
when the device reports the message as invalid or unauthentic; connection, session
and every other device error are `Unavailable`. These checks are unit-tested against
`MockHsm` and a fake device; `tests/yubihsm.rs` runs them against real hardware when
`OWT_YUBIHSM_CONNECTOR` is set:

```rust,no_run
use std::sync::Arc;
use owt_crypt::kek::KekProvider;
use owt_crypt::yubihsm::YubiHsmKek;

# fn demo() -> anyhow::Result<()> {
let password = owt_runtime::env::required("MYAPP_HSM_PASSWORD")?;
// Authentication key 0x0002, wrap key 0x0064; checks the wrap key at startup.
let kek: Arc<dyn KekProvider> = Arc::new(YubiHsmKek::http("127.0.0.1", 12345, 0x0002, password.as_bytes(), 0x0064)?);
# let _ = kek; Ok(()) }
```

Provision once, with Yubico's `yubihsm-shell`, on an offline machine: an AES-256-CCM
wrap key (`aes256-ccm-wrap`) with the capabilities `wrap-data`, `unwrap-data` and
`exportable-under-wrap` (for the backup, below), and an authentication key for the
app with `wrap-data` and `unwrap-data` only, and without `export-wrapped`. Change or
delete the factory authentication key. `exportable-under-wrap` stays on the KEK only
while a backup copy is being made.

**Backup and disaster recovery.** The wrap key exists only inside HSMs, so losing the
HSM without a second copy loses every key it wraps, and so all encrypted data.
Before production holds any, keep a second YubiHSM 2, offline and in a safe away
from the node, holding the same wrap key under the same object id (so the KEK id,
`yubihsm:0x0064`, matches):

0. Create the app's authentication key on the backup HSM as well, with the same id
   and password (and capabilities and domains): authentication keys are not exported,
   and without it the backup cannot be used.
1. Put the same *transport* wrap key on both devices (`yubihsm-shell`, `put wrapkey`):
   key material generated on the offline machine, imported into each HSM as a wrap key
   with `export-wrapped` and `import-wrapped`, and with *delegated* capabilities that
   include `exportable-under-wrap`, `wrap-data` and `unwrap-data` (the ceiling on what
   it may carry; without `exportable-under-wrap` the KEK cannot be exported again on
   the next rotation). The transport key itself needs no `wrap-data` or `unwrap-data`.
   Then destroy the material, or keep it as split custody: key shares held by
   different officers.
2. Export the KEK from the primary under the transport key (`get wrapped`) and
   import it on the backup (`put wrapped`). The KEK leaves an HSM only encrypted.
3. Test the backup: plug it into a staging node, point a staging app at a copy of
   production's `owt_crypt_keys`, and decrypt a known value. Repeat after every KEK
   rotation, which needs the same export to the backup.

To recover, move the backup HSM to the replacement node, start its connector, and
start the app; nothing in the database changes.

### Object storage

`owt-storage` keeps files (recordings, documents, images) in an S3-compatible bucket:
one inside the cluster (MinIO, or OpenShift Data Foundation's object gateway, through
`Storage::s3_in_cluster`), Cloudflare R2, Backblaze B2, or MinIO in development. Objects that hold health data
are **encrypted in the app** before they leave it, under a fresh content key per
object that `owt-crypt` seals for the tenant and the object's key. The bucket, its
replicas and anyone holding its credentials see only ciphertext.

```rust,no_run
use std::time::Duration;
use owt_storage::{S3Config, Storage};

# async fn demo<R: tokio::io::AsyncRead + Unpin + Send>(crypt: owt_crypt::Crypt, upload: R) -> anyhow::Result<()> {
let storage = Storage::s3(&S3Config {
    endpoint: owt_runtime::env::required("MYAPP_S3_ENDPOINT")?, // https://s3.us-west-004.backblazeb2.com
    bucket: owt_runtime::env::required("MYAPP_S3_BUCKET")?,
    region: owt_runtime::env::required("MYAPP_S3_REGION")?,
    access_key_id: owt_runtime::env::required("MYAPP_S3_KEY_ID")?,
    secret_access_key: owt_runtime::env::required("MYAPP_S3_SECRET")?,
})?
.encrypted(crypt);

// A recording of any length, from the request body: encrypted 1 MiB at a time into
// a multipart upload before anything reaches the bucket.
let bytes = storage.upload_sealed("practice-3", "recordings/7f3a.webm", upload).await?;

// Read it back (it refuses an object altered, truncated, or copied to another key).
let audio = storage.get_sealed("practice-3", "recordings/7f3a.webm").await?;

// Gone, and checked gone.
storage.delete_verified("recordings/7f3a.webm").await?;

// Non-sensitive files: a short-lived URL the browser reads directly.
let url = storage.presign_get("public/logo.png", Duration::from_mins(10)).await?;
# let _ = (bytes, audio, url); Ok(()) }
```

- **Encrypted format.** A header (magic, format, chunk size, the sealed content key,
  a nonce prefix), then 1 MiB chunks, each AES-256-GCM sealed with the header as
  associated data and a nonce of the prefix, the chunk's index and a last-chunk flag
  (the STREAM construction). Any edited byte, a chunk dropped from the end, swapped
  chunks, or the object copied under another key or tenant fails to open.
  `download_sealed` streams into a writer and writes each chunk only once it
  authenticates; on an error, discard what it wrote. A reader rejects any chunk size
  but the writer's.
- **Rotating data keys.** The sealed content key is in the header, and the header is
  every chunk's associated data, so an object cannot move to a newer `owt-crypt`
  data-key version without being rewritten. `storage.reencrypt(scope, key)` does that:
  it streams the object through `download_sealed` into `upload_sealed` at the same key
  (the object's key is part of what the content key is bound to, so a copy from a
  temporary key would not open), replacing it only after the last chunk verified. Run
  it per object after `rotate` and `reencrypt_column`, before retiring an old version.
  Readers see the old version until the replacement lands. Hold an app-level lock on
  the key (no concurrent writer) while it runs: it checks the object's size and etag
  before and just before completing and fails with `StorageError::Conflict` on a
  change, but a store's multipart completion has no `If-Match`, so only the lock closes
  the race. The plaintext passes through a 1 MiB in-process pipe that is not zeroized
  when freed.
- **Size limit.** Uploads use 5 MiB parts and a multipart upload has at most 10,000, so
  an object is limited to about 48 GiB; a larger limit needs a larger part size.
- **Health data streams through the app.** Upload it with `upload_sealed` straight
  from the request body, so it is encrypted before it touches storage, and serve it
  with `download_sealed` into the response. Presigned URLs are for data that may sit
  in the bucket as it is.
- **Presigned URLs** live at most `MAX_PRESIGN` (an hour) and move bytes between the
  browser and the bucket without passing through the app, so the app cannot encrypt
  them. **Not for health data:** the pattern below leaves plaintext in the bucket
  until it is sealed. For other large uploads, the browser `PUT`s to a presigned URL
  under an `incoming/` prefix and the app then calls
  `seal_uploaded(scope, "incoming/…", "files/…")`, which encrypts it into its final key
  and deletes the upload, verified. Give
  `incoming/` a lifecycle rule that expires objects after a day, so an upload never
  sealed does not linger. A presigned URL is only as reachable as the endpoint it
  signs: for an in-cluster bucket, sign against the endpoint browsers reach (a Route
  to the gateway), not the Service name. A presigned URL limits neither size nor content type, and
  stays valid until its TTL ends even after the object is sealed and deleted, so
  whoever holds it can upload plaintext again: keep upload TTLs to minutes, use an
  unguessable key per upload, and seal after the URL has expired. A zero TTL is
  refused.
- **Use an unversioned bucket for anything `delete_verified` must remove.** Verified
  deletion deletes, then requires a `HEAD` of 404. On an unversioned bucket (the
  default for MinIO, ODF and R2) that 404 means the bytes are gone. On a versioned
  bucket a delete only *hides* the object: its bytes stay recoverable with the
  bucket's credentials, the 404 proves nothing, and no S3-API call `owt-storage`
  makes can delete a specific version. So keep media and presigned uploads in a bucket
  with versioning and Object Lock off, and check that setting when the bucket is
  made.
- **Backups on Backblaze B2.** B2 buckets are versioned by default. When a backup
  of the bucket (or of anything holding ciphertext) goes to B2, give that bucket the
  lifecycle rule "keep only the last version" (`daysFromHidingToDeleting: 1`), and
  count deletions as complete only after the backup's own retention ends: B2 applies
  lifecycle rules about once a day, so a hidden object stays recoverable for at least
  a day and up to about two.
- **Interrupted uploads.** A failed `upload_sealed` aborts its multipart upload, but a
  dropped future (a client disconnect, a timeout) leaves an incomplete one that is
  billed and invisible to listing. Give the bucket the lifecycle rule "abort incomplete
  multipart uploads after 1 day".
- **Configuration.** The endpoint is `https`; plain `http` is accepted only for the IP
  literals `127.0.0.1` and `[::1]`, not the name `localhost`; an in-cluster Service over
  plain `http` uses `Storage::s3_in_cluster`. `S3Config`'s `Debug`
  redacts the secret.
- **Verified deletion** deletes, then requires the store to answer that the object is
  gone, which proves deletion on an unversioned bucket only (above).
- `Storage::from_store` takes any `object_store` store: `InMemory` in tests, a
  directory in development (neither presigns).

### Audit log

`owt-audit` records who did what to which record, why, and how it went, in an
append-only table where any later change shows. Each event joins its tenant's chain
(events with no tenant share the chain `""`): its `seq` follows the chain's last,
its `prev` is that event's hash, and its `hash` is SHA-256 over a canonical encoding
of all its fields (`owt_audit::canonical`). The database assigns all four as the row
is inserted, whoever inserts it, and `record_in` checks the database's hash against
the crate's. Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` while they stand; only
the tables' owner can drop or disable them, which anchoring (below) exposes. A role
that may insert can still record false events, as it can make false changes; the log
shows what was recorded, and that nothing recorded was altered since.

```rust,no_run
use owt_audit::{ActorKind, Audit, Event, Outcome};

# async fn demo(pool: sqlx::PgPool, ip: std::net::IpAddr) -> anyhow::Result<()> {
owt_audit::migrate(&pool).await?; // as the migration role, at start
let audit = Audit::new(pool.clone());

// A clinician opens a chart: references and codes only.
audit
    .record(
        &Event::new(ActorKind::Account, "17", "record.view", "chart")
            .tenant("practice-3")
            .subject("patient:4821")
            .resource_id("4821")
            .purpose("treatment")
            .client(Some(ip), Some("Mozilla/5.0 …"), Some("req-7f3a")),
    )
    .await?;

// With the change it records: both commit, or neither.
let mut tx = pool.begin().await?;
// ... sign the note in `tx` ...
let signed = Event::new(ActorKind::Account, "17", "note.sign", "note")
    .tenant("practice-3")
    .subject("patient:4821")
    .resource_id("note:991");
owt_audit::record_in(&mut tx, &signed).await?;
tx.commit().await?;

// Refusals are events too.
let denied = Event::new(ActorKind::Account, "23", "record.view", "chart")
    .tenant("practice-3")
    .subject("patient:4821")
    .outcome(Outcome::Denied);
audit.record(&denied).await?;
# Ok(()) }
```

**What goes in an event.** Ids, never content: an account id, the patient's record
id, a resource's id, and codes (`[a-z0-9_.:-]`, up to 100) for the action, the
resource type and the purpose of use. Never a name, a diagnosis, a note's text or a
search term; the log is kept for years and erases nothing. The fields are short (200
characters, a user agent 512) and `Event::check` refuses control characters and
malformed codes; the table's own constraints refuse control characters and malformed
addresses too. `record_in` holds its tenant's chain until the transaction ends, so
call it last in the transaction, and the transaction must be READ COMMITTED (the
default; the database refuses others, whose snapshot could miss the chain's last
event).

**Locks and refusals.** The chain lock is per tenant and lasts until commit, so:

- Record for one tenant per transaction. Two transactions that record for tenants
  `a` and `b` in opposite orders deadlock; Postgres aborts one of them
  (`40P01`). If one transaction must record for several tenants, record them in a
  fixed order (sorted by tenant).
- Never call `audit.record` for a tenant while your own open transaction has already
  run `record_in` for that tenant. `record` takes another pool connection, which
  waits for your transaction's lock while your task waits for `record`. Postgres
  cannot see that wait, so it lasts until a statement timeout ends it, or forever
  without one.
- Record refusals and failures (`Outcome::Denied`, a failed attempt) with
  `audit.record`, in a transaction of their own, as in the example above. An event
  recorded with `record_in` rolls back with its transaction, and the transaction of
  a refused or failed request is usually the one that rolls back.

**Roles.** Run the migrations as the role that owns the schema. Give the app's role
`INSERT` and `SELECT` on the events and `SELECT` on the anchors; it then cannot drop
or disable the triggers, which takes ownership. Only the role that runs the anchoring
job inserts anchors, so the app cannot record a manifest of its own. The OpenShift
template does this for the app's role (`owt_audit::grant_runtime`, from its
`migrate` init container; see "Database roles"); by hand it is:

```sql
GRANT USAGE ON SCHEMA public TO myapp_app, myapp_anchor;
GRANT SELECT, INSERT ON owt_audit_events TO myapp_app;
GRANT SELECT ON owt_audit_anchors TO myapp_app;
GRANT SELECT ON owt_audit_events TO myapp_anchor;
GRANT SELECT, INSERT ON owt_audit_anchors TO myapp_anchor;
-- Nothing else: no UPDATE, DELETE, TRUNCATE, TRIGGER or ownership.
```

`owt_audit::privileges(&pool)` reports what the role a pool connects as may do to
the audit tables: whether it owns them (or is a member of their owner), is a
superuser, or holds `UPDATE`, `DELETE`, `TRUNCATE` or `TRIGGER` on them. Check it at
startup, on the pool that serves requests. `templates/openshift/app.yaml`
runs migrations as the database's owner and serves as a runtime role that
`owt_audit::grant_runtime` grants as above, so a deployment from it passes this
check.

```rust,no_run
# async fn demo(pool: sqlx::PgPool) -> anyhow::Result<()> {
let p = owt_audit::privileges(&pool).await?;
if !p.least() {
    // Refuse instead where the log must hold: `anyhow::bail!("{p}")`.
    tracing::warn!(%p, "the audit log is not append-only for this role");
}
# Ok(()) }
```

**Anchoring.** The schema's owner can still drop the triggers and rewrite a chain
from some event on, recomputing every hash after it; the chain still verifies on its
own. So, on a schedule, write every chain's head to storage the database's owner
cannot change: `anchor::anchor(&pool, &store)` verifies each chain since the previous
manifest (so a broken chain is never anchored), builds a manifest of the heads
(naming the previous manifest's digest), stores it through an `anchor::Anchor`, and
records it in `owt_audit_anchors`; runs are serialized by an advisory lock. `verify_anchor` then fails for any chain that no longer
holds an anchored head. `NoAnchor` records manifests in the database only, for
development and tests; production uses `S3ObjectLock` (feature `s3`, below),
or implements `Anchor` over another write-once store. The database's copy of a manifest is checked against its recorded
digest, but it is only as trustworthy as the roles that may insert anchors; an
independent check verifies against the copy in the store
(`myapp audit verify --manifest m.json`).

```rust,no_run
use std::time::Duration;
use owt_audit::anchor::{self, NoAnchor};
use owt_runtime::jobs::{CancellationToken, Every, Jobs};

# async fn demo(pool: sqlx::PgPool) {
let jobs = Jobs::new(CancellationToken::new());
let p = pool.clone();
jobs.singleton("audit_anchor", Every::new(Duration::from_hours(1)), pool.clone(), 7_210_010, move || {
    let p = p.clone();
    async move {
        anchor::anchor(&p, &NoAnchor).await?; // the app's WORM store in production
        Ok(())
    }
});
# }
```

**Anchoring to S3 Object Lock.** With feature `s3`, `anchor::S3ObjectLock` PUTs each
manifest to a bucket with `x-amz-object-lock-mode: COMPLIANCE` and a
`retain-until-date` of now plus the retention you configure (one day to 100 years;
seven years covers HIPAA's six, with a margin), a `Content-MD5` and
`If-None-Match: *`. Until the date passes, nothing can overwrite or delete the
object, the bucket owner included. The requests are signed in the crate (AWS
Signature V4, path-style).

`put` does not trust the PUT's success. A missing `x-amz-version-id` is an error
(Object Lock implies versioning, so a store that returns none is not locking), and
it then reads the stored version's retention back and fails unless the mode is
COMPLIANCE and the retain-until date is no earlier than the one requested. The
first `put` also runs `verify_bucket()`, which fails unless the bucket reports
Object Lock enabled; it tells a bucket without Object Lock (404) from a refused
credential or a server error, and names the S3 error code. The receipt is the
version id.

The retain-until date follows this host's clock, so a clock set back shortens the
lock: every response's `Date` header is compared with the local clock, a response
without a valid one is refused, and a difference over five minutes fails the
request. On a `put` that error can arrive after the object is locked, to a date that
follows the wrong clock; write a new key once the clock is fixed. Keep the host on
NTP.

The readback proves the store reports the lock, not that it enforces it: the
retention document is parsed structurally (a `Retention` root with `Mode` and
`RetainUntilDate` children), so a store that returns the object or any other body
fails, but a store that fabricates a well-formed one cannot be detected from the
client. Use a store you trust to honor Object Lock.

Tested against MinIO only (`bitnamilegacy/minio`, a bucket made with
`mc mb --with-lock`). Backblaze B2 and AWS S3 follow the same API and the signer is
checked against AWS's published examples, but neither was exercised.

Set the bucket up once:

1. Create it with Object Lock enabled (it enables versioning). AWS can also enable
   Object Lock on an existing versioned bucket; B2: "Object Lock" at creation;
   MinIO: `mc mb --with-lock <alias>/<bucket>`.
2. Give the anchoring job a credential of its own, restricted to this bucket and to
   `s3:PutObject`, `s3:PutObjectRetention` (a PUT carrying lock headers needs it; it
   can only extend a COMPLIANCE retention, never shorten it), `s3:GetObject`,
   `s3:GetObjectVersion`, `s3:GetObjectRetention` and
   `s3:GetBucketObjectLockConfiguration`. Grant no `s3:DeleteObject`,
   `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention` or
   `s3:PutBucketObjectLockConfiguration`. On B2 the application key's capabilities
   are `writeFiles`, `readFiles`, `writeFileRetentions`, `readFileRetentions` and
   `readBucketRetentions`, and not `deleteFiles`. Keep it out of the app's
   environment and the database host's reach.
3. Use `https://`. A plain `http://` endpoint is refused unless its host is a
   loopback IP literal or `allow_insecure_http` is set, which is for a MinIO on the
   cluster's own network only. Redirects are not followed; a 3xx is an error that
   usually means the wrong region or endpoint. The endpoint is an origin: no path,
   userinfo or query.

`If-None-Match: *` keeps a second `put` of a key from replacing the first, where the
store honors it: AWS and MinIO do, B2's S3 API does not document it. Do not rely on
it; the version check above and `fetch` by version id are the guarantee. A `put`
retried after a lost response gets a 412 (the key exists) although the object is
anchored; `anchor` mints a new key on each run, so only a caller that retries `put`
itself sees this. Keys must be non-empty, not start with `/`, and have no empty, `.`
or `..` segment.

`fetch(key, version_id)` reads a manifest back (at most 16 MiB), to save as the file
`audit verify --manifest` takes. Pass the receipt: without a version id the latest
version is read, which a credential that can write the key again could have replaced.
With a version id, `fetch` fails unless the response is a 200 whose
`x-amz-version-id` equals it and the version's retention reads back as COMPLIANCE
with a valid retain-until date, checked before the body is read, so only a version
that was locked is trusted. An expired date is accepted: a version id names immutable
content and a COMPLIANCE date cannot be shortened. Once it passes, though, nothing
prevents deleting the version, so set the retention beyond your audit horizon.

Requests go straight to the endpoint: the HTTP client ignores `HTTPS_PROXY`,
`HTTP_PROXY` and `ALL_PROXY`, so the environment cannot route signed requests
through a third party. Reaching a store through a proxy is not supported.

```rust,no_run
use std::time::Duration;
use owt_audit::anchor::{self, S3Config, S3ObjectLock};

# async fn demo(pool: sqlx::PgPool) -> anyhow::Result<()> {
let store = S3ObjectLock::new(S3Config {
    endpoint: "https://s3.us-west-004.backblazeb2.com".into(),
    bucket: "myapp-audit-anchors".into(),
    region: "us-west-004".into(),
    access_key: owt_runtime::env::required("MYAPP_ANCHOR_KEY_ID")?,
    secret_key: owt_runtime::env::required("MYAPP_ANCHOR_KEY")?.into(),
    allow_insecure_http: false,
    retention: Duration::from_hours(7 * 365 * 24),
})?;
store.verify_bucket().await?;

let anchored = anchor::anchor(&pool, &store).await?;
// Later, for `myapp audit verify --manifest m.json`:
let key = anchored.manifest.key();
std::fs::write("m.json", store.fetch(&key, Some(&anchored.receipt)).await?)?;
# Ok(()) }
```

**Verifying.** `owt_audit::verify(&pool, tenant)` walks a chain and names the first
event that was edited (`Broken::Hash`), removed (`Broken::Gap`) or swapped
(`Broken::Link`); `verify_anchor(&pool, &manifest)` checks a manifest's heads.
`anchor::history(&pool)` reads every manifest the database records and fails, rather
than skipping, on one that does not match its digest or does not name the one before
it; `anchor::age(&pool)` is how old the latest is, for an alert when anchoring stops
(a store credential rotated, a job not running). With the `cli` feature the app gets
these as operator commands: `myapp audit verify` checks every chain, that the
database's anchors chain, and the latest one's heads; `myapp audit verify --manifest
m.json`, for a manifest fetched from the store, also fails unless the database
records it; `--max-age 2h` fails when the latest anchor is older (schedule it a
margin above the anchoring interval); and `myapp audit heads`:

```rust,no_run
use clap::{Parser, Subcommand};
use owt_audit::cli::AuditCommand;

#[derive(Parser)]
struct Cli { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    /// The audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

# async fn demo(pool: sqlx::PgPool) -> anyhow::Result<()> {
match Cli::parse().command {
    Command::Audit(cmd) => owt_audit::cli::run(&pool, cmd).await?,
}
# Ok(()) }
```

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
    // What a subscriber gets when broadcasts may have been lost: after a resubscribe,
    // and after its own full queue dropped messages, once it has room again.
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

A subscriber that falls behind loses messages rather than stalling the publisher.
The first loss marks it lagged (`Subscription::is_lagged`) and logs one warning, not
one per message; the drop counter counts each. It gets `resync()` once it has room:
from `recv` when it has read what was queued, or ahead of its next message when the
loop reads `rx` directly. So a slow tab replays its state instead of staying stale.

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
  a check that itself takes longer than `LOCK_CHECK` aborts the run too. By default
  the lock's connection comes from the app's pool and is held for the whole run, so a
  task that also uses the pool needs a pool of two. `singleton_with` takes
  `PgConnectOptions` instead and holds the lock on a dedicated connection outside the
  pool, kept between ticks (one idle server connection per replica): an hour-long
  singleton then holds no pool slot. If that connection drops, the run is stopped as
  above and the next tick reconnects and contends for the lock again.
- `leased` (feature `redis`): one replica, the same one while it lives, by a Redis
  lease renewed while held; on shutdown it is released, so another replica takes over
  at once.

Choosing: `singleton` for periodic work that one replica at a time does and that
needs only Postgres; `leased` when the work wants a sticky owner and a fast handover
at shutdown, or the app sits behind a transaction-mode pooler; the durable queue
("Durable job queue", below) for work items that must each run, survive a crash and
retry, rather than a tick that may be skipped.

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

// A long singleton on a connection of its own, outside the app's pool.
let opts = pool.connect_options().as_ref().clone();
jobs.singleton_with("rebuild", Every::new(Duration::from_hours(1)), opts, 7_210_003, || async { Ok(()) });

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
const HOUR: Duration = Duration::from_hours(1);
const DAY: Duration = Duration::from_hours(24);
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

### Durable job queue

`jobs` runs periodic work; `owt_runtime::queue` runs work items that must survive
crashes and deploys (a message to send, a file to process). Delivery is **at least
once**: a crash, a stale recovery, a heartbeat lost to a database blip or a put-back at
shutdown runs a job again, perhaps after the first run had its side effects. Handlers
must be idempotent; the enqueue key deduplicates enqueues, not executions.
Each job is a row of `owt_jobs`, a table the library migrates into its own ledger
(`_owt_runtime_migrations`): await `queue::migrate(&pool)` at start, before the first
enqueue.

- **Enqueue** with `Queue::enqueue`, or `enqueue_in(&mut tx, ..)` inside the app's
  own transaction, so the job exists exactly when the change that wants it commits.
  `Job::key` is an idempotency key: enqueueing the same key again returns the first
  job (`Enqueued { fresh: false, .. }`) for as long as its row lasts, a dead job's
  included: nothing new is queued until the dead job is discarded or redriven.
  `Job::delay` and `Job::run_at` schedule it. A keyed `enqueue_in` needs a
  `READ COMMITTED` transaction (the default); under `REPEATABLE READ` or
  `SERIALIZABLE` it returns an error saying so.
- **Claims** take due jobs oldest first with `FOR UPDATE SKIP LOCKED`, so replicas
  never take the same job or wait on each other. Each claim counts an attempt and
  takes the next number of the job's claim counter, which only rises. That number
  fences the claim (`Claimed::claim`): a claim that went stale and was given to
  another worker can no longer complete, fail, release or heartbeat the job. Fencing
  stops a stale worker from recording a result, not from running, hence the
  idempotence above; a `lost` outcome means the side effect may have happened twice.
- **Retries** back off exponentially with jitter (`Retry`, default 5 attempts from
  about 10 s, capped at an hour). After the last attempt, or when the handler returns
  `JobError::permanent(..)`, the job is **dead**: kept with its payload and last error
  for `Queue::dead`, `Queue::redrive` (queued again with fresh attempts) or
  `Queue::discard_dead`.
- **The worker** polls: it claims while it has free slots (`concurrency`) and, after
  a claim that finds nothing due, waits `Worker::poll` (default 5 s) before claiming
  again. A job that becomes due, a freshly enqueued one included, may therefore wait
  up to that interval before it starts; a queue that needs a quicker start sets
  `.poll(Duration::from_millis(500))` or so, at one claim query per interval per
  replica. There is no `LISTEN/NOTIFY` (see "Decisions"). The worker runs each job in its
  own task (a panic is a failed attempt), renews running jobs' heartbeats every third
  of `stale_after` (aborting a handler whose claim the heartbeat finds taken over, so
  a lost claim does not run on beside its replacement), and puts back jobs whose heartbeat went stale on any replica (a
  replica that died). Heartbeats and housekeeping run in tasks of their own, so a slow
  claim or purge never delays a heartbeat. Done jobs are purged after `retain_done`
  (7 days) in batches, which frees their keys. On shutdown it claims nothing more,
  gives running jobs `shutdown_grace` to finish, then aborts the rest and queues them
  again. The aborted attempt stays counted, so a handler that never returns reaches
  `max_attempts` and the job goes dead.

```rust,no_run
use std::time::Duration;
use owt_runtime::jobs::{CancellationToken, Jobs};
use owt_runtime::queue::{self, Claimed, Job, JobError, Queue, QueueMetrics, Retry};

#[derive(serde::Serialize, serde::Deserialize)]
struct SendReminder { appointment: i64 }

async fn send_reminder(job: Claimed) -> Result<(), JobError> {
    // A payload that never parses will not parse next time either.
    let r: SendReminder = job.json().map_err(JobError::permanent)?;
    let _ = r.appointment; // look the appointment up, send, ... (`?` retries)
    Ok(())
}

# async fn demo(pool: sqlx::PgPool) -> anyhow::Result<()> {
queue::migrate(&pool).await?;
let reminders = Queue::new(pool.clone(), "reminders")?.retry(Retry {
    max_attempts: 8,
    base: Duration::from_secs(30),
    cap: Duration::from_hours(2),
});

// In the transaction that books the appointment: one job per appointment.
let mut tx = pool.begin().await?;
let job = Job::json(&SendReminder { appointment: 42 })?
    .key("reminder:42")
    .delay(Duration::from_hours(23));
reminders.enqueue_in(&mut tx, job).await?;
tx.commit().await?;

let shutdown = CancellationToken::new();
let jobs = Jobs::new(shutdown.clone());
reminders
    .worker(send_reminder)
    .concurrency(8)
    .metrics(QueueMetrics::prefixed("myapp"))
    .spawn(&jobs);

owt_runtime::serve::shutdown_signal().await;
shutdown.cancel();
jobs.stopped().await; // running jobs finish, or go back to the queue
# Ok(()) }
```

**Payloads are not encrypted.** The table, its backups and its replicas hold them as
they are. A payload carries references (an id the handler looks up), not personal or
health data; one that must carry such data is encrypted by the app before it is
enqueued. A done job's payload is emptied at once; a dead job's is kept for
redriving, so discard dead jobs the app will not redrive. The last error is stored
(cut to `queue::MAX_ERROR_CHARS`) and logged, so a handler keeps personal data out of
its error messages too.

`QueueMetrics::prefixed("myapp")` records `<prefix>_queue_jobs_total{queue,outcome}`
(`done`, `retried`, `dead` (a released job on its last attempt included), `lost`,
`released`, `recovered`),
`<prefix>_queue_job_seconds{queue}`, and, at each housekeeping pass,
`<prefix>_queue_depth{queue,state}` and `<prefix>_queue_lag_seconds{queue}` (how long
the oldest due job has waited); call its `describe()` inside the closure passed to
`owt_runtime::metrics::install`. Alert on lag and on dead jobs.

A worker without `Jobs` is `worker.run(shutdown).await`; `Queue::claim`,
`complete`, `fail` and `heartbeat` are there for an app that drives jobs itself.

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
let page = browser.get_page("/").await; // a page load: Sec-Fetch-Dest: document
assert_eq!(page.status, 200);

// A page and its fragment render one region alike.
fragment::assert_same_element(&page.text(), "<main id=\"m\"> <p>Hi</p></main>", "#m");

// Golden pages: compared modulo layout, with what changes per run masked.
// `UPDATE_GOLDEN=1 cargo test` rewrites the snapshots; review the diff.
// `asset_versions` drops the `?v=…` fingerprint from URLs under `/static/` (and only
// those: a page link like `/watch?v=abc` keeps it), so a snapshot recorded with the
// stylesheet built matches a test job that builds no CSS. Assets under another prefix:
// `asset_versions_under("/assets")`.
let normalize = Normalizer::new().uuids("<uuid>").asset_versions();
# if false { // no snapshots beside the README
let mut golden = Golden::new("tests/golden/pages");
golden.take("home", normalize.normalize(&page.text()));
golden.check(); // a Golden dropped unchecked fails the test
# }
# }
```

`Client::get_page` loads a page as a browser does (`Sec-Fetch-Dest: document`,
`Sec-Fetch-Mode: navigate`, `Accept: text/html`), which is what the accounts' policy
gate interrupts: test a gate, or anything else that tells page loads from fetches,
with it. `Client::get` sends no fetch metadata, as a non-browser client.

A `Client`'s requests come from a fixed peer, `owt_test::PEER` (`192.0.2.1:40000`),
as axum's `MockConnectInfo` gives it, so a handler taking `ConnectInfo<SocketAddr>` or
`ClientIp` (and code reading `owt_web::client_ip::peer`) answers in-process without a
peer extension of the app's own; code that reads `Extension<ConnectInfo<SocketAddr>>`
or the `ConnectInfo` extension directly sees none;
`Client::with_peer(Some(addr))` picks another, `with_peer(None)` none. A
`MockConnectInfo` or `Extension(ConnectInfo(..))` layer on the router still decides,
so an app that adds one keeps its address.

**Accounts in tests.** Seal the session directly instead of signing in through the form,
which costs an Argon2 round per test, and keep the helper out of the production crate:
`owt-test` is a `[dev-dependencies]` entry and nothing else, because
`Client::sign_in_as` seals a session for any account. `owt_test::accounts::test_key()`
is a fixed, public session key for the test's `Sessions`; `accounts::create` (and
`create_staff`, `create_with_password`, the one that hashes) makes an account;
`Client::sign_in_as(&sessions, &account)` sets the cookie `owt_accounts::session::sign_in`
would, for any session type that implements `owt_accounts::session::Signed`;
`accounts::agree_to_current` records the account's agreement to the current version of
every published policy, so the gate lets it through; and `Client::sign_in_new` does all
three for a fresh account.

```rust,no_run
use std::time::Duration;
use axum::Router;
use owt_accounts::session::Data;
use owt_test::{Client, accounts};
use owt_web::session::Sessions;

# async fn run(app: impl FnOnce(&Sessions<Data>) -> Router, pool: sqlx::PgPool) {
let sessions = Sessions::<Data>::new(accounts::test_key(), "s", Duration::from_hours(1), false);
let client = Client::new(app(&sessions));
let ada = client.sign_in_new(&pool, &sessions, "ada").await; // signed in, policies agreed
assert_eq!(client.get_page("/me").await.status, 200);
# let _ = ada;
# }
```

`just dev-only` (part of `just check`) fails if a crate of the workspace depends on
`owt-test`, or turns on `owt-accounts`' `test-util`, outside `[dev-dependencies]`; an app
can run `cargo tree --edges normal,build -i owt-test` and `cargo tree --edges
normal,build -e features -i owt-accounts` (looking for `feature "test-util"`) on its own
workspace.

**A schema per test.** `#[sqlx::test]` names its database from a hash of the test's
module path alone and creates it on the server `DATABASE_URL` names, so the same test
run from two worktrees, or from two apps with tests at one path, asks the shared server
for the same name twice: one run drops the other's database, or fails with "database
`_sqlx_test_…` already exists". A per-worktree `DATABASE_URL` does not help, because
database names are server-wide, and sqlx offers no way to rename them. Tests that
share a server use `owt_test::schema::TestSchema` instead, in a plain `#[tokio::test]`
(it replaces `#[sqlx::test(migrations = false)]`): it creates
`owt_test_<checkout>_<pid>_<nonce>_<sequence>` (eight hex digits of a hash of the host
name and the `CARGO_MANIFEST_DIR` you pass, the process id, eight random hex digits
drawn once per process, and a counter; under 63 bytes; the nonce keeps apart processes
with one pid in containers that share a host name and path)
in the database `DATABASE_URL` names, and gives its pool `search_path = <schema>,
public`. It needs `CREATE` on the database, not `CREATEDB`, and avoids the checkpoint
each `DROP DATABASE` forces. It returns `None` when `DATABASE_URL` is unset, so the
test skips. Queries that name `public.` bypass the `search_path`; leave the schema out
of the app's SQL.

The test ends with `db.close().await`, which closes the pool and drops the schema with
its contents. Dropping the value does the same as a fallback, from a thread of its own.
Both first end the pool's server sessions (they carry the schema's name as
`application_name`), so a transaction dropped open or a pool clone still held in app
state cannot keep `DROP SCHEMA` waiting, and both give up after 30 seconds in all. A run that
is killed or aborted leaves its schema behind; the next `create` in the same checkout
drops it, along with any schema of that checkout whose process is no longer running
on this host (Linux only, as the check reads `/proc`).

`CREATE EXTENSION` installs into the first schema on the `search_path`, which is the
test's. A migration that creates an extension names the schema
(`CREATE EXTENSION IF NOT EXISTS citext SCHEMA public`), or the extension is installed
in `public` beforehand; otherwise the first test's schema holds it, concurrent schemas
fail with `type "citext" does not exist`, and dropping that schema removes it. Each
schema runs its migrations in full, and the advisory locks behind them
(`owt_accounts::migrations::LOCK_ID`, the app's `migrate_locked` id) are database-wide,
so the migrations of every test, worktree and app sharing the database queue behind
one another: correct, and slower under parallel load.

```rust,no_run
use owt_test::schema::TestSchema;

# static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator::DEFAULT;
// static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!(); // the app's migrations/
# async fn run() {
let Some(db) = TestSchema::create(env!("CARGO_MANIFEST_DIR")).await else {
    return; // no DATABASE_URL: skip
};
owt_accounts::migrations::start(db.pool(), || {
    owt_runtime::db::migrate_locked(db.pool(), &MIGRATOR, 8_531_207)
})
.await
.unwrap();
// ... test against `db.pool()`, then:
db.close().await;
# }
```

Tests that keep `#[sqlx::test]` need a server of their own per checkout.

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
Every app then answers to the same commands:

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
then the database).
App-specific recipes go below the template's `---- app recipes ----` line. The
compose ports and database name come from the app's `.env` (`POSTGRES_PORT`,
`POSTGRES_DB`, ...), so two apps' stacks can run side by side.

**Fast tests:** a debug build runs password hashing and the ciphers 20 to 50 times
slower than a release one, and a suite that signs users in or seals a cookie spends
most of its time there. This repository's root `Cargo.toml` builds the cryptography
dependencies at `opt-level = 3` in the dev profile (which `cargo test` inherits), and
the workspace's own crates stay unoptimised, so recompiling after an edit stays quick.
An app adds the same to its root `Cargo.toml`, for the crates its `Cargo.lock` has
(cargo warns about an override for a package that is absent; `cargo tree -i <crate>`
shows whether one is):

```toml
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.sha2]
opt-level = 3
# likewise: blake2, password-hash, aes, aes-gcm, aead, ghash, polyval, universal-hash,
# sha1, md-5, hmac, hkdf, chacha20, ctr, cipher, inout, digest, block-buffer,
# crypto-common, cpufeatures, subtle, base64ct, curve25519-dalek, ed25519-dalek, rsa,
# num-bigint-dig, crypto-bigint, pbkdf2, p256, p384, elliptic-curve, primeorder, ecdsa,
# ff, group, fiat-crypto
```

It changes nothing about the lockfile, `cargo audit` or sccache (the optimised
artifacts are cached under their own key).

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
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@<commit>  # v0.11.0
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
    uses: onewaytek/owt-stack/.github/workflows/release.yml@<commit>  # v0.11.0
  image:
    needs: release
    if: needs.release.outputs.version != ''
    permissions: {contents: read, packages: write, id-token: write}
    uses: onewaytek/owt-stack/.github/workflows/image.yml@<commit>  # v0.11.0
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
        version: {description: "The released version (0.11.0, v0.2.0-rc.1)", required: true}
        floating-tags: {description: "Also move the channel's floating tags", type: boolean, default: false}
  jobs:
    image:
      permissions: {contents: read, packages: write, id-token: write}
      uses: onewaytek/owt-stack/.github/workflows/image.yml@<commit>  # v0.11.0
      with: {version: "${{ inputs.version }}", floating-tags: "${{ inputs.floating-tags }}", bin: myapp}
      secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
  ```
- **The rc channel** (optional): on each same-repository PR into `main`, once its
  checks pass, merge the PR into `rc` and cut a prerelease. After each stable
  release, merge `main` back into `rc` (`sync-rc`). When the merge changes `rc`'s tree
  (a fix committed straight to `main`) it also releases `rc`; when it only joins the
  histories (the usual case: `rc` already carries its PRs, squashed into `main`) it
  releases nothing. That rule belongs to `sync-rc` as written below; a sync through the
  candidate flow releases on every publish. The test is the whole tree: `-X theirs`
  can pull `rc`'s tree toward `main` where an in-flight feature edits the same lines,
  and an app whose release commits `chore(release)` files back to `main` has a
  changed tree at every sync. Such a release run publishes nothing (no releasable
  commit, no image) and costs one run. A release run on `rc` that failed and is
  re-run after `rc` moved publishes nothing either, since semantic-release will not
  release from a commit behind its branch. The next release run releases everything
  since the last tag, the failed run's commits included, but a history-only sync
  starts none, so those commits wait for the next promotion or tree-changing sync.
  An app that passed `dispatch-release: false` to `sync-rc` drops it to get the
  rule. A PR's checks run on the PR alone, so two
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
  oldest one (a person's PR before a bot's; see "Dependabot on the rc channel" below),
  one at a time and only while no run is waiting (a re-run is itself a new arrival in
  the group; a waiting run a bot started is the exception). A run that succeeded
  without running "Merge into rc" (an `edited` or `labeled` trigger whose candidate
  job was skipped) doesn't count, so it
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

  **Dependabot on the rc channel.** A Dependabot pull request is promoted like any
  other, and `rc` is where a bump is tried: merged into `rc`, released as a
  prerelease and deployed wherever the app deploys `rc`, with no review. Review stays
  required before `main` and production. It reaches `rc` only under these conditions,
  which are GitHub's for a run Dependabot triggers (it gets a read-only `GITHUB_TOKEN`
  and only Dependabot secrets, and a re-run keeps both): the `permissions:` the
  promotion jobs declare (`contents: write`, `actions: write`, as in the example below) raise the
  token, which is what lets the merge push `rc` and dispatch the release, so the
  calling jobs must declare them and the repository must not cap the token below
  them; and every secret the checks and the candidate's checks use (the sccache
  password, a database URL) must also exist as a *Dependabot* secret, or those steps
  run without it. Absent either, the bump's promotion fails at "Merge into rc" or
  checks without its secrets, and the PR waits for a person.

  Dependabot opens its pull requests in bursts, and the group admits one promotion
  with one waiting, so a burst cancels waiting runs. A person's pull request is not
  left behind it: `requeue-rc.yml` re-runs every person's lost promotion before any
  bot's, and a person's re-run may cancel a run *pending* in the group that a bot
  started (that PR is requeued after every person's); a bot's re-run cancels nothing.
  A bot is an author or actor whose account type is `Bot`: Dependabot, but also any
  GitHub App, release-please's pull requests and one an app opens among them. A
  person's PR waits for the run in progress, not for the bumps behind it.

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
    uses: onewaytek/owt-stack/.github/workflows/conventional-commits.yml@<commit>  # v0.11.0, and "commits / commits"
    # with: {title: false}   # an app that checks titles another way: only "commits / commits" runs (the skipped
    # "commits / title" counts as passing for a required check)
  candidate:
    needs: ci
    if: github.event.pull_request.head.repo.full_name == github.repository && !github.event.pull_request.draft
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@<commit>  # v0.11.0
    with: {source: "${{ github.event.pull_request.head.ref }}", pr: "${{ github.event.pull_request.number }}", candidate: true}
  check-rc:
    needs: candidate
    if: needs.candidate.outputs.changed == 'true'
    uses: onewaytek/owt-stack/.github/workflows/rust-ci.yml@<commit>  # v0.11.0
    with: {ref: "${{ needs.candidate.outputs.sha }}", database: myapp}  # as the app's CI
    secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
  promote:
    needs: [candidate, check-rc]
    permissions: {contents: write, actions: write}
    uses: onewaytek/owt-stack/.github/workflows/publish-rc.yml@<commit>  # v0.11.0
    with: {sha: "${{ needs.candidate.outputs.sha }}", base: "${{ needs.candidate.outputs.base }}"}
  requeue:
    needs: promote
    if: always() && github.event.pull_request.head.repo.full_name == github.repository
    permissions: {actions: write, contents: read, pull-requests: read}
    uses: onewaytek/owt-stack/.github/workflows/requeue-rc.yml@<commit>  # v0.11.0
    with: {workflow: pr.yml}  # this file
# in requeue-rc.yml, on {schedule: [{cron: "*/30 * * * *"}], workflow_dispatch: {}}:
# the requeue job above, without its needs and if
# in release.yml
  sync-rc:
    needs: release
    if: github.ref_name == 'main'
    permissions: {contents: write, actions: write, pull-requests: write}
    uses: onewaytek/owt-stack/.github/workflows/promote-rc.yml@<commit>  # v0.11.0
    with: {source: main}
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
(0755, owned by `workdir-owner`), and the `files` under it, owned by `files-owner`. The
read-only `verify` job checks the layer's paths and modes and that the base has
`base-requires` and a glibc at least as new as the binary needs. The `push` job
confirms the layer is the one verified and runs none of the app's code; of the
`crane` builder's jobs it alone holds `packages: write` (the `docker` builder's job
and `attest` hold it too): with
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
| `cargo-profile` | `release` | the profile `cargo build` uses (`--release`, else `--profile <name>`; `dev` installs from `target/debug`); meant for `image-check.yml`, see below |
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
| `vuln-fail-on` | `critical` | none (the scan below); `negligible`, `low`, `medium`, `high`, `critical`, or `none` to report only |
| `vuln-ignore-file` | none | none; a grype configuration file in the repository whose `ignore:` rules waive findings |
| `attest` | `true` | none; `false` skips the signature and the SBOM (`image.yml` only) |

**Supply chain:** each image is scanned, signed and given an SBOM.

- **Scan:** grype runs before anything is pushed, so a finding of `vuln-fail-on`
  severity or worse (`critical` by default) pushes and tags nothing. With `crane`, a
  `scan` job assembles the image as `push` would make it (the base pinned by digest,
  the layer on top) and `push` waits for it. With `docker`, the image is pushed
  once under a temporary tag (`scan-<run id>-<attempt>`), scanned there by digest, and only then given its
  version and floating tags (the same digest, retagged); a failing scan leaves
  the temporary tag and no other. `vuln-fail-on: none` still prints the
  findings and never fails; any other value than `negligible`, `low`, `medium`,
  `high`, `critical` or `none` fails the job. grype reads exactly the configuration
  `vuln-ignore-file` names, and none when it is empty: a `.grype.yaml` in the
  repository is not picked up unasked. A finding with no fix, or a false positive,
  is waived in that file:

  ```yaml
  # .grype.yaml, named by vuln-ignore-file
  ignore:
    - vulnerability: CVE-2026-0001   # a finding id
    - fix-state: not-fixed           # or every finding that has no fix yet
  ```
- **Signature:** the `attest` job signs the pushed digest, never a tag, with
  [cosign](https://github.com/sigstore/cosign) keyless: the run's OIDC token, which
  Sigstore exchanges for a short-lived certificate, and a record in the public
  transparency log. The certificate's identity is the reusable workflow, not the
  app's workflow, and the app's repository is its source repository:

  ```sh
  cosign verify ghcr.io/<owner>/<app>@<digest> \
    --certificate-identity 'https://github.com/onewaytek/owt-stack/.github/workflows/image.yml@<commit>' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository <owner>/<app>
  ```

  The identity ends in the ref the app's workflow calls `image.yml` at: with the
  commit SHA the adoption examples pin (`image.yml@<commit>  # vX.Y.Z`), it is that
  SHA, so `<commit>` above is the same 40-character SHA, and the image verifies only
  if it was signed by that reviewed revision of the workflow. A caller that pins a
  tag instead uses `@refs/tags/vX.Y.Z`. Never match a pattern that ends at `@`: it
  also verifies an image signed by a workflow run from an unreviewed branch.
- **SBOM:** the same job runs [syft](https://github.com/anchore/syft) on the pushed
  digest, uploads the SPDX JSON as the run's `sbom.spdx.json` artifact and attaches
  it to the image as a signed attestation (`cosign verify-attestation --type
  spdxjson ...`, with the same identity flags).

The caller's job therefore grants `id-token: write` besides `packages: write`
(`permissions: {contents: read, packages: write, id-token: write}`): a reusable
workflow cannot take a permission its caller withholds, and a caller that grants
less fails to start, `attest: false` or not. `attest: false` skips the signature and
the SBOM, not the scan.

**Base images float on purpose.** The template's `FROM` lines name tags (`rust:1`,
`core-runtime:2`), not digests, so every build picks up the base's latest patches
without a bot bumping pins. Two builds of one commit can therefore differ. What a
given image was built from is still on record: the signature binds its digest, and
the SBOM attestation lists the base's packages and versions. An app that needs a
rebuild to be byte-reproducible passes `base-image` as a digest (used as given).

The two builders make equivalent images, not byte-identical ones. The binary differs in
bytes and in size, by a few percent: the crane builder compiles it in Debian's Rust
image and the Dockerfile in Hummingbird's. The template Dockerfile owns `/app/static`
as `65532:0`, as `files-owner` does; an app whose Dockerfile is an older copy
(`COPY --from=css /app/static ./static`, no `--chown`) has it owned `0:0`, and recopies
the template's line to match. Compare the two by layout (paths, owners, modes,
configuration), not by digest.

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
for the setup actions), so the verify job checks the newest `GLIBC_` version the
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
fully qualified, so a local `podman build` works without a registry prompt.
`core-runtime` runs non-root from its first step: its default user is 65532 from the
first instruction, not root until a `USER` line, so a `RUN` in the runtime stage that
needs root (a package install, a write outside `/app`) fails there. Do that work in an earlier
stage and `COPY` the result in, with `--chown=65532:0` for what the app writes.

**Checking the image on a pull request** (opt-in): the Dockerfile or the build
inputs can break only in the image, and without a check that shows after a version is
tagged, as a release with no image. `image-check.yml` builds the pull request's merge
commit the way a release does and verifies all but the push: with `builder: crane`
(the default) the compile, the npm assets, the packed layer, and the base's tools and
glibc, by the same `build` and `verify` jobs as `image.yml`'s (`just image-check`
keeps them identical); with `builder: docker` the Dockerfile is built with BuildKit
and pushed nowhere. It also scans the image with grype, as `image.yml` does, with the
same `vuln-fail-on` and `vuln-ignore-file` inputs: this is where a vulnerable base image
is most useful to learn of, before the release. Nothing is signed and no SBOM is made
here, and the caller still grants `contents: read` only. It takes `image.yml`'s inputs that shape the build (`bin`,
`cargo-args`, `files`, `base-image`, ...) and none that shape the push.
`cargo-profile` makes the check cheaper: a pull request can build with `dev`, or with a
profile of the app's own that turns off fat LTO and sets many codegen units
(`[profile.ci] inherits = "release"`), instead of the release link. The check then does
not prove that the release profile's link succeeds, so a release still builds with
`release`. It is a workflow of its own because no job in it writes: the caller grants `contents: read`
only, which a Dependabot pull request's token can. (A called workflow that asks for
`packages: write`, as `image.yml`'s `push` does, fails to start for a caller that
grants less, skipped job or not.) Call it from a workflow of its own with a `paths:`
filter, so it neither gates every merge nor runs for a change the image does not see:

<!-- x-release-please-start-version -->
```yaml
# .github/workflows/image-check.yml
on:
  pull_request:
    # What the image reads: the Dockerfile and its ignore file, the Rust sources and
    # manifests (every workspace crate), the lockfiles and the asset inputs.
    paths:
      - Dockerfile
      - .dockerignore
      - Cargo.toml
      - Cargo.lock
      - src/**
      - crates/**
      - package.json
      - package-lock.json
      - static/**
      - templates/**
      - .github/workflows/image-check.yml
permissions: {}
jobs:
  image:
    # A fork's pull request is not built here (image-check.yml refuses it too).
    if: github.event.pull_request.head.repo.full_name == github.repository
    permissions: {contents: read}
    uses: onewaytek/owt-stack/.github/workflows/image-check.yml@<commit>  # v0.11.0
    with: {bin: myapp}   # as the release's image job
    secrets: {SCCACHE_REDIS_PASSWORD: "${{ secrets.SCCACHE_REDIS_PASSWORD }}"}
```
<!-- x-release-please-end -->

The cost is one release build per push to a matching pull request. With `crane` it
runs on the ARC scale set, which bills no GitHub-hosted minutes (it takes the
cluster's capacity), and sccache shortens the compile (a Dependabot pull request
reads Dependabot's secrets, not Actions', so it compiles without it). With
`builder: docker` it runs on `ubuntu-latest`, so a private app pays minutes for every
such push, and the build is cold: a pull request restores the Actions cache only from
its own ref, its base branch and the default branch, and the release builds write
theirs under tag refs, so none is read (a cold BuildKit build of a Rust app takes
ten minutes or more). Keep the `paths:` list to the files the image reads, and leave
the check out of an app whose Dockerfile rarely changes.

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
then each task's) when present; `tunnel.yaml` when `params.env` sets `TUNNEL_HOST`
and `TUNNEL_ID` (below); `cronjob.yaml` once per
`deploy/openshift/jobs/<JOB>.env`, whose lines (`JOB`, `SCHEDULE`, `ARGS`, and any
override such as `INTERNET_CIDR` or the task's `MEMORY_LIMIT`) are read over
`params.env`; `monitoring.yaml` with `--monitoring`, since it needs monitoring-edit
(see "Monitoring"). One pair of quotes comes off a value (`BACKUP_SCHEDULE="0 0 2 * *
*"`); the parameters reach `oc process` in a `--param-file`, so a comma in a value
(`RUST_LOG=info,myapp=debug`) is not read as a list. A name two templates declare
means one thing in both (`NAME`, `NAMESPACE`, `CHANNEL`, `DB_SUFFIX`); Redis's image and memory limit are `REDIS_IMAGE` and
`REDIS_MEMORY_LIMIT`, apart from the app's. Upgrading owt-stack is: copy the templates
again, keep `params.env`. Exit status 1 means the diff found changes, 2 a refusal or
a failed `oc`.

A parameter `params.env` cannot hold (a checksum of a ConfigMap, a value derived from
the cluster) comes from an optional executable `deploy/openshift/pre-render`. It runs
once, in that directory, in a diff as in an apply, so it only reads; the `params.env`
parameters are its environment, its stdin is empty, and its stdout is `KEY=VALUE`
lines (read as `params.env`'s are) that join the parameters over `params.env`'s,
under a task's own file. `NAME` and `NAMESPACE` stay `params.env`'s: a hook that sets
either to another value is refused. Its stderr shows, and a failure, a line that is
no pair, or a `pre-render` that is not an executable file (a dangling link, no x bit)
exits 2 before anything renders. The output becomes template parameters, applied into
the cluster's objects and shown in a diff, so it must not hold a secret. Assign
before echoing: in `echo "K=$(cmd)"` a failing `cmd` is swallowed by `echo`'s status.

```sh
#!/usr/bin/env bash
# deploy/openshift/pre-render
set -euo pipefail
level=$(oc get configmap myapp-log -o jsonpath='{.data.level}')
echo "RUST_LOG=info,myapp=$level"
```

The script writes no Secret: the app's environment is `env.sh`'s, below, and a Redis
password is made by hand. `templates/openshift/apply-test.sh` proves the script against a
stand-in `oc` (`just templates` runs it here).

The ImageStream polls ghcr for the channel's tag (`rc` or `latest`), and the
Deployment's trigger rolls out each new digest. By hand, the same is one
`oc process … | oc apply -f -` per template:

```sh
oc process -f templates/openshift/app.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p IMAGE=ghcr.io/onewaytek/myapp -p CHANNEL=rc -p PORT=8000 | oc apply -f -
```

**Database roles.** The app serves as a runtime role, `myapp_runtime`, that owns
nothing; the schema's owner (`myapp`, CNPG's `myapp-db-app` Secret) runs only in each
pod's `migrate` init container, which runs the binary's `migrate` subcommand and exits
before the app starts. So an injection or a compromised replica cannot drop the audit
tables' triggers or rewrite their chain (see "Roles" under the audit log). CNPG
manages the runtime role (`managed.roles`) from a Secret made once, by hand, before
the first apply (a hex password needs no escaping in the URL the Deployment builds):

```sh
pw=$(openssl rand -hex 32)
oc create secret generic myapp-db-runtime -n myapp --type=kubernetes.io/basic-auth \
  --from-literal=username=myapp_runtime --from-literal=password="$pw"
oc label secret myapp-db-runtime -n myapp cnpg.io/reload=true
```

The init container sets `DATABASE_URL` to the owner's and `DB_RUNTIME_ROLE` to the
runtime role's name. The `migrate` subcommand runs the migration sequence (see
"Tables" under accounts), then grants the runtime role what serving needs, and the
app's serve path no longer migrates (it would fail: the runtime role cannot `CREATE`):

```rust,no_run
# async fn migrate(pool: sqlx::PgPool, app_migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
owt_accounts::migrations::start(&pool, || {
    owt_runtime::db::migrate_locked(&pool, app_migrator, 8_531_207)
})
.await?;
owt_audit::migrate(&pool).await?;
if let Ok(role) = std::env::var("DB_RUNTIME_ROLE") {
    // Every table: SELECT, INSERT, UPDATE, DELETE; sequences; ledgers read-only.
    owt_runtime::db::grant_runtime(&pool, &role).await?;
    // Then the audit tables narrowed: SELECT, INSERT on events, SELECT on anchors.
    owt_audit::grant_runtime(&pool, &role).await?;
}
# Ok(()) }
```

Tasks from `cronjob.yaml` connect as the runtime role too. A task that needs more
gets a role of its own, never the owner's: the anchoring job inserts anchors, which
the runtime role may only read, so it runs as `myapp_anchor`, a second managed role
in the Cluster, its Secret `myapp-db-anchor` made like `myapp-db-runtime`, given the
grants under "Roles" (Audit log) once by the owner, and the task processed
with `-p DB_ROLE=anchor`.

**Upgrading an app to the two roles:** add the `migrate` subcommand above (or the
grants to the one it has) and stop migrating in the serve path; create the
`myapp-db-runtime` Secret; apply. The first pod's init container grants the existing
tables, and the role owns nothing to hand back.

**The app's environment** (`SESSION_SECRET`, a provider's credentials, its own
tuning) lives in a Secret named `myapp-env`, which the Deployment reads whole. It is
optional: until it exists, the app starts without it. A variable the template sets
(`DATABASE_URL`, `PGSSLMODE`, `BIND_ADDR`, `RUST_LOG`, …) wins over the Secret's;
`RUST_LOG` is the template's `RUST_LOG` parameter (default `info`), so a narrower
filter goes in `params.env` (`RUST_LOG=info,myapp=debug`), or in a task's
`jobs/<JOB>.env` for that task alone. A
Secret's change reaches pods only when they start, so restart after one.

`env.sh`, beside `apply.sh`, makes the Secret idempotently from `env.env`, one
`KEY=VALUE` a line (read as `params.env`'s are), with `NAME` and `NAMESPACE` from
`params.env`:

```sh
# deploy/openshift/env.env, committed: it holds no secret value
# Written as given; a changed value is patched in.
PUBLIC_BASE_URL=https://myapp.example
# 64 random bytes, made once and never regenerated.
SESSION_SECRET=@generate
# The caller's $PROVIDER_TOKEN; kept when unset.
PROVIDER_TOKEN=@env
```

```sh
deploy/openshift/env.sh               # what would change (exit 1 when something)
read -rs PROVIDER_TOKEN && export PROVIDER_TOKEN   # not in argv or shell history
deploy/openshift/env.sh --apply
oc rollout restart deployment/myapp
```

It reports each key (`created`, `set`, `kept`, `unchanged`) and never a value, which
reach `oc` in a file rather than on a command line. A key the Secret holds that the
file does not list (one set by hand with `oc set data`) is left alone. A value with a
newline is refused, and so is an `@env` key that is neither set (an empty variable
counts as unset) nor already in the Secret; `@env` reads the exported environment
only. Two runs at once race, the last patch winning. `templates/openshift/env-test.sh` proves it against a stand-in `oc`.

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
#    List them in env.env (a literal, or @env for a secret exported without argv, as
#    "The app's environment" shows), then make the Secret:
deploy/openshift/env.sh --apply
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
database access: `DATABASE_URL` as the runtime role from `myapp-db-runtime` (or the
role `DB_ROLE` names, from `myapp-db-<DB_ROLE>`), `PGSSLMODE=verify-full` with
`PGSSLROOTCERT` at the mounted `myapp-db-ca`, `POD_NAMESPACE`, `REDIS_URL` and
`myapp-env`. A credential only the task needs goes in a Secret of its own,
`myapp-<JOB>-env` (`myapp-digest-env`), which the task reads after `myapp-env` (its
keys win) and the web pods never read. It is optional, like `myapp-env`, so a
misspelt name starts the task without the credential: check
`oc get secret myapp-digest-env`. Make it from a file, not the command line:

```sh
oc create secret generic myapp-digest-env --from-env-file=digest-secret.env
```

The template takes the same `DB_SUFFIX` as `app.yaml` (default `db`), which names the
database cluster and those Secrets. Its pods are labelled `app: myapp-<JOB>`, never
`app: myapp`, which the app's Service sends traffic to. The database's and Redis's NetworkPolicies admit the
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

**The public address, through a Cloudflare tunnel.** On a cluster the internet
cannot reach, `tunnel.yaml` gives the app a Cloudflare named tunnel of its own: two
`cloudflared` connectors in its namespace dial out to Cloudflare's edge, and requests
for `TUNNEL_HOST` come back down those connections to the app's Service (port 80),
the browser's `Host` passed through. The tunnel is locally managed: its ingress rules
are the template's, in git, and the Cloudflare account holds only the tunnel and its
DNS record. Each app has its own tunnel and connectors, never another app's: a
connector restart drops every WebSocket and SSE stream it carries ("Decisions").

Made once, where `cloudflared` is logged in to the account (`cloudflared tunnel
login`): the tunnel, whose credentials file goes into a Secret and nowhere else, and
the DNS record, a proxied CNAME to `<id>.cfargotunnel.com`:

```sh
cloudflared tunnel create myapp                       # prints the id, writes ~/.cloudflared/<id>.json
oc create secret generic myapp-tunnel -n myapp \
  --from-file=credentials.json=$HOME/.cloudflared/<id>.json
cloudflared tunnel route dns myapp myapp.example.com  # --overwrite-dns replaces a record
```

Then `params.env` names the host and the tunnel, and `apply.sh` renders `tunnel.yaml`
beside `app.yaml`:

```sh
TUNNEL_HOST=myapp.example.com
TUNNEL_ID=<id>                    # cloudflared tunnel list; not a secret
# CREDENTIALS_SECRET=myapp-tunnel # the default, <NAME>-tunnel
```

`TUNNEL_HOST` without `TUNNEL_ID`, or the reverse, is refused, as is a `TUNNEL_HOST`
that is not a bare host name (a wildcard, `*.example.com`, is one), a `TUNNEL_ID` that
is no UUID, or a `TUNNEL_HOST` with no `tunnel.yaml` beside the script. The objects'
names are fixed (`cloudflared`, `cloudflared-config`), whatever `NAME` is: one tunnel
per namespace, as one app per namespace.
`cloudflared` reads its config once, at start, so `apply.sh` puts a checksum of the
rendered config in the connectors' pod template (`TUNNEL_CONFIG_CHECKSUM`): a new host
or tunnel rolls them, one at a time, each new connector registered with the edge
before an old one stops. A rotated credentials Secret is not in the checksum: `oc
rollout restart deployment/cloudflared` after it. The image is pinned by tag and
digest (`CLOUDFLARED_IMAGE`), with no self-update, so the connectors restart only when
an upgrade of owt-stack or the app changes it; each one requests 10m CPU and 48Mi
(about what one uses idle), with a `TUNNEL_MEMORY_LIMIT` of 256Mi for the streams it
carries. There is no PodDisruptionBudget: on a single node a drain takes both pods
whatever it says; on several, the two spread across nodes when they can. Liveness
reads `/ready` but waits five minutes of failures, so an edge or network outage that
`cloudflared` rides out by reconnecting does not restart it into CrashLoopBackOff.

The NetworkPolicies come with it: `myapp-from-tunnel` admits the connectors to the
app's HTTP port, beside `app.yaml`'s policy, which admits the router alone, and
`cloudflared` admits nothing to the connectors and lets them open only the cluster's
DNS (`DNS_NAMESPACE`, `DNS_PORT`, as `egress.yaml`'s), Cloudflare's edge on 7844 (QUIC
over UDP, HTTP/2 over TCP), HTTPS (IPv4 and IPv6 alike), and the app's HTTP port.
Removing the tunnel is by hand, since `apply.sh` renders and never deletes: drop the
two keys, then `oc delete deployment,configmap,networkpolicy -l app=cloudflared` and
`oc delete networkpolicy myapp-from-tunnel`.

Every request through the tunnel carries the client's address in `CF-Connecting-IP`,
which Cloudflare sets, so the app's environment (`env.env`, below) has
`CLIENT_IP=header:CF-Connecting-IP` ("The client's address"). That header is believed
from anyone who can reach the app: the app's Route still answers on the cluster's own
network, and a client there could write the header itself, so this setting is for an
app whose Route only trusted machines reach. The Route stays for them; the tunnel is
the public way in. By hand, without `apply.sh`, the render names the Secret, and a
config change needs the restart:

```sh
oc process -f templates/openshift/tunnel.yaml -p NAME=myapp -p NAMESPACE=myapp \
  -p TUNNEL_HOST=myapp.example.com -p TUNNEL_ID=<id> \
  -p CREDENTIALS_SECRET=myapp-tunnel | oc apply -f -
```

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

**The `migrate` init container's `DATABASE_URL` is the `uri` key of `myapp-db-app`**
(`myapp-<DB_SUFFIX>-app`). CloudNativePG creates that Secret,
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
hand, outside the template; an existing Route's value goes in `params.env` before
the first apply, or the apply resets it ("Upgrading from 0.8"). (An upgraded WebSocket answers to
the router's `timeout tunnel` instead, an hour by default.)

**Backups come with it.** The database takes a volume snapshot nightly
(`BACKUP_SCHEDULE`, CNPG's six-field cron, seconds first) and once at first apply.
They are offline by default (`BACKUP_ONLINE=false`): Postgres stops for the seconds an
LVM snapshot takes, because an online snapshot is only consistent with a WAL archive,
which these clusters don't have. With one instance (`DB_INSTANCES=1`, the default)
the app sees that pause: requests needing the database fail for a few seconds each
night, and once at the first apply, when the immediate backup overlaps the rollout
that same apply starts (apply outside busy hours, or expect a few errors then). The
choices: accept the pause (a pod starting during it waits, since `PoolConfig::connect`
retries for a minute); run two instances (`-p DB_INSTANCES=2`: CNPG snapshots the
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
"devDependencies": { "@onewaytek/owt-stack": "github:onewaytek/owt-stack#v0.11.0" }
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
  `Sessions::validate_with`. A session ends after 30 minutes idle and at its absolute
  lifetime (24 hours) however often it is re-sealed, both unless the app sets others, and a response that sets the cookie is never cacheable.
- **Fragments have their own URLs.** Nothing varies by request header, so every
  response stays cacheable behind a CDN that ignores `Vary`.
- **Password policy: NIST SP 800-63B-4, not folklore.** 15 characters at least for a password
  that signs in alone (`Policy::single_factor`), 8 only where a second factor is required
  (`Policy::new`), configurable upward with `Policy::min_len`; 128 at most, never under 64; counted in code points after NFKC. Every
  character is allowed, spaces included. **No composition rules** (a mix of cases,
  digits and symbols yields `Password1!`, and 800-63B-4 §3.1.1.2 says verifiers SHOULD NOT
  impose them) and **no periodic expiry** (SHOULD NOT require arbitrary change: forced
  rotation yields `Summer2026`, then `Autumn2026`; change on evidence of compromise).
  Passwords are refused for being in a breach corpus, or containing the username, the
  email's name part or a context word (of four characters or more, so `ed` does not
  ban a great many good passwords). The breach check is offline, against a file the
  app ships: the Pwned Passwords range API would send a hash prefix of every new
  password to a third party. A `Bloom` filter's errors fail safe (a good password
  refused, never a breached one accepted).
- **Recovery codes are Argon2id hashes**, not a peppered HMAC: 50 bits is too little for
  a fast hash, and a pepper is a secret to keep and rotate; the table alone then
  protects them.
- **A second factor is TOTP and recovery codes, with step-up, enforced at the layer.**
  Pending sign-ins carry no signature, so no extractor can mistake one for a session, and
  `Accounts::load`, on an `Accounts` that `require_mfa`, holds every signature (provider, link, gate, old route) to the
  second factor. A session records when the account last proved who it is, bound to its
  account and epoch, and sensitive actions ask for a recent proof (`Recent`, `RecentMfa`);
  a sign-in that records nothing counts as stale. Factor changes need a `ChangeProof` from
  `Mfa::authorize_change`, move the account's session epoch on and reseal the current
  session. Ten wrong codes lock the authenticator (persisted). The TOTP secret is stored
  with a format and key id by an app-supplied `SecretSealer`. Enrolling from a pending
  sign-in is allowed under `Required` and flagged (`while_pending`) so the owner is told;
  the library does not require an emailed link.
- **The shared throttle fails closed.** If Redis is unreachable, sign-in is refused
  (`Refusal::Unavailable`) rather than allowed unthrottled: the throttle is the only
  bound on online guessing. `FailMode::Open` is the app's choice to make.
- **Library code holds no `query!` macros**, so it needs no `.sqlx/` metadata and builds
  offline anywhere.
- **Metric names belong to the app.** The library takes them as arguments, so an app's
  dashboards and load-test reports keep their names.
- **Bus channel names** (`<prefix>:<topic>`, `~changed`, `~beat`) are a wire format
  between replicas. Changing one is a rollout hazard: old and new replicas must agree.
- **The job queue polls; it is not notified.** `LISTEN/NOTIFY` would pin a
  connection per listening worker, and `NOTIFY` serialises committing transactions on
  one server-wide lock, a ceiling for enqueue-heavy apps; a transaction-mode pooler
  drops `LISTEN` without a word, so a safety poll is needed anyway. A claim is one
  partial-index query per worker per interval (`Worker::poll`, default 5 s), and a
  queue that needs a quicker start shortens its interval.
- **One audit chain per tenant**, not one global chain. Appends to a chain are
  serialized, so a global chain would make every tenant's writes wait on one lock;
  per tenant, they never wait on each other. A tenant's chain verifies and exports
  on its own, without revealing other tenants' events, and a tenant's log can be
  handed over or retired at the end of its contract without breaking anyone else's.
  What a global chain adds, evidence across tenants, comes from anchoring: each
  manifest holds every chain's head and names the previous manifest.
- **OpenShift Template, not Kustomize**, for the deployment: the app's name must reach
  the image trigger annotation and the CNPG Secret's name, which Kustomize's name
  transformers do not rewrite.
- **One Cloudflare tunnel per app**, with its connectors in the app's namespace. A
  WebSocket or SSE stream is pinned to the connector that accepted it and ends when
  that connector restarts, so connectors shared between apps would let one app's
  rollout, crash or config change cut another's live connections. The tunnel is
  locally managed (credentials in a Secret, ingress rules in git), not configured in
  the Cloudflare dashboard, so a deploy's configuration stays reviewable in one place.

## Security an app wires

The router example under "Wiring an app" composes the layers; beyond it:

- `headers::security` sends HSTS for the app's own host. An app that owns its whole
  domain adds `includeSubDomains` itself.
- Sign-in: `throttle::Throttle::sign_in` *before* `password::verify_or_decoy` (a
  refused sign-in checks no password), keyed on `client_ip::Source::client_ip`
  (configured for the proxies actually in front of the app), and
  `redirect::local_or` on `?next=` before redirecting to it (see "Authentication").
- Passwords and second factors: `password::Policy` on every new password (see
  "Authentication"), and on a system holding health records `totp` or a passkey on top,
  `SharedThrottle` once there is more than one replica, and the TOTP secret sealed at
  rest.
- Anonymous forms: `owt_auth::bots::Guard` (see "Anonymous forms"); a form anyone can
  post, with no budget, is a free write into the database or an inbox.
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

## Upgrading from 0.9

- **The Cloudflare tunnel is a template** (`templates/openshift/tunnel.yaml`, "The
  public address, through a Cloudflare tunnel"). An app that keeps its own copy of
  the `cloudflared` ConfigMap and Deployment (in its `app.yaml`, or a `tunnel.yaml` and
  script of its own) moves over in place, without a second tunnel: the template's
  objects are the copies' names (`cloudflared-config`, `cloudflared`), with the same
  `app: cloudflared` selector, so the apply updates them.

  1. Copy `tunnel.yaml` and `apply.sh` into `deploy/openshift/`, and delete the app's
     own tunnel objects from its templates, and any script of its own that rendered
     them.
  2. In `params.env`: `TUNNEL_HOST` (the host the copy served), `TUNNEL_ID` (from
     `cloudflared tunnel list`, or the `TunnelID` in the credentials Secret:
     `oc get secret myapp-tunnel -o jsonpath='{.data.credentials\.json}' | base64 -d`),
     and `CREDENTIALS_SECRET` when the Secret is not `myapp-tunnel`. The Secret, the
     tunnel and its DNS record stay as they are.
  3. `deploy/openshift/apply.sh`, and read the diff: the ConfigMap's comments, the
     image (now with its digest), resources, probes' port name and the pod template's
     annotations change, so the connectors roll once, one at a time. Then `--apply`.
  4. A policy of the copy's that admitted the connectors to the app under another name
     (`myapp-from-cloudflared`) is now `myapp-from-tunnel`'s job: `oc delete
     networkpolicy myapp-from-cloudflared`. A rule for the connectors written into the
     app's own policy goes when that policy is `app.yaml`'s again.

  The connectors gain an egress policy they did not have: DNS, 7844 and 443 to the
  internet, and the app's HTTP port. A connector that cannot register shows as not
  ready, and the rollout stops with the old one still serving.

## Upgrading from 0.8

- **Breaking:** owt-accounts migrates its own tables, in a ledger of its own
  (`_owt_accounts_migrations`; "Tables" under "Accounts"), and
  `migrations::assert_installed` is gone. An app that copied `ALL` into its
  `migrations/` moves over in one release, without re-running anything:

  1. At start the app awaits `owt_accounts::migrations::start(&pool, || its migrator)`
     in place of its migrator and `complete`: `migrations::run(&pool)`, then the app's
     migrator, then `migrations::complete`. On the first start `run` finds the copies in
     `_sqlx_migrations` by checksum (whatever versions and names the app gave them),
     records them in `_owt_accounts_migrations` as applied without running them, and
     runs any entry the app had not copied yet. Replicas starting together take its
     advisory lock in turn; the second finds nothing to do.
  2. The app deletes its copies from `migrations/`: every file whose text is one of
     `ALL` (`0001_owt_accounts.sql`, `0006_owt_accounts_roles.sql`, and so on), and
     the test that called `assert_installed`.
  3. Its own migrator ignores the versions it no longer has, since their rows stay in
     `_sqlx_migrations`: `let mut migrator = sqlx::migrate!(); migrator.set_ignore_missing(true);`
     (and `sqlx migrate run --ignore-missing` by hand). Nothing deletes those rows,
     so a replica of the previous release, still carrying the copies, keeps starting
     during the rollout, and a rollback works. Once no running binary carries the
     copies, `owt_accounts::migrations::forget_copies(&pool)` may delete them and the
     app may drop `set_ignore_missing`; leaving them is harmless.
  4. An app whose own migrations must partly run before the library's (one that renamed
     an `accounts` of its own out of the way) runs its migrator to that version first
     with `owt_runtime::db::migrate_locked_to`, then `migrations::run`, then
     `migrate_locked`, then `migrations::complete`, in place of `start`. A database
     built from nothing then runs the app's migrations after all of the library's (or
     after the split), not interleaved with them as the copies were: run CI, or `just
     migrate` on an empty database, before deploying, since that order is new for every
     app.
  5. The app's binary takes a `migrate` subcommand that runs the start's sequence and
     exits; the justfile's `migrate_command` and `rust-ci.yml`'s `migrate-command`
     run it (`SQLX_OFFLINE=true cargo run --locked -- migrate`), because a database
     made by `sqlx migrate run` alone no longer has the library's tables.
  6. Its tests stop building databases from `migrations/` alone, which no longer
     makes the library's tables: `#[sqlx::test(migrations = false)]` (in place of
     `#[sqlx::test]` or `#[sqlx::test(migrator = "myapp::MIGRATOR")]`), and the test
     first awaits the app's start-up sequence on the pool it is given (its `migrate`
     function: `migrations::start`), so every test runs the order production runs.
  7. `run` stops the start, naming the row, when a copy differs from its entry
     (`EditedCopy`: the app edited a copy, so its table is not the library's), is
     recorded as failed (`FailedCopy`), or skips an earlier entry (`Gap`). Nothing is
     adopted then; restore the copy's table to the library's, or apply the missing
     copy, and start again. A copy both edited and renamed is recognised by neither
     its text nor its name: `run` then applies that entry anew and fails at the first
     name it already holds, and `migrations::conflicts(&pool)` names them.

- Copy the templates again (`templates/openshift/`, `templates/justfile`,
  `templates/dependabot.yml`) and keep `params.env`:
  - `justfile`: the `migrate` recipe runs `migrate_command` and refuses a shared
    `postgres` or `template1` database outside CI, and `check` starts with `migrate`;
    without them its `doc` step fails on an unmigrated database.
  - `dependabot.yml`: its npm ecosystem ignores the stylesheet's
    `@onewaytek/owt-stack` git dependency, which Dependabot would move to an older
    tag. An app that copied the template earlier adds the `ignore` entry before it
    resumes Dependabot.
  - `apply.sh` passes the parameters in a `--param-file`, so a comma in a value
    (`RUST_LOG=info,myapp=debug`) is one value. `env.sh` and the `pre-render` hook
    are new and optional ("The app's environment"); `cronjob.yaml` reads an optional
    `myapp-<JOB>-env` Secret after `myapp-env`.
- An app that passed `dispatch-release: false` to the `sync-rc` call of
  `promote-rc.yml` drops it: the sync then releases `rc` only when the merge changed
  `rc`'s tree.
- `owt_test::Client` sends every request from the peer `owt_test::PEER`, so a handler
  taking `ConnectInfo<SocketAddr>` or `ClientIp` answers under it; a test that
  asserted the 500 from a missing peer uses `Client::with_peer(None)`.
- `PoolConfig::connect` waits up to a minute for an unreachable database;
  `connect_within(url, Duration::ZERO)` tries once.
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
  keep the purpose with `SESSION_PURPOSE`, or `SESSION_KEY_PURPOSE` for one of
  another shape (see "Moving onto `from_env`" under "Session key").
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

## Working on owt-stack

`just check` is the gate (fmt, clippy over every crate and feature and over
`owt-change` and `owt-auth` without their defaults, `dev-only`, the tests with the README
doctests, `cargo audit`, the template tests, the commitlint configuration and `image-check`), and CI
runs the same command. The Redis tests run when
`REDIS_URL` is set, the Postgres ones (`owt-runtime`'s singleton jobs) when
`DATABASE_URL` is, and `owt-bus`'s TLS test when `REDIS_TLS_URL` is a `rediss://` URL
whose certificate the system trusts (`SSL_CERT_FILE=ca.crt` for a test CA; the test's
header says how to run such a Redis). Each is skipped otherwise; CI sets the first two.

**Tests come in five kinds**, and a change to anything that reads what a client sent
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
`accounts`, `audit`, `change`, `crypt`, `storage`, `tailwind`, `deps`, `release` (release-please and its configuration).

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
