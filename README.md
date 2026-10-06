# owt-stack

An opinionated stack used as a base for One Way Tek projects:
Rust, Axum, SQLx on Postgres, Redis, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; fingerprinted static URLs; security headers and a nonce-based content security policy; a response deadline and body cap; safe `?next=` redirects; the client's address behind proxies; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | sign-in throttling by address and account; Argon2id hashing off the runtime with bounded concurrency and a decoy check for unknown accounts, accepting Django `pbkdf2_sha256` hashes for migration; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar; the router on an ephemeral port |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow: fmt, audit, sqlx metadata, clippy, tests (on ARC), and the stylesheet build |
| `templates/Dockerfile` | cargo-chef, an npm Tailwind stage, distroless non-root runtime (with `templates/dockerignore`) |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger, Service, Route, CNPG Postgres over verified TLS, NetworkPolicies |
| `tailwind/owt.css` | font stacks and htmx state variants (`htmx-request:opacity-50`) |

## Using it

```toml
[dependencies]
owt-web = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.1.0" }
owt-runtime = { git = "https://github.com/onewaytek/owt-stack", tag = "v0.1.0" }
```

While developing against a local checkout, patch the git source in the app's
`.cargo/config.toml` (not committed) instead of editing `Cargo.toml`:

```toml
[patch."https://github.com/onewaytek/owt-stack"]
owt-web = { path = "../owt-stack/crates/owt-web" }
owt-runtime = { path = "../owt-stack/crates/owt-runtime" }
```

The repository is private, so fetching it needs a token with read access to it:

- **CI:** an `OWT_STACK_TOKEN` secret (organization or repository), passed to the
  reusable workflow with `secrets: inherit`.
- **Image builds:** the same token as a BuildKit secret, `owt_stack_token`
  (`templates/Dockerfile` shows the step that mounts it).

A shared crate is only shared while the majors agree: an app that names `axum`, `sqlx`,
`askama` or `redis` directly must use the major in this workspace's `Cargo.toml`.
Upgrading one of those is a release of this repository first, then of every app.

An app that names `sqlx` uses its `tls-rustls-aws-lc-rs` feature, not `tls-rustls`
(which means ring). With both rustls backends compiled in, rustls cannot pick one, and
the first `rediss://` connection panics.

## Decisions

- **No CSRF tokens.** Unsafe requests are refused when the browser's fetch metadata
  (`Sec-Fetch-Site`) or, failing that, `Origin` says they came from another origin:
  Go 1.25's `CrossOriginProtection`. Forms carry no hidden field, and htmx sends no
  header. Session cookies stay `SameSite=Lax` as a second line.
- **Sessions are cookies.** Sealed with AES-GCM; no store. Revoke by epoch (a counter
  in the account, copied into the session at sign-in, bumped at sign-out) checked in
  `Sessions::validate_with`. A session ends at its absolute lifetime however often it
  is re-sealed, and a response that sets the cookie is never cacheable.
- **Library code holds no `query!` macros**, so it needs no `.sqlx/` metadata and builds
  offline anywhere.
- **Metric names belong to the app.** The library takes them as arguments, so an app's
  dashboards and load-test reports keep their names.
- **Bus channel names** (`<prefix>:<topic>`, `~changed`, `~beat`) are a wire format
  between replicas. Changing one is a rollout hazard: old and new replicas must agree.
- **OpenShift Template, not Kustomize**, for the deployment: the app's name must reach
  the image trigger annotation and the CNPG Secret's name, which Kustomize's name
  transformers do not rewrite.

## What an app must wire

The library supplies these; composing them is the app's router:

```rust,ignore
let csp = Csp::new().report_only(true); // enforce once the console is quiet
let sessions = Sessions::new(key, "__Host-sid", max_age, true).validate_with(move |s| {
    let pool = pool.clone();
    async move {
        match account_epoch(&pool, s.data.user_id).await {
            Ok(epoch) => (epoch == s.data.epoch).into(), // Valid or Revoked
            // Neither admit a revoked session nor sign everyone out.
            Err(_) => Verdict::Unknown,
        }
    }
});
let app = Limits::default().apply(routes)
    .layer(from_fn_with_state(sessions, Sessions::layer))
    .layer(from_fn_with_state(CrossOrigin::new(), CrossOrigin::layer))
    .layer(from_fn_with_state(csp, Csp::layer))
    .layer(from_fn(headers::private_by_default))
    .layer(from_fn(headers::security));
```

- `headers::security` sends HSTS for the app's own host. An app that owns its whole
  domain adds `includeSubDomains` itself.
- Sign-in: `throttle::Throttle::sign_in` *before* `password::verify_or_decoy` (a
  refused sign-in checks no password), keyed on `client_ip::Source::client_ip`
  (configured for the proxies actually in front of the app), and
  `redirect::local_or` on `?next=` before redirecting to it.
- OAuth: `oauth::http_client()` for the exchange; `Client::complete` checks the
  state and the provider itself.
- The bus's Redis is inside the trust boundary: a password or ACL user, a network
  only the app reaches, `rediss://` where the path leaves the node.
- `Limits` bounds the time to a response, not the time a client takes to send a
  request: serve behind a proxy that bounds that (the OpenShift router does).

## Upgrading from 0.1

- **Everyone signs in once more:** the sealed session gains its start time (`i`), and
  cookies sealed before it no longer open. Session data may not use the field names
  `k`, `x` or `i`.
- `Sessions::validate_with`'s closure answers a `Verdict` (a `bool` still converts).
- `oauth::Client::complete` takes the callback's `state`; drop the app's own
  `Pending::matches` check. `Pending` gains `provider`, so a sign-in in flight across
  the deploy fails once with `Error::Provider`.
- `jwt::Error` and `oauth::Error` have new variants; a `match` on them needs arms.
- `CrossOrigin::layer` refuses cross-origin WebSocket upgrades. A bypass prefix
  matches whole path segments: `/mcp` no longer covers `/mcp-admin`.
- The workspace's `tower-http` names only `timeout`; an app names its own features.
- `sqlx` is built with `tls-rustls-aws-lc-rs` (above).
- The OpenShift template adds NetworkPolicies, Postgres over verified TLS, a
  read-only root filesystem and a `CNPG_NAMESPACE` parameter: process it into a
  staging namespace first.

## Checks

`cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features`.
`owt-bus`'s Redis test runs when `REDIS_URL` is set and is skipped otherwise.
