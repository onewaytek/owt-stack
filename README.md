# owt-stack

What the onewaytek apps (epicpartygame-rs, pets and, after its port, kynestro) share:
Rust, Axum, SQLx on Postgres, Askama, htmx and Tailwind, deployed to OpenShift.

| Crate | What an app gets |
|---|---|
| `owt-web` | the handler error type and its HTTP mapping; tokenless cross-origin protection; typed sessions sealed in an encrypted cookie; fingerprinted static URLs; response headers; htmx extractors (re-exported `axum-htmx`); SSE framing; pager and text helpers |
| `owt-runtime` | configuration from the environment; logging (JSON in production) and OTLP export (feature `otel`); Prometheus (feature `metrics`, default); the Postgres pool and migrations under an advisory lock; serving with graceful shutdown |
| `owt-auth` | Argon2id hashing off the runtime, accepting Django `pbkdf2_sha256` hashes for migration; OAuth 2 sign-in with PKCE (Google, Discord, Twitch, any OIDC); JWT bearer verification against a JWKS |
| `owt-bus` | topic fan-out to a replica's sockets and streams, across replicas over Redis pub/sub, with heartbeat, resubscription and resync |
| `owt-test` | an in-process client with a cookie jar; the router on an ephemeral port |

Outside the crates:

| Path | What it is |
|---|---|
| `.github/workflows/rust-ci.yml` | the reusable check workflow: fmt, audit, sqlx metadata, clippy, tests (on ARC), and the stylesheet build |
| `templates/Dockerfile` | cargo-chef, an npm Tailwind stage, distroless non-root runtime |
| `templates/openshift/app.yaml` | an OpenShift Template: ImageStream following a ghcr channel, Deployment with an image trigger, Service, Route, CNPG Postgres |
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

A shared crate is only shared while the majors agree: an app that names `axum`, `sqlx`,
`askama` or `redis` directly must use the major in this workspace's `Cargo.toml`.
Upgrading one of those is a release of this repository first, then of every app.

## Decisions

- **No CSRF tokens.** Unsafe requests are refused when the browser's fetch metadata
  (`Sec-Fetch-Site`) or, failing that, `Origin` says they came from another origin:
  Go 1.25's `CrossOriginProtection`. Forms carry no hidden field, and htmx sends no
  header. Session cookies stay `SameSite=Lax` as a second line.
- **Sessions are cookies.** Sealed with AES-GCM; no store, no query per request.
  Revoke by epoch (a counter in the account, copied into the session at sign-in).
- **Library code holds no `query!` macros**, so it needs no `.sqlx/` metadata and builds
  offline anywhere.
- **Metric names belong to the app.** The library takes them as arguments, so an app's
  dashboards and load-test reports keep their names.
- **Bus channel names** (`<prefix>:<topic>`, `~changed`, `~beat`) are a wire format
  between replicas. Changing one is a rollout hazard: old and new replicas must agree.
- **OpenShift Template, not Kustomize**, for the deployment: the app's name must reach
  the image trigger annotation and the CNPG Secret's name, which Kustomize's name
  transformers do not rewrite.

## Checks

`cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features`.
`owt-bus`'s Redis test runs when `REDIS_URL` is set and is skipped otherwise.
