# syntax=docker/dockerfile:1.7
#
# The image every owt-stack app builds. Copy it into the app's repository and set
# the three ARGs below (or pass them with --build-arg). Three stages:
#
# 1. css: Tailwind scans templates/ (and Rust sources, if the app's input CSS says
#    so) and emits the stylesheet. npm, not the standalone binary, so plugins such as
#    Flowbite load. Node is build-time only.
# 2. build: cargo-chef caches the dependency graph in its own layer, so a source edit
#    recompiles the app and nothing else. SQLX_OFFLINE: queries are checked against
#    the committed .sqlx/ data; no database at build time. Migrations and Askama
#    templates are compiled into the binary.
# 3. runtime: distroless glibc, non-root. rustls means no OpenSSL; the image carries
#    CA certificates for outbound TLS. Distroless has no shell: an app whose
#    operations `oc exec` shell tools into the pod (epicpartygame-rs's capacity
#    harness runs `sh`, `timeout` and `env` there) keeps a debian-slim runtime.
#
# Copy templates/dockerignore beside it as .dockerignore: both `COPY . .` steps take
# the whole build context.
#
# Built on GitHub-hosted runners and pushed to ghcr; the cluster pulls it through an
# ImageStream (see templates/openshift/app.yaml). The ARC runners are rootless with no
# Docker daemon, so they run checks, never this.

# The binary's name (the Cargo package's `[[bin]]`, usually the package name).
ARG BIN=app
# The port the binary binds (its BIND_ADDR default inside the image).
ARG PORT=8000
# npm script that writes the stylesheet into static/.
ARG CSS_SCRIPT=css:build

FROM node:22-bookworm-slim AS css
ARG CSS_SCRIPT
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run ${CSS_SCRIPT}

FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
ARG BIN
COPY --from=planner /app/recipe.json recipe.json
# owt-stack is a private git dependency. The token arrives as a BuildKit secret
# (docker/build-push-action: `secrets: owt_stack_token=...`), mounted for the fetch
# step only and passed to git through the environment, so it is in no layer and no
# config file. The fetch runs no code of the dependencies'; the cook step, which
# runs their build scripts and proc macros, has no token in its environment and
# finds every checkout in CARGO_HOME, so it fetches nothing (as rust-ci.yml does).
RUN cargo chef cook --release --locked --recipe-path recipe.json --no-build
RUN --mount=type=secret,id=owt_stack_token,required=false \
    if [ -s /run/secrets/owt_stack_token ]; then \
      export GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/owt_stack_token)@github.com/onewaytek/owt-stack.insteadOf" \
        GIT_CONFIG_VALUE_0="https://github.com/onewaytek/owt-stack"; \
    fi; \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo fetch --locked
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin ${BIN} && cp target/release/${BIN} /app/server

FROM gcr.io/distroless/cc-debian12:nonroot
ARG PORT
ARG VERSION=dev
LABEL org.opencontainers.image.version=$VERSION
WORKDIR /app
COPY --from=build /app/server /usr/local/bin/server
COPY --from=css /app/static ./static
ENV BIND_ADDR=0.0.0.0:${PORT}
EXPOSE ${PORT}
USER nonroot
ENTRYPOINT ["/usr/local/bin/server"]
